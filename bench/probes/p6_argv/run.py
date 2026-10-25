#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""P6: where must the capture read argv at exec so it sees what the kernel ran?

Two modes, each TRIALS executions of /bin/echo by p6-racer (racer.c) under
argv.bt:

  control  nobody rewrites the argument: ENTER, EXEC and TRUTH must all agree,
           or the harness itself is broken and the run is INVALID
  race     a second thread rewrites the argument during execve

For every trial (joined on the child pid) it counts whether each tracer read
matches TRUTH (what echo actually printed) and whether a read is missing or
came back empty. Nothing is dropped: probe lines that match no trial, and
lines of unknown shape, are counted too.

    sudo python3 bench/probes/p6_argv/run.py --trials 1000
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import probelib as P  # noqa: E402

MODES = (("control", []), ("race", ["--race"]))
SOURCES = ("ENTER", "EXEC")


def parse(probe_text: str, racer_text: str) -> dict:
    reads = {s: {} for s in SOURCES}
    truth, unknown, dup, preamble, started = {}, 0, 0, 0, False
    for line in probe_text.splitlines():
        parts = line.split(" ", 2)
        if not started:
            # bpftrace 0.25 prints compiler warnings on stdout before BEGIN runs (E-0019): kept, counted
            started = line == "P6 start"
            preamble += not started
        elif len(parts) >= 2 and parts[0] in SOURCES and parts[1].isdigit():
            src, pid = parts[0], int(parts[1])
            dup += pid in reads[src]
            reads[src][pid] = parts[2] if len(parts) == 3 else ""
        elif line not in ("P6 end", ""):
            unknown += 1
    for line in racer_text.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[0] == "TRUTH":
            truth[int(parts[1])] = (parts[2], int(parts[3]))
        elif line:
            unknown += 1
    if not started:
        unknown += 1  # no start marker: nothing after it can be trusted
    return {"reads": reads, "truth": truth, "unknown_lines": unknown, "duplicate_reads": dup,
            "preamble_lines": preamble}


def analyze(parsed: dict) -> dict:
    truth = parsed["truth"]
    res = {"trials": len(truth), "echo_failed": sum(1 for _, st in truth.values() if st != 0),
           "unknown_lines": parsed["unknown_lines"], "duplicate_reads": parsed["duplicate_reads"],
           "preamble_lines": parsed["preamble_lines"]}
    for src in SOURCES:
        got = parsed["reads"][src]
        c = {"match": 0, "mismatch": 0, "missing": 0, "empty": 0}
        for pid, (val, _) in truth.items():
            if pid not in got:
                c["missing"] += 1
            elif got[pid] == "":
                c["empty"] += 1
            else:
                c["match" if got[pid] == val else "mismatch"] += 1
        c["unmatched_events"] = sum(1 for pid in got if pid not in truth)
        res[src] = c
    res["truth_all_A"] = sum(1 for v, _ in truth.values() if v == "A" * 16)
    return res


def problems(mode: str, r: dict, trials: int) -> list[str]:
    """Reasons this mode's result can't be used. Mismatches under race are findings, not problems."""
    out = []
    if r["trials"] != trials:
        out.append(f"{r['trials']} of {trials} trials reported")
    if r["echo_failed"]:
        out.append(f"echo failed {r['echo_failed']} times")
    if r["unknown_lines"] or r["duplicate_reads"]:
        out.append(f"{r['unknown_lines']} unknown lines, {r['duplicate_reads']} duplicate reads")
    for src in SOURCES:
        c = r[src]
        if c["missing"] or c["empty"] or c["unmatched_events"]:
            out.append(f"{src}: {c['missing']} missing, {c['empty']} empty, {c['unmatched_events']} unmatched")
        if mode == "control" and c["mismatch"]:
            out.append(f"{src}: {c['mismatch']} mismatches with no race: the harness is broken")
    return out


def render(conds: dict, results: dict) -> str:
    out = [f"# P6 argv at exec: {conds['utc_start']}", "",
           f"- kernel {conds['kernel']}; {conds['bpftrace']}; {conds['gcc']}; git {conds['git_commit'][:12]}"
           f"{' (dirty)' if conds['git_dirty'] else ''}; {conds['trials']} trials per mode", "",
           "| mode | trials | kernel copied all-'A' | ENTER = truth | EXEC = truth | missing / empty | usable |",
           "|---|---:|---:|---:|---:|---|---|"]
    for mode, r in results.items():
        n = r["trials"] or 1
        miss = "; ".join(f"{s} {r[s]['missing']} / {r[s]['empty']}" for s in SOURCES)
        out.append(f"| {mode} | {r['trials']} | {r['truth_all_A']} | {r['ENTER']['match']} ({100 * r['ENTER']['match'] / n:.1f} %) | "
                   f"{r['EXEC']['match']} ({100 * r['EXEC']['match'] / n:.1f} %) | {miss} | "
                   f"{'yes' if not r['problems'] else 'NO: ' + '; '.join(r['problems'])} |")
    out += ["", "ENTER = read from the caller's memory at syscall entry (raw_syscalls, id 59). "
            "EXEC = read from the new program's stack at sched_process_exec. "
            "Truth = what /bin/echo printed, i.e. what the kernel actually copied.", ""]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--trials", type=int, default=1000)
    ap.add_argument("--bpftrace", default="bpftrace")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)
    if args.trials <= 0:
        ap.error("--trials must be positive")
    if os.geteuid() != 0:
        ap.error("must run as root (bpftrace); use sudo")

    user = P.sudo_user()
    out = args.out or Path("/var/tmp/fd-probes") / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-p6")
    out.mkdir(parents=True, exist_ok=False)
    if user:
        shutil.chown(out, user=user)
    conds = P.conditions(HERE, [HERE / "racer.c", HERE / "argv.bt", Path(__file__).resolve(), HERE.parent / "probelib.py"],
                         args.bpftrace) | {"trials": args.trials}
    (out / "conditions.json").write_text(json.dumps(conds, indent=2) + "\n")
    racer = out / "p6-racer"
    if not P.build(HERE / "racer.c", racer, ["-O2", "-Wall", "-Wextra", "-pthread"], out / "build.log"):
        print(f"build failed; see {out / 'build.log'}")
        return 1

    results = {}
    for mode, flags in MODES:
        probe = P.start_probe(args.bpftrace, HERE / "argv.bt", out / f"{mode}-probe.txt", out / f"{mode}-probe.err", "P6 start")
        try:
            code = P.run_as(user, [str(racer), str(args.trials), *flags], out / f"{mode}-racer.txt",
                            timeout=60 + args.trials, cwd=out)
        finally:
            clean = P.stop_probe(probe)
        r = analyze(parse((out / f"{mode}-probe.txt").read_text(errors="replace"),
                          (out / f"{mode}-racer.txt").read_text(errors="replace")))
        r["problems"] = problems(mode, r, args.trials)
        if code != 0:
            r["problems"].append(f"racer exit {code}")
        if not clean:
            r["problems"].append("bpftrace did not stop cleanly")
        results[mode] = r
        print(f"[p6] {mode}: {json.dumps({k: r[k] for k in ('trials', 'ENTER', 'EXEC')})}", flush=True)

    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    report = render(conds, results)
    (out / "index.md").write_text(report)
    print("\n" + report + f"\nResults in {out}")
    return 0 if not any(r["problems"] for r in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
