#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""What each of p15d's BPF programs costs while a command runs, from the kernel's own program
statistics (ADR-0018 rule 3.2).

    sudo python3 bench/prim_cost/prog_stats.py --p15d build/p15d --ops 220000 --rounds 7 \
        --ref-nullsys-ns 89.1 -- build/open_cost DIR 200000 20000

Starts p15d, waits for code=start and SETTLE seconds, switches kernel.bpf_stats_enabled on, then
ROUNDS times: reads every loaded program's run_cnt and run_time_ns (bpftool prog show --json), runs
the command, reads them again. Restores the sysctl and stops p15d. Prints, for every program that
ran: its runs, and the median over the rounds (with the cheapest and dearest round) of its ns per
run, and with --ops N of its ns per operation of the command; then every round's raw figures.

Host speed (E-0180). If the command prints bench/open_cost's "row event=nullsys" line, each round's
null-syscall cost is reported and judged as in summarize.py (UNSTEADY, SLOW against
--ref-nullsys-ns); without it the report says it cannot show how fast the host was.

What the numbers are, and are not:
  - run_time_ns is the program's body. The hook path that calls it (the trampoline, the fprobe)
    is not in it; bench/rw_hook_cost measured those.
  - with the statistics on, every program run pays for two clock reads, about 20 ns (Kahle; ADR-0018
    rule 3.2), which is inside run_time_ns only in part. So this run tells where the time goes;
    it is not the run to quote an overhead from (bench/open_cost is, with the statistics off).
  - programs of other tools loaded at the same time are listed too, by name.
"""
from __future__ import annotations

import argparse
import json
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import summarize as SUM  # noqa: E402

P = SUM.P
SYSCTL = Path("/proc/sys/kernel/bpf_stats_enabled")
NULLSYS = re.compile(r"^row event=nullsys n=(\d+) cpu_ns=(\d+)\b", re.M)


class StatsError(Exception):
    pass


def parse_progs(text: str) -> dict[int, dict]:
    """bpftool prog show --json -> {id: {name, type, run_cnt, run_time_ns}} (0 where a field is absent:
    bpftool leaves the two counters out for a program that never ran with statistics on)."""
    try:
        progs = json.loads(text)
    except json.JSONDecodeError as e:
        raise StatsError(f"bpftool output is not JSON: {e}") from e
    if not isinstance(progs, list):
        raise StatsError("bpftool output is not a list of programs")
    out = {}
    for p in progs:
        if "id" not in p:
            raise StatsError(f"a program without an id: {p}")
        out[int(p["id"])] = {"name": p.get("name", "?"), "type": p.get("type", "?"),
                             "run_cnt": int(p.get("run_cnt", 0)), "run_time_ns": int(p.get("run_time_ns", 0))}
    return out


def delta(before: dict[int, dict], after: dict[int, dict]) -> list[dict]:
    """Per program that ran in between: runs and ns. A program loaded in between counts from zero;
    one unloaded in between is not listed (its counters are gone)."""
    out = []
    for pid, a in after.items():
        b = before.get(pid, {"run_cnt": 0, "run_time_ns": 0})
        runs, ns = a["run_cnt"] - b["run_cnt"], a["run_time_ns"] - b["run_time_ns"]
        if runs < 0 or ns < 0:
            raise StatsError(f"program {pid} ({a['name']}): its counters went backwards")
        if runs:
            out.append({"id": pid, "name": a["name"], "type": a["type"], "runs": runs, "ns": ns})
    return sorted(out, key=lambda r: -r["ns"])


def table(rows: list[dict], ops: int | None) -> str:
    L = ["| program | type | runs | total ms | ns per run |" + (" runs per op | ns per op |" if ops else ""),
         "|---|---|---|---|---|" + ("---|---|" if ops else "")]
    for r in rows:
        line = f"| {r['name']} | {r['type']} | {r['runs']:,} | {r['ns'] / 1e6:.2f} | {r['ns'] / r['runs']:.1f} |"
        if ops:
            line += f" {r['runs'] / ops:.3f} | {r['ns'] / ops:.1f} |"
        L.append(line)
    total = sum(r["ns"] for r in rows)
    L.append(f"| **all** | | {sum(r['runs'] for r in rows):,} | {total / 1e6:.2f} | |" +
             (f" {sum(r['runs'] for r in rows) / ops:.3f} | {total / ops:.1f} |" if ops else ""))
    return "\n".join(L)


def host_ns(stdout: str) -> float | None:
    """The command's own null-syscall cost (ns each), if it printed bench/open_cost's nullsys row."""
    m = NULLSYS.search(stdout)
    if not m or int(m[1]) <= 0 or int(m[2]) <= 0:
        return None
    return int(m[2]) / int(m[1])


def host_of(outs: list[str]) -> list[float]:
    """Every round's null-syscall cost, or [] if no round has one. Some but not all is an error."""
    ns = [host_ns(o) for o in outs]
    if any(x is None for x in ns) and any(x is not None for x in ns):
        raise StatsError(f"round {[x is None for x in ns].index(True)}: the command printed no null-syscall row")
    return [x for x in ns if x is not None]


def summary(rounds: list[list[dict]], ops: int | None) -> str:
    """Per program: the median over the rounds it ran in of its ns per run, with the cheapest and dearest."""
    progs: dict[int, dict] = {}
    for rows in rounds:
        for r in rows:
            e = progs.setdefault(r["id"], {"name": r["name"], "type": r["type"], "runs": 0, "per_run": [], "ns": []})
            e["runs"] += r["runs"]
            e["per_run"].append(r["ns"] / r["runs"])
            e["ns"].append(r["ns"])
    L = ["| program | type | rounds | runs | ns per run (median) | cheapest to dearest round |" +
         (" runs per op | ns per op (median) |" if ops else ""), "|---|---|---|---|---|---|" + ("---|---|" if ops else "")]
    for e in sorted(progs.values(), key=lambda e: -P.median(e["ns"])):
        line = (f"| {e['name']} | {e['type']} | {len(e['ns'])} | {e['runs']:,} | {P.median(e['per_run']):.1f} |"
                f" {min(e['per_run']):.1f} to {max(e['per_run']):.1f} |")
        if ops:
            line += f" {e['runs'] / (ops * len(e['ns'])):.3f} | {P.median(e['ns']) / ops:.1f} |"
        L.append(line)
    total = [sum(r["ns"] for r in rows) for rows in rounds]
    runs = sum(r["runs"] for rows in rounds for r in rows)
    L.append(f"| **all** | | {len(rounds)} | {runs:,} | | |" +
             (f" {runs / (ops * len(rounds)):.3f} | {P.median(total) / ops:.1f} |" if ops else ""))
    return "\n".join(L)


def bpftool(binary: str) -> dict[int, dict]:
    r = subprocess.run([binary, "prog", "show", "--json"], capture_output=True, text=True)
    if r.returncode:
        raise StatsError(f"{binary} prog show failed: {r.stderr.strip()}")
    return parse_progs(r.stdout)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--p15d", type=Path, required=True)
    ap.add_argument("--p15d-arg", action="append", default=[])
    ap.add_argument("--bpftool", default="bpftool")
    ap.add_argument("--ops", type=int, help="operations the command performs: adds per-operation columns")
    ap.add_argument("--settle", type=float, default=1.0)
    ap.add_argument("--rounds", type=int, default=7)
    ap.add_argument("--ref-nullsys-ns", type=float, help="the null syscall's cost on a good day: above 1.5x is SLOW")
    ap.add_argument("command", nargs="+")
    a = ap.parse_args(argv)
    if a.rounds < 1 or (a.ref_nullsys_ns is not None and a.ref_nullsys_ns <= 0):
        ap.error("--rounds >= 1 and --ref-nullsys-ns > 0")
    work = Path(tempfile.mkdtemp(prefix="p15-prog-stats-"))
    log = work / "p15d.log"
    old = SYSCTL.read_text().strip()
    with open(log, "wb") as lf:
        p = subprocess.Popen([str(a.p15d), "--wal-dir", str(work / "wal")] + a.p15d_arg, stdout=lf, stderr=lf)
    rc = 1
    try:
        t0 = time.monotonic()
        while "code=start" not in log.read_text(errors="replace"):
            if p.poll() is not None or time.monotonic() - t0 > 120:
                raise StatsError(f"p15d did not start: {log.read_text(errors='replace')[-300:]}")
            time.sleep(0.05)
        time.sleep(a.settle)
        SYSCTL.write_text("1")
        rounds, outs = [], []
        for r in range(a.rounds):
            before = bpftool(a.bpftool)
            cmd = subprocess.run(a.command, capture_output=True, text=True)
            after = bpftool(a.bpftool)
            if cmd.returncode:
                raise StatsError(f"round {r}: the command exited {cmd.returncode}: {cmd.stderr.strip()}")
            rounds.append(delta(before, after))
            outs.append(cmd.stdout.strip())
        host, _ = SUM.host_lines(host_of(outs), a.ref_nullsys_ns)
        print(f"# Per-program cost while `{' '.join(a.command)}` ran, {a.rounds} rounds"
              " (bpf_stats on: not an overhead measurement)\n")
        print("\n".join(host))
        print(summary(rounds, a.ops))
        for r, (rows, out) in enumerate(zip(rounds, outs)):
            print(f"\n## Round {r}\n\n{table(rows, a.ops)}\n\n{out}")
        rc = 0
    except StatsError as e:
        print(f"prog_stats: {e}", file=sys.stderr)
    finally:
        SYSCTL.write_text(old)
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
        try:
            code = p.wait(120)
        except subprocess.TimeoutExpired:
            p.kill()
            code = -9
        print(f"\np15d exit {code}; its log and WAL: {work}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
