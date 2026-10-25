#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""P8: do the capture hooks see I/O and exec made through the 32-bit (compat) ABI?

Builds compat.c twice (64-bit using int $0x80; 32-bit static, if gcc-multilib is
installed), runs each under compat.bt, and checks that every operation the
program reports produced the probe record it should: the syscall at
raw_syscalls (with its number and TS_COMPAT bit), the byte count at fexit
vfs_read / vfs_write, the file at fexit security_file_open, and the exec at
sched_process_exec.

    sudo python3 bench/probes/p8_compat/run.py

Exit: 0 both variants ran and every check passed; 3 every check passed but a
variant was skipped (shown in the report); 1 a check or an operation failed.
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

VARIANTS = {"64": ["-O2", "-Wall", "-Wextra"], "32": ["-m32", "-static", "-O2", "-Wall", "-Wextra"]}
KINDS = {"SYS": ("tid", "id", "compat"), "VFS_READ": ("tid", "ret", "compat"), "VFS_WRITE": ("tid", "ret", "compat"),
         "OPEN": ("tid", "ret", "compat", "name"), "EXEC": ("pid", "compat", "name")}
# What a reader that decodes raw_syscalls ids with the x86_64 table would call these i386 numbers.
X64_NAME = {3: "close", 4: "stat", 5: "fstat", 6: "lstat", 11: "munmap"}
I386_NAME = {3: "read", 4: "write", 5: "open", 6: "close", 11: "execve"}
OP_RESULT = {"native_read": 1111, "compat_read": 2222, "compat_write": 3333}


def expectations(variant: str) -> list[tuple[str, str, dict]]:
    """(operation, record kind, fields the record must have). The 32-bit build's libc calls are compat too."""
    native_compat, native_read_nr = (0, 0) if variant == "64" else (1, 3)
    return [
        ("native_read", "SYS", {"id": native_read_nr, "compat": native_compat}),
        ("native_read", "VFS_READ", {"ret": 1111, "compat": native_compat}),
        ("compat_open", "SYS", {"id": 5, "compat": 1}),
        ("compat_open", "OPEN", {"ret": 0, "compat": 1, "name": "p8-src.dat"}),
        ("compat_read", "SYS", {"id": 3, "compat": 1}),
        ("compat_read", "VFS_READ", {"ret": 2222, "compat": 1}),
        ("compat_open_w", "SYS", {"id": 5, "compat": 1}),
        ("compat_open_w", "OPEN", {"ret": 0, "compat": 1, "name": "p8-dst.dat"}),
        ("compat_write", "SYS", {"id": 4, "compat": 1}),
        ("compat_write", "VFS_WRITE", {"ret": 3333, "compat": 1}),
        ("compat_execve", "SYS", {"id": 11, "compat": 1}),
        ("compat_execve", "EXEC", {"name": "/bin/true"}),
    ]


def parse_probe(text: str) -> tuple[list[dict], int, int]:
    """Records after the start marker; returns (records, unknown lines, preamble lines)."""
    recs, unknown, preamble, started = [], 0, 0, False
    for line in text.splitlines():
        if not started:
            started = line == "P8 start"
            preamble += not started
            continue
        parts = line.split(" ", len(KINDS.get(line.split(" ", 1)[0], ())))
        fields = KINDS.get(parts[0])
        if fields and len(parts) == len(fields) + 1:
            rec = {"kind": parts[0]}
            try:
                for f, v in zip(fields, parts[1:]):
                    rec[f] = v if f == "name" else int(v)
            except ValueError:
                unknown += 1
                continue
            recs.append(rec)
        elif line not in ("P8 end", ""):
            unknown += 1
    return recs, unknown + (0 if started else 1), preamble


def parse_ops(text: str) -> tuple[dict, int]:
    ops, unknown = {}, 0
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 5 and parts[0] == "OP":
            ops[parts[1]] = parts[4]
        elif line:
            unknown += 1
    return ops, unknown


def op_problems(ops: dict) -> list[str]:
    out = [f"{op} returned {ops.get(op)}, expected {want}" for op, want in OP_RESULT.items()
           if ops.get(op) != str(want)]
    for op in ("compat_open", "compat_open_w"):
        if not ops.get(op, "-1").isdigit():
            out.append(f"{op} returned {ops.get(op)}")
    if ops.get("compat_execve") != "pending" or "compat_execve_failed" in ops:
        out.append(f"compat execve failed: {ops.get('compat_execve_failed')}")
    return out


def analyze(variant: str, probe_text: str, ops_text: str) -> dict:
    recs, unknown, preamble = parse_probe(probe_text)
    ops, ops_unknown = parse_ops(ops_text)
    checks = []
    for op, kind, want in expectations(variant):
        seen = sum(1 for r in recs if r["kind"] == kind and all(r.get(k) == v for k, v in want.items()))
        checks.append({"op": op, "kind": kind, "want": want, "seen": seen})
    compat_ids = sorted({r["id"] for r in recs if r["kind"] == "SYS" and r["compat"]})
    return {
        "variant": variant, "records": len(recs), "unknown_lines": unknown + ops_unknown, "preamble_lines": preamble,
        "ops": ops, "op_problems": op_problems(ops), "checks": checks,
        "missed": [f"{c['op']}: no {c['kind']} {c['want']}" for c in checks if not c["seen"]],
        "native_exec_ids_seen": sum(1 for r in recs if r["kind"] == "SYS" and r["id"] in (59, 322)),
        "compat_ids_seen": compat_ids,
        "x64_misreading": {i: f"{I386_NAME[i]} would read as {X64_NAME[i]}" for i in compat_ids if i in X64_NAME},
        "exec_compat_bit": [r["compat"] for r in recs if r["kind"] == "EXEC"],
    }


def render(conds: dict, results: dict, skipped: dict) -> str:
    out = [f"# P8 compat ABI: {conds['utc_start']}", "",
           f"- kernel {conds['kernel']}; {conds['bpftrace']}; {conds['gcc']}; git {conds['git_commit'][:12]}"
           f"{' (dirty)' if conds['git_dirty'] else ''}; IA32 config: {', '.join(conds['kconfig_ia32'])}", ""]
    for v, why in skipped.items():
        out.append(f"**Variant {v}-bit SKIPPED:** {why}\n")
    for v, r in results.items():
        out += [f"## Variant {v}-bit ({'int $0x80 from a 64-bit process' if v == '64' else 'i386 program, libc vDSO entry'})", "",
                "| operation | record | fields required | seen |", "|---|---|---|---:|"]
        for c in r["checks"]:
            fields = ", ".join(f"{k}={v2}" for k, v2 in c["want"].items())
            out.append(f"| {c['op']} | {c['kind']} | {fields} | {c['seen'] or '**0**'} |")
        out += ["", f"- program results: {r['ops']}" + (f"; **problems: {r['op_problems']}**" if r["op_problems"] else ""),
                f"- syscall ids seen with TS_COMPAT set: {r['compat_ids_seen']}; "
                f"with an x86_64 table: {'; '.join(r['x64_misreading'].values()) or 'n/a'}",
                f"- execve ids 59/322 seen: {r['native_exec_ids_seen']}; TS_COMPAT at sched_process_exec: {r['exec_compat_bit']}",
                f"- {r['records']} records; {r['unknown_lines']} unknown lines; {r['preamble_lines']} preamble lines", ""]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--bpftrace", default="bpftrace")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)
    if os.geteuid() != 0:
        ap.error("must run as root (bpftrace); use sudo")

    user = P.sudo_user()
    out = args.out or Path("/var/tmp/fd-probes") / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-p8")
    out.mkdir(parents=True, exist_ok=False)
    conds = P.conditions(HERE, [HERE / "compat.c", HERE / "compat.bt", Path(__file__).resolve(), HERE.parent / "probelib.py"],
                         args.bpftrace)
    (out / "conditions.json").write_text(json.dumps(conds, indent=2) + "\n")

    results, skipped = {}, {}
    for v, flags in VARIANTS.items():
        exe = out / f"p8-compat{v}"
        if not P.build(HERE / "compat.c", exe, flags, out / f"build-{v}.log"):
            first = next((l for l in (out / f"build-{v}.log").read_text().splitlines()[2:] if "error" in l), "see log")
            skipped[v] = f"build failed ({first.strip()}); full output in build-{v}.log"
            print(f"[p8] variant {v}: SKIPPED, {skipped[v]}", flush=True)
            continue
        work = out / f"work-{v}"
        work.mkdir()
        if user:
            for p in (out, work):
                shutil.chown(p, user=user)
        probe = P.start_probe(args.bpftrace, HERE / "compat.bt", out / f"probe-{v}.txt", out / f"probe-{v}.err", "P8 start")
        try:
            code = P.run_as(user, [str(exe), str(work)], out / f"program-{v}.txt", timeout=60, cwd=work)
        finally:
            clean = P.stop_probe(probe)
        r = analyze(v, (out / f"probe-{v}.txt").read_text(errors="replace"),
                    (out / f"program-{v}.txt").read_text(errors="replace"))
        r["program_exit"], r["probe_clean_stop"] = code, clean
        if code != 0:
            r["op_problems"].append(f"program exit {code}")
        if not clean:
            r["op_problems"].append("bpftrace did not stop cleanly")
        results[v] = r
        print(f"[p8] variant {v}: {len(r['missed'])} checks missed, problems {r['op_problems']}", flush=True)

    (out / "results.json").write_text(json.dumps({"results": results, "skipped": skipped}, indent=2) + "\n")
    report = render(conds, results, skipped)
    (out / "index.md").write_text(report)
    print("\n" + report + f"\nResults in {out}")
    if any(r["missed"] or r["op_problems"] or r["unknown_lines"] for r in results.values()) or not results:
        return 1
    return 3 if skipped else 0


if __name__ == "__main__":
    sys.exit(main())
