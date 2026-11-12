#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize a path_walk run (bench/path_walk/path_walk.c): gate 2 of STATE decision 28.

    python3 bench/path_walk/summarize.py path_walk.txt

The walk passes when it never gives a wrong path without saying so:
  - every case's walk equals bpf_d_path, or carries a flag that says why it does not
    (TRUNCATED, RACED, DNAME, NO_ROOT): a MISMATCH, an unflagged difference, fails the run;
  - in the rename race, no sample is a MISMATCH. A sample during which the tree moved between bpf_d_path and the
    walk ("moved") is not compared (each may be right for its own instant) and is counted; at least one sample
    must be compared.
Cases expected to be flagged (EXPECT) are listed as such; a case flagged that was expected equal is
reported (a coverage gap, not a wrong path). Timing: per path, the median over rounds of ns per call
for bpf_d_path and the walk in the fentry, and the walk in the kprobe.session. Every timed round must
have exactly N runs of each program (the config line's n): fewer means samples were lost (E-0195).
Exit 1 if the walk failed, a line does not parse, a case is missing, or a round is short.
"""
from __future__ import annotations

import re
import statistics
import sys
from pathlib import Path

CASES = ("plain", "root", "dir", "proc", "sysfs", "devtmpfs", "deep40", "deep70", "longnames", "tmpfs", "bind",
         "overlay", "deleted", "memfd", "pipe", "socket", "eventfd", "chroot")
EXPECT = {"deep70": "flagged"}
WHY = {"deep70": "70 components: beyond the walk's 64, so TRUNCATED"}
CONFIG = re.compile(r"^config dir=\S+ rounds=(\d+) n=(\d+) ")
_S = r"verdict=(\w+) flags=0x([0-9a-f]+) dpath_rc=(-?\d+) dpath_len=(\d+) walk_len=(\d+) dpath=(\S*) walk=(\S*)"
CASE = re.compile(r"^case (\w+) (samples=(\d+) open_errno=(\d+) " + _S +
                  r"|open_failed errno=\d+|no_sample|mount_failed( errno=\d+)?|chroot_failed errno=\d+)$")
SAMPLE = re.compile(r"^sample (\w+) (\d+) " + _S + "$")
KEEP = 4   # path_walk.c keeps at most this many samples of a case
RACE = re.compile(r"^race opens=(\d+) renames=(\d+) samples=(\d+) equal=(\d+) flagged=(\d+) moved=(\d+) raced=(\d+) "
                  r"retried=(\d+) "
                  r"mismatch=(\d+) dpath_failed=(\d+) open_failed=(\d+)$")
END = re.compile(r"^end lost=(\d+) kprobe_flags=0x([0-9a-f]+)$")
TIME = re.compile(r"^time round=(-?\d+) path=(\w+) fentry_runs=(\d+) dpath_ns=(\d+) walk_fentry_ns=(\d+) kprobe_runs=(\d+) "
                  r"walk_kprobe_ns=(\d+)$")
FLAGS = ((1, "TRUNCATED"), (2, "RACED"), (4, "DNAME"), (8, "DELETED"), (16, "NOT_UNDER_ROOT"), (32, "ESCAPED"),
         (64, "NO_SEQ"), (128, "NO_ROOT"), (256, "RETRIED"), (512, "SYNTH"))


class ParseError(Exception):
    pass


def flag_names(v: int) -> str:
    return ",".join(n for b, n in FLAGS if v & b) or "-"


def parse(text: str):
    cases, races, times, other, ends = {}, [], {}, [], []
    n = None
    for line in text.splitlines():
        if line.startswith("case "):
            m = CASE.match(line)
            if not m:
                raise ParseError(f"unparsed case: {line}")
            name = line.split()[1]
            if name in cases:
                raise ParseError(f"case {name} twice")
            if m[3] is None:
                cases[name] = {"verdict": line.split()[2].split("=")[0], "flags": 0, "raw": line, "n": 0, "more": []}
            else:
                cases[name] = {"verdict": m[5], "flags": int(m[6], 16), "dpath_rc": int(m[7]), "dpath": m[10],
                               "walk": m[11], "raw": line, "n": int(m[3]), "errno": int(m[4]), "more": []}
        elif line.startswith("sample "):
            m = SAMPLE.match(line)
            if not m:
                raise ParseError(f"unparsed sample: {line}")
            c = cases.get(m[1])
            if c is None or int(m[2]) != len(c["more"]) + 1:
                raise ParseError(f"a sample out of order: {line}")
            c["more"].append({"verdict": m[3], "flags": int(m[4], 16), "dpath": m[8], "walk": m[9]})
        elif line.startswith("race_mismatch "):
            other.append(line)
        elif line.startswith("race "):
            m = RACE.match(line)
            if not m:
                raise ParseError(f"unparsed race: {line}")
            races.append(dict(zip(("opens", "renames", "samples", "equal", "flagged", "moved", "raced", "retried", "mismatch",
                                   "dpath_failed", "open_failed"), map(int, m.groups()))))
        elif line.startswith("time "):
            m = TIME.match(line)
            if not m:
                raise ParseError(f"unparsed time: {line}")
            rnd, path = int(m[1]), m[2]
            if rnd < 0:
                continue
            fr, dn, wf, kr, wk = map(int, m.groups()[2:])
            if n is None:
                raise ParseError("a time line before the config line")
            if fr != n or kr != n:
                raise ParseError(f"time round {rnd} {path}: {fr} fentry and {kr} kprobe runs, not {n} each ({line})")
            times.setdefault(path, []).append((dn / n, wf / n, wk / n))
        elif line.startswith("end "):
            m = END.match(line)
            if not m:
                raise ParseError(f"unparsed end: {line}")
            ends.append((int(m[1]), int(m[2], 16)))
        elif line.startswith("config "):
            m = CONFIG.match(line)
            if not m or n is not None:
                raise ParseError(f"config line: {line}")
            n = int(m[2])
            other.append(line)
        elif not line.strip():
            other.append(line)
        else:
            raise ParseError(f"unknown line: {line}")
    for name, c in cases.items():
        if len(c["more"]) != max(0, min(c["n"], KEEP) - 1):
            raise ParseError(f"case {name}: {c['n']} samples, {len(c['more'])} sample lines")
    missing = [c for c in CASES if c not in cases]
    if missing:
        raise ParseError(f"missing cases: {', '.join(missing)}")
    if len(races) != 1:
        raise ParseError(f"expected one race line, got {len(races)}")
    if len(ends) != 1:
        raise ParseError(f"expected one end line, got {len(ends)}")
    return cases, races[0], times, other, ends[0]


def report(text: str) -> tuple[str, int]:
    cases, race, times, other, (lost, kflags) = parse(text)
    fails, notes = [], []
    out = ["# path_walk: the dentry walk against bpf_d_path (gate 2)", ""]
    out += [ln[7:] for ln in other if ln.startswith("config ")] + [""]
    out += ["| case | samples | verdict (worst) | expected | walk's flags | bpf_d_path | walk |",
            "|---|---|---|---|---|---|---|"]
    for c in CASES:
        r = cases[c]
        exp = EXPECT.get(c, "equal")
        out.append(f"| {c} | {r['n']} | {r['verdict']} | {exp} | {flag_names(r['flags'])} | `{r.get('dpath', '')[:60]}` | "
                   f"`{r.get('walk', '')[:60]}` |")
        for k, x in enumerate(r["more"], 1):
            out.append(f"| ... sample {k} | | {x['verdict']} | | {flag_names(x['flags'])} | `{x['dpath'][:60]}` | "
                       f"`{x['walk'][:60]}` |")
            if x["verdict"] == "MISMATCH":
                fails.append(f"case {c} sample {k}: the walk gave another path and did not say so")
        if r["verdict"] == "MISMATCH":
            fails.append(f"case {c}: the walk gave another path and did not say so")
        elif r["verdict"] not in ("equal", "flagged"):
            fails.append(f"case {c}: {r['verdict']} ({r['raw']})")
        elif r["verdict"] != exp:
            notes.append(f"case {c}: {r['verdict']}, expected {exp}" + (f" ({WHY[c]})" if c in WHY else ""))
    out += ["", f"Rename race: {race['opens']:,} opens against {race['renames']:,} renames on another CPU; "
            f"{race['samples']:,} samples: {race['equal']:,} equal, {race['flagged']:,} flagged, "
            f"{race['moved']:,} not compared (the tree moved between bpf_d_path and the walk) "
            f"({race['raced']:,} RACED after the retry; {race['retried']:,} needed the retry), "
            f"**{race['mismatch']:,} wrong without a flag**; bpf_d_path failed {race['dpath_failed']:,}, "
            f"opens failed {race['open_failed']:,}.", ""]
    if race["mismatch"]:
        fails.append(f"the rename race: {race['mismatch']} samples wrong without a flag")
        out += [ln for ln in other if ln.startswith("race_mismatch")] + [""]
    if race["samples"] - race["moved"] <= 0:
        fails.append("the rename race compared no sample")
    out += [f"Samples the ring had no room for (fentry, all parts): {lost:,}. Flags the walk set in the kprobe.session: "
            f"{flag_names(kflags)}.", ""]
    if times:
        out += ["| path | rounds | bpf_d_path (fentry) | walk (fentry) | walk (kprobe.session) |", "|---|---|---|---|---|"]
        for path, rows in times.items():
            med = [statistics.median(col) for col in zip(*rows)]
            out.append(f"| {path} | {len(rows)} | {med[0]:.1f} ns | {med[1]:.1f} ns | {med[2]:.1f} ns |")
        out.append("")
    else:
        fails.append("no timing rounds")
    out += ["## Verdict", ""]
    out += [f"- FAIL: {f}" for f in fails] or ["- PASS: no case and no race sample gave a wrong path without a flag"]
    out += [f"- note: {n}" for n in notes]
    return "\n".join(out + [""]), 1 if fails else 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        text, rc = report(Path(argv[1]).read_text())
    except (ParseError, ValueError) as e:
        print(f"summarize: {e}", file=sys.stderr)
        return 1
    print(text)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
