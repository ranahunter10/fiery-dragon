#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize flow_cost output (bench/flow_cost/flow_cost.c) as the ADR-0018 rule 2 report.

    python3 bench/flow_cost/summarize.py flow_cost.txt

On the metric declared before the run (the harness thread's CPU time per read), and on wall time
as the secondary:
  - each arm's cost per read: median over rounds, with its order-statistic interval;
  - every traced arm against none, against the A/A floor (none2 against none);
  - the questions of decision waiting 13: ts against session (what option A's task storage adds
    without a record), ts_rec against end_rec (what option A adds to a record: the deciding
    number), end_rec against session (what writing the record costs);
  - the added cost per read in ns, also in null syscalls (ADR-0018 rule 3.2);
  - the kernel's skip counters per arm, and the check pass (option A's start times inside each
    read's own CLOCK_BOOTTIME bracket).
Timings are reported only if every book closes. Exit 1 if a book does not close, the check failed
or is missing, an arm is missing from a round, or a result-like line does not parse.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "quant"))
import paired as P  # noqa: E402

# rw_hook_cost's report lines, so both benches state a comparison the same way
_spec = importlib.util.spec_from_file_location("rw_hook_cost_summarize",
                                               Path(__file__).resolve().parents[1] / "rw_hook_cost" / "summarize.py")
_RW = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_RW)
comparison, _ns = _RW.comparison, _RW._ns

ROW = re.compile(r"^row round=(-?\d+) event=read arm=(\w+) n=(\d+) cpu_ns=(-?\d+) wall_ns=(\d+) "
                 r"hits=(\d+) lost=(\d+) drained=(\d+) refused=(\d+) rmiss=(\d+) lmiss=(\d+)$")
NULL = re.compile(r"^nullsys round=(\d+) calls=(\d+) total_ns=(\d+)$")
CHECK = re.compile(r"^check reads=(\d+) flows=(\d+) outside=(\d+) refused=(\d+) ts_lost=(\d+) "
                   r"create_failed=(\d+) (ok|FAIL)$")
ALL_ARMS = ("none", "none2", "session", "ts", "end_rec", "ts_rec")
UNTRACED = ("none", "none2")
RECORDS = ("end_rec", "ts_rec")
QUESTIONS = (("ts", "session"), ("ts_rec", "end_rec"), ("end_rec", "session"))


class ParseError(Exception):
    pass


def parse(text: str):
    rows = defaultdict(dict)            # round -> arm -> row
    nulls, checks, bad = {}, [], []
    skips = defaultdict(lambda: [0, 0])
    for line in text.splitlines():
        if line.startswith("row "):
            m = ROW.match(line)
            if not m:
                raise ParseError(f"unparsed row: {line}")
            rnd, arm, n, cpu, wall, hits, lost, drained, refused, rmiss, lmiss = m.groups()
            rnd, n, hits, lost, drained, refused = int(rnd), int(n), int(hits), int(lost), int(drained), int(refused)
            if arm not in ALL_ARMS:
                raise ParseError(f"unknown arm: {line}")
            if hits != (0 if arm in UNTRACED else n):
                bad.append(f"round {rnd} {arm}: {hits} hits, expected {0 if arm in UNTRACED else n}")
            if lost:
                bad.append(f"round {rnd} {arm}: {lost} lost (no cookie, start time, storage or reservation)")
            if refused:
                bad.append(f"round {rnd} {arm}: the drain refused {refused} FLOW records")
            if drained != (n if arm in RECORDS else 0):
                bad.append(f"round {rnd} {arm}: {drained} FLOW records drained, expected {n if arm in RECORDS else 0}")
            skips[arm][0] += int(rmiss)
            skips[arm][1] += int(lmiss)
            if int(cpu) <= 0 or int(wall) <= 0:
                bad.append(f"round {rnd} {arm}: no time measured (the arm did not run)")
            elif rnd >= 0:
                rows[rnd][arm] = {"n": n, "cpu_ns": int(cpu), "wall_ns": int(wall)}
        elif line.startswith("nullsys "):
            m = NULL.match(line)
            if not m:
                raise ParseError(f"unparsed nullsys: {line}")
            nulls[int(m[1])] = int(m[3]) / int(m[2])
        elif line.startswith("check "):
            m = CHECK.match(line)
            if not m:
                raise ParseError(f"unparsed check: {line}")
            checks.append(m.groups())
            if m[7] != "ok" or m[1] != m[2] or any(int(x) for x in m.groups()[2:6]):
                bad.append(f"check: {m[2]} of {m[1]} FLOWs, {m[3]} outside their read, {m[4]} refused, "
                           f"{m[5]} start times lost, {m[6]} storage creations failed")
    if not checks:
        bad.append("no check line: option A's start times were not checked")
    return rows, nulls, checks, skips, bad


def series(rows, metric: str):
    rounds = sorted(rows)
    if not rounds:
        return [], (), {}
    arms = tuple(a for a in ALL_ARMS if a in rows[rounds[0]])
    out = {a: [] for a in arms}
    for r in rounds:
        missing = [a for a in ALL_ARMS if a not in rows[r]]
        if missing:
            raise ParseError(f"round {r}: missing arms {missing}")
        for a in arms:
            out[a].append(rows[r][a][metric] / rows[r][a]["n"])
    return rounds, arms, out


def report(text: str) -> tuple[str, int]:
    rows, nulls, checks, skips, bad = parse(text)
    if not nulls:
        raise ParseError("no nullsys lines")
    null_ns = P.median(list(nulls.values()))
    out = ["# flow_cost: step 2b's read hook and FLOW's start time (decision waiting 13)", "",
           f"Null syscall (getppid), median over rounds: {_ns(null_ns)}.", ""]
    for metric in (() if bad else ("cpu_ns", "wall_ns")):
        rounds, arms, s = series(rows, metric)
        if not rounds:
            raise ParseError("no timed rounds")
        role = "primary" if metric == "cpu_ns" else "secondary"
        out += [f"## {metric[:-3]} time per read ({role}; {len(rounds)} rounds)", "",
                "| arm | median | 95 % interval |", "|---|---|---|"]
        for a in arms:
            ci = P.median_ci(s[a])
            span = f"{_ns(ci.lo)} to {_ns(ci.hi)}" if ci else "too few rounds"
            out.append(f"| {a} | {_ns(P.median(s[a]))} | {span} |")
        out.append("")
        u, aa = s["none"], s["none2"]
        for a in arms:
            if a not in UNTRACED:
                out += comparison(f"{a} against none", s[a], u, aa, null_ns)
        for t, b in QUESTIONS:
            out += comparison(f"{t} against {b}", s[t], s[b], [x * v / w for x, v, w in zip(s[b], aa, u)], null_ns)
        out.append("")
    out += ["## Kernel skip counters, all rounds", "", "| arm | recursion_misses | kprobe_multi.missed |", "|---|---|---|"]
    out += [f"| {a} | {skips[a][0]} | {skips[a][1]} |" for a in ALL_ARMS if a in skips]
    out += ["", "## Option A's start times against each read's bracket", ""]
    out += [f"- {c[0]} reads, {c[1]} FLOWs, {c[2]} outside their read, {c[4]} lost, {c[5]} creations failed: {c[6]}"
            for c in checks] or ["- not run"]
    out.append("")
    if bad:
        out += ["## Books that did not close", ""] + [f"- {b}" for b in bad] + [""]
    return "\n".join(out), 1 if bad else 0


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
