#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize hook_cost output (bench/hook_cost/hook_cost.c) as the ADR-0018 rule 2 report.

    python3 bench/hook_cost/summarize.py hook_cost.txt

Per event, on the metric declared before the run (rename: the harness's thread CPU time; exec:
its children's CPU time, where the hook runs), and on wall time as the secondary:
  - each arm's cost per event: median over rounds, with its order-statistic interval;
  - tp against none, btf against none, and spine against none (exec): the paired effect, its
    exact interval and p, against the A/A floor (none2 against none), and the verdict;
  - tp against btf, the question ADR-0020 confirmation 5 asks, against the same A/A floor;
  - the added cost per event in ns (Hodges-Lehmann of the per-round differences), also as a
    multiple of the same session's null-syscall time (ADR-0018 rule 3.2).
The warm-up rows (round -1) are checked but not used. Exit 1 if any arm's books don't close,
if an arm is missing from a round, or if a result-like line doesn't parse.
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "quant"))
import paired as P  # noqa: E402

ROW = re.compile(r"^row round=(-?\d+) event=(rename|exec) arm=(\w+) n=(\d+) cpu_ns=(-?\d+) wall_ns=(\d+) hits=(\d+)$")
NULL = re.compile(r"^nullsys round=(\d+) calls=(\d+) total_ns=(\d+)$")
ARMS = {"rename": ("none", "none2", "tp", "btf"), "exec": ("none", "none2", "tp", "btf", "spine")}
PRIMARY = {"rename": "cpu_ns", "exec": "cpu_ns"}
UNTRACED = ("none", "none2")


class ParseError(Exception):
    pass


def parse(text: str):
    rows = defaultdict(dict)            # (event, round) -> arm -> row
    nulls = {}
    bad = []
    for line in text.splitlines():
        if line.startswith("row "):
            m = ROW.match(line)
            if not m:
                raise ParseError(f"unparsed row: {line}")
            rnd, ev, arm, n, cpu, wall, hits = m.groups()
            rnd, n, hits = int(rnd), int(n), int(hits)
            want = 0 if arm in UNTRACED else n
            if hits != want:
                bad.append(f"round {rnd} {ev}/{arm}: {hits} hits, expected {want}")
            if rnd >= 0:
                rows[(ev, rnd)][arm] = {"n": n, "cpu_ns": int(cpu), "wall_ns": int(wall)}
        elif line.startswith("nullsys "):
            m = NULL.match(line)
            if not m:
                raise ParseError(f"unparsed nullsys: {line}")
            nulls[int(m[1])] = int(m[3]) / int(m[2])
    return rows, nulls, bad


def series(rows, ev: str, metric: str):
    rounds = sorted(r for (e, r) in rows if e == ev)
    out = {a: [] for a in ARMS[ev]}
    for r in rounds:
        got = rows[(ev, r)]
        missing = [a for a in ARMS[ev] if a not in got]
        if missing:
            raise ParseError(f"round {r} {ev}: missing arms {missing}")
        for a in ARMS[ev]:
            out[a].append(got[a][metric] / got[a]["n"])        # per event
    return rounds, out


def _ns(x: float) -> str:
    return f"{x:,.1f} ns"


def comparison(name: str, t: list[float], u: list[float], aa: list[float], null_ns: float) -> list[str]:
    r = P.paired_report(t, u, aa)
    diff = P.hodges_lehmann([a - b for a, b in zip(t, u)])
    lines = [f"- **{name}:** {r.verdict()}"]
    ci = diff.ci
    added = f"added per event {_ns(diff.estimate)}"
    if ci:
        added += f" (95 % interval {_ns(ci.lo)} to {_ns(ci.hi)})"
    added += f", {diff.estimate / null_ns:.2f} null syscalls"
    lines.append(f"  - {added}; ratio of medians {r.ratio_of_medians:.4f}; effect p = {r.effect_test.p_two_sided:.3g}")
    if r.notes:
        lines.append("  - notes: " + "; ".join(r.notes))
    return lines


def report(text: str) -> tuple[str, int]:
    rows, nulls, bad = parse(text)
    if not nulls:
        raise ParseError("no nullsys lines")
    null_ns = P.median(list(nulls.values()))
    out = ["# hook_cost: the classic-tracepoint hook path against tp_btf (ADR-0020 confirmation 5)", "",
           f"Null syscall (getppid), median over rounds: {_ns(null_ns)}.", ""]
    for ev in ("rename", "exec"):
        for metric in (PRIMARY[ev], "wall_ns"):
            rounds, s = series(rows, ev, metric)
            if not rounds:
                continue
            role = "primary" if metric == PRIMARY[ev] else "secondary"
            out += [f"## {ev}, {metric[:-3]} time per event ({role}; {len(rounds)} rounds)", "",
                    "| arm | median | 95 % interval |", "|---|---|---|"]
            for a in ARMS[ev]:
                ci = P.median_ci(s[a])
                span = f"{_ns(ci.lo)} to {_ns(ci.hi)}" if ci else "too few rounds"
                out.append(f"| {a} | {_ns(P.median(s[a]))} | {span} |")
            out.append("")
            u, aa = s["none"], s["none2"]
            out += comparison("tp against none", s["tp"], u, aa, null_ns)
            out += comparison("btf against none", s["btf"], u, aa, null_ns)
            if ev == "exec":
                out += comparison("spine EXEC (shipped) against none", s["spine"], u, aa, null_ns)
            # tp against btf, with the same host floor: U' / U carried onto the btf arm
            out += comparison("tp against btf (the ADR-0020 question)", s["tp"], s["btf"],
                              [b * v / w for b, v, w in zip(s["btf"], aa, u)], null_ns)
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
