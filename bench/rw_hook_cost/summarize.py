#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize rw_hook_cost output (bench/rw_hook_cost/rw_hook_cost.c) as the ADR-0018 rule 2 report.

    python3 bench/rw_hook_cost/summarize.py rw_hook_cost.txt

On the metric declared before the run (the harness thread's CPU time per read), and on wall time
as the secondary:
  - each arm's cost per read: median over rounds, with its order-statistic interval;
  - every traced arm against none: the paired effect, its exact interval and p, against the A/A
    floor (none2 against none), and the verdict;
  - the comparisons decision 1a and N5 ask: session against pair, session against fexit, and
    session against kpm, each against the same floor carried onto the second arm;
  - the added cost per read in ns (Hodges-Lehmann of the per-round differences), also as a
    multiple of the session's null-syscall time (ADR-0018 rule 3.2);
  - the kernel's skip counters per arm, summed over all rounds (recursion_misses, and the
    kprobe.multi links' missed), and the coexistence check.
The warm-up rows (round -1) are checked but not timed. If any book does not close, only the books
and skip counters are reported. Exit 1 if any book does not close, if the coexistence check failed, if an arm is missing from a round, or if a result-like line does
not parse.
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "quant"))
import paired as P  # noqa: E402

ROW = re.compile(r"^row round=(-?\d+) event=read arm=(\w+) n=(\d+) cpu_ns=(-?\d+) wall_ns=(\d+) "
                 r"hits=(\d+) orphan=(\d+) rmiss=(\d+) lmiss=(\d+)$")
NULL = re.compile(r"^nullsys round=(\d+) calls=(\d+) total_ns=(\d+)$")
COEXIST = re.compile(r"^coexist function=(\w+) opens=(\d+) session=(\d+) fentry=(\d+) (ok|FAIL)$")
ALL_ARMS = ("none", "none2", "fentry", "fexit", "kpm", "pair", "session")
UNTRACED = ("none", "none2")
QUESTIONS = (("session", "pair"), ("session", "fexit"), ("session", "kpm"))


class ParseError(Exception):
    pass


def parse(text: str):
    rows = defaultdict(dict)            # round -> arm -> row
    nulls, coexist, bad = {}, [], []
    skips = defaultdict(lambda: [0, 0])
    for line in text.splitlines():
        if line.startswith("row "):
            m = ROW.match(line)
            if not m:
                raise ParseError(f"unparsed row: {line}")
            rnd, arm, n, cpu, wall, hits, orphan, rmiss, lmiss = m.groups()
            rnd, n, hits, orphan = int(rnd), int(n), int(hits), int(orphan)
            if arm not in ALL_ARMS:
                raise ParseError(f"unknown arm: {line}")
            want = 0 if arm in UNTRACED else n
            if hits != want:
                bad.append(f"round {rnd} {arm}: {hits} hits, expected {want}")
            if orphan:
                bad.append(f"round {rnd} {arm}: {orphan} returns without their entry")
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
        elif line.startswith("coexist "):
            m = COEXIST.match(line)
            if not m:
                raise ParseError(f"unparsed coexist: {line}")
            coexist.append(m.groups())
            if m[5] != "ok":
                bad.append(f"coexist on {m[1]}: session {m[3]}, fentry {m[4]}, expected {m[2]} each")
    return rows, nulls, coexist, skips, bad


def series(rows, metric: str):
    rounds = sorted(rows)
    if not rounds:
        return [], (), {}
    arms = tuple(a for a in ALL_ARMS if a in rows[rounds[0]])
    out = {a: [] for a in arms}
    for r in rounds:
        missing = [a for a in arms if a not in rows[r]]
        if missing:
            raise ParseError(f"round {r}: missing arms {missing}")
        for a in arms:
            out[a].append(rows[r][a][metric] / rows[r][a]["n"])
    return rounds, arms, out


def _ns(x: float) -> str:
    return f"{x:,.1f} ns"


def comparison(name: str, t: list[float], u: list[float], aa: list[float], null_ns: float) -> list[str]:
    r = P.paired_report(t, u, aa)
    diff = P.hodges_lehmann([a - b for a, b in zip(t, u)])
    lines = [f"- **{name}:** {r.verdict()}"]
    added = f"added per read {_ns(diff.estimate)}"
    if diff.ci:
        added += f" (95 % interval {_ns(diff.ci.lo)} to {_ns(diff.ci.hi)})"
    added += f", {diff.estimate / null_ns:.2f} null syscalls"
    lines.append(f"  - {added}; ratio of medians {r.ratio_of_medians:.4f}; effect p = {r.effect_test.p_two_sided:.3g}")
    if r.notes:
        lines.append("  - notes: " + "; ".join(r.notes))
    return lines


def report(text: str) -> tuple[str, int]:
    rows, nulls, coexist, skips, bad = parse(text)
    if not nulls:
        raise ParseError("no nullsys lines")
    null_ns = P.median(list(nulls.values()))
    out = ["# rw_hook_cost: hook types on vfs_read (ADR-0015 decision 1a, N5)", "",
           f"Null syscall (getppid), median over rounds: {_ns(null_ns)}.", ""]
    # timings are reported only when every book closes: a broken arm's times mean nothing
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
            if t in s and b in s:
                out += comparison(f"{t} against {b}", s[t], s[b], [x * v / w for x, v, w in zip(s[b], aa, u)], null_ns)
        out.append("")
    out += ["## Kernel skip counters, all rounds", "", "| arm | recursion_misses | kprobe_multi.missed |", "|---|---|---|"]
    out += [f"| {a} | {skips[a][0]} | {skips[a][1]} |" for a in ALL_ARMS if a in skips]
    out.append("")
    out += ["## kprobe.session and fentry on one function", ""]
    out += [f"- {f}: {o} opens, session {sv}, fentry {fv}: {v}" for f, o, sv, fv, v in coexist] or ["- not run"]
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
