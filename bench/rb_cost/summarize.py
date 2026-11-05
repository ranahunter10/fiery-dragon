#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize exec_cost output (bench/rb_cost/exec_cost.c) as Markdown.

    python3 bench/rb_cost/summarize.py exec_cost.txt

Per argv size and EXEC way: the per-run cost run_time_ns / run_cnt from bpf_stats, as the
median, min and max over rounds, and as a multiple of the same session's null-syscall time
(ADR-0018 rule 3.2). Then, paired by round, each way's difference from OUTPUT. These are this
host's numbers, raw medians and ranges; they are not an ADR-0018 overhead estimate.

Exit 1 if a row reports a wrong record or a missed exec, if the ways do not have the same
rounds, or if a line that starts like a result line does not parse.
"""
from __future__ import annotations

import re
import statistics
import sys
from collections import defaultdict

WAYS = ("fixed", "output", "dynptr")
ROW_KEYS = ("round", "way", "argv", "execs", "run_cnt", "run_time_ns", "ours", "foreign", "invalid",
            "wrong_size", "wrong_argv")
KV = re.compile(r"(\w+)=(\S+)")


class ParseError(Exception):
    pass


def parse(lines: list[str]) -> dict:
    out = {"selftest": {}, "nullsys": {}, "rows": [], "other": 0}
    for no, line in enumerate(lines, 1):
        word = line.split(" ", 1)[0]
        if word not in ("row", "nullsys", "selftest"):
            out["other"] += 1
            continue
        kv = dict(KV.findall(line))
        try:
            if word == "selftest":
                verdict = line.split()[2]
                if kv["way"] not in WAYS or verdict not in ("PASS", "FAIL"):
                    raise ValueError
                out["selftest"][kv["way"]] = (verdict, int(kv["failed_checks"]))
            elif word == "nullsys":
                out["nullsys"][int(kv["round"])] = int(kv["total_ns"]) / int(kv["calls"])
            else:
                if set(kv) != set(ROW_KEYS) or kv["way"] not in WAYS:
                    raise ValueError
                row = {k: (v if k == "way" else int(v)) for k, v in kv.items()}
                if row["run_cnt"] <= 0:
                    raise ValueError
                out["rows"].append(row)
        except (KeyError, ValueError, IndexError):
            raise ParseError(f"line {no}: cannot parse: {line.strip()}") from None
    return out


def problems(d: dict) -> list[str]:
    probs = []
    for r in d["rows"]:
        if r["ours"] != r["execs"] or r["invalid"] or r["wrong_size"] or r["wrong_argv"]:
            probs.append(f"round {r['round']} {r['way']} argv {r['argv']}: ours {r['ours']}/{r['execs']}, "
                         f"invalid {r['invalid']}, wrong size {r['wrong_size']}, wrong argv {r['wrong_argv']}")
    rounds = defaultdict(set)
    for r in d["rows"]:
        rounds[(r["argv"], r["way"])].add(r["round"])
    for argv in {a for a, _ in rounds}:
        sets = [rounds.get((argv, w), set()) for w in WAYS]
        if any(s != sets[0] for s in sets):
            probs.append(f"argv {argv}: the ways do not have the same rounds")
    return probs


def ns_per_run(r: dict) -> float:
    return r["run_time_ns"] / r["run_cnt"]


def report(d: dict) -> str:
    L = ["## Self-test per way", "", "| Way | Verdict | Failed checks |", "|---|---|---:|"]
    L += [f"| {w} | {d['selftest'][w][0]} | {d['selftest'][w][1]} |" for w in WAYS if w in d["selftest"]]
    null = sorted(d["nullsys"].values())
    nmed = statistics.median(null) if null else None
    if null:
        L += ["", f"Null syscall (getppid), ns per call over {len(null)} rounds: median {nmed:.1f}, "
              f"min {null[0]:.1f}, max {null[-1]:.1f}."]
    by = defaultdict(dict)
    for r in d["rows"]:
        by[(r["argv"], r["way"])][r["round"]] = ns_per_run(r)
    foreign = sum(r["foreign"] for r in d["rows"])
    L += ["", f"Records from other processes' execs during the measurements: {foreign} "
          "(their runs are inside run_cnt)."]
    for argv in sorted({a for a, _ in by}):
        L += ["", f"## argv {argv} bytes", "", "| Way | Rounds | Median ns/run | Min | Max | Median / null syscall |",
              "|---|---:|---:|---:|---:|---:|"]
        for w in WAYS:
            v = sorted(by[(argv, w)].values())
            if not v:
                continue
            m = statistics.median(v)
            ratio = f"{m / nmed:.1f}" if nmed else "-"
            L.append(f"| {w} | {len(v)} | {m:.0f} | {v[0]:.0f} | {v[-1]:.0f} | {ratio} |")
        L += ["", "Paired by round, minus OUTPUT:", "", "| Way | Median Δ ns | Min Δ | Max Δ | Rounds cheaper than OUTPUT |",
              "|---|---:|---:|---:|---:|"]
        base = by[(argv, "output")]
        for w in ("fixed", "dynptr"):
            diffs = sorted(by[(argv, w)][k] - base[k] for k in by[(argv, w)] if k in base)
            if diffs:
                below = sum(x < 0 for x in diffs)
                L.append(f"| {w} | {statistics.median(diffs):+.0f} | {diffs[0]:+.0f} | {diffs[-1]:+.0f} | "
                         f"{below} of {len(diffs)} |")
    return "\n".join(L) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: summarize.py EXEC_COST_OUTPUT", file=sys.stderr)
        return 2
    try:
        with open(argv[0]) as f:
            d = parse(f.read().splitlines())
    except ParseError as e:
        print(f"summarize: {e}", file=sys.stderr)
        return 1
    print(report(d), end="")
    probs = problems(d)
    for p in probs:
        print(f"PROBLEM: {p}")
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
