#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize an idle-cost run (bench/idle_cost/run.py): gate 3 of STATE decision 28.

    python3 bench/idle_cost/summarize.py idle_cost.txt [--budget-ms 2.0]

Per arm: p15d's CPU per second of wall time over each round's window (all threads; the median over
rounds, with the cheapest and dearest round), each thread's median, the drain's polls per second,
and the background load in the window (spine and bulk records per second), with the ratio of the
first arm's CPU to each arm's. The budget (STATE decision 29: under 2 ms of CPU per second idle) is
met by an arm whose median and dearest round are both under it.
Exit 1 if a run failed, a line does not parse, an arm misses rounds, or the harness stopped.
"""
from __future__ import annotations

import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

CONFIG = re.compile(r"^config rounds=(\d+) settle=(\S+) window=(\S+) arms=(.+)$")
THREAD = re.compile(r"^thread arm=(\w+) round=(\d+) name=(\S+) cpu_ns=(\d+)$")
RUN = re.compile(r"^run arm=(\w+) round=(\d+) window_ns=(\d+) cpu_ns=(\d+) spine=(\d+) bulk=(\d+) polls_per_s=(-?[\d.]+) "
                 r"exit=(-?\d+) end=(\d) state=(-?\d+) invariant=(-?\d+) (ok|FAIL)$")


class ParseError(Exception):
    pass


def parse(text: str) -> dict:
    cfg, runs, threads, bad = None, defaultdict(dict), defaultdict(lambda: defaultdict(dict)), []
    for line in text.splitlines():
        if not line.strip():
            continue
        if m := CONFIG.match(line):
            if cfg is not None:
                raise ParseError("a second config line")
            cfg = {"rounds": int(m[1]), "window": float(m[3]),
                   "arms": [x.split(":", 1)[0] for x in m[4].split(";")]}
        elif m := THREAD.match(line):
            threads[m[1]][int(m[2])][m[3]] = threads[m[1]][int(m[2])].get(m[3], 0) + int(m[4])
        elif m := RUN.match(line):
            arm, rnd = m[1], int(m[2])
            if rnd in runs[arm]:
                raise ParseError(f"arm {arm} round {rnd} twice")
            runs[arm][rnd] = {"window": int(m[3]), "cpu": int(m[4]), "spine": int(m[5]), "bulk": int(m[6]),
                              "polls": float(m[7]), "ok": m[12] == "ok"}
            if m[12] != "ok":
                bad.append(f"arm {arm} round {rnd} failed: {line}")
        elif line.startswith("run_error "):
            bad.append(f"the harness stopped: {line[10:]}")
        else:
            raise ParseError(f"unknown line: {line}")
    if cfg is None:
        raise ParseError("no config line")
    for arm in cfg["arms"]:
        if sorted(runs[arm]) != list(range(cfg["rounds"])):
            bad.append(f"arm {arm}: rounds {sorted(runs[arm])}, expected 0..{cfg['rounds'] - 1}")
    extra = set(runs) - set(cfg["arms"])
    if extra:
        raise ParseError(f"runs of arms not in the config: {', '.join(sorted(extra))}")
    return {"cfg": cfg, "runs": runs, "threads": threads, "bad": bad}


def ms_per_s(cpu_ns: int, window_ns: int) -> float:
    return cpu_ns / window_ns * 1e3


def report(text: str, budget: float = 2.0) -> tuple[str, int]:
    d = parse(text)
    cfg, runs = d["cfg"], d["runs"]
    out = ["# idle_cost: p15d's CPU on an idle host (gate 3)", "",
           f"{cfg['rounds']} rounds of a {cfg['window']:g} s window per arm, arms rotated each round. "
           f"Budget (STATE decision 29): under {budget:g} ms of CPU per second.", ""]
    if d["bad"]:
        return "\n".join(out + ["## Checks that failed: no number is reported", ""] + [f"- {b}" for b in d["bad"]] + [""]), 1
    out += ["| arm | CPU ms/s, median | cheapest .. dearest round | polls/s | load, records/s (spine + bulk) | "
            "first arm / this | under the budget |", "|---|---|---|---|---|---|---|"]
    med = {}
    for arm in cfg["arms"]:
        rs = [runs[arm][k] for k in sorted(runs[arm])]
        cpu = [ms_per_s(r["cpu"], r["window"]) for r in rs]
        load = statistics.median((r["spine"] + r["bulk"]) / (r["window"] / 1e9) for r in rs)
        med[arm] = statistics.median(cpu)
        ratio = med[cfg["arms"][0]] / med[arm] if med[arm] else float("inf")
        out.append(f"| {arm} | {med[arm]:.3f} | {min(cpu):.3f} .. {max(cpu):.3f} | "
                   f"{statistics.median(r['polls'] for r in rs):.1f} | {load:.1f} | {ratio:.2f}x | "
                   f"{'yes' if med[arm] < budget and max(cpu) < budget else 'no'} |")
    out += ["", "Per thread, median ms/s over rounds:", ""]
    names = sorted({n for arm in cfg["arms"] for rnd in d["threads"][arm].values() for n in rnd})
    out += ["| arm | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for arm in cfg["arms"]:
        cells = []
        for n in names:
            v = [ms_per_s(d["threads"][arm][k].get(n, 0), runs[arm][k]["window"]) for k in sorted(runs[arm])]
            cells.append(f"{statistics.median(v):.3f}")
        out.append(f"| {arm} | " + " | ".join(cells) + " |")
    return "\n".join(out + [""]), 0


def main(argv: list[str]) -> int:
    args = argv[1:]
    budget = 2.0
    if len(args) == 3 and args[1] == "--budget-ms":
        budget = float(args[2])
        args = args[:1]
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        text, rc = report(Path(args[0]).read_text(), budget)
    except (ParseError, ValueError) as e:
        print(f"summarize: {e}", file=sys.stderr)
        return 1
    print(text)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
