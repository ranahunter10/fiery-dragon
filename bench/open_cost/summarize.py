#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize an open-cost run (bench/open_cost/run.py) as the ADR-0018 rule 2 report.

    python3 bench/open_cost/summarize.py open_cost.txt

Timings are reported only if every traced arm's capture line is ok and every round has every arm
and event. Then, for each of the two open events (same: the steady state; distinct: every open a
first sighting), on the thread's CPU time (the primary metric, declared before the run) and on
wall time:
  - each arm's cost per open+close: the median over rounds with its order-statistic interval;
  - p15d against none: the paired effect, its exact interval and p, against the A/A floor (none2
    against none), and the verdict of rule 2.4;
  - the added cost per open+close in ns (Hodges-Lehmann of the per-round differences), also in
    null syscalls of the same session (rule 3.2).
And from the capture lines:
  - records and bytes per open+close in the WAL, the share of opens carrying facts, PATH_MISSING;
  - p15d's own CPU: per second when idle, and per open+close of the workload after the idle rate
    is taken off (both arithmetic means, costs that are sums: rule 2.5);
  - the agent overhead: p15d's CPU above its idle rate / the open events' CPU time without
    capture; and, as eAudit defines it (R-042 §4.3), all of p15d's CPU in the window / the whole
    workload's CPU time without capture.
Exit 1 if a book does not close, an arm or event is missing, or a line does not parse.
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "quant"))
import paired as P  # noqa: E402

ROW = re.compile(r"^row round=(-?\d+) arm=(\w+) event=(\w+) n=(\d+) cpu_ns=(\d+) wall_ns=(\d+)$")
CAP = re.compile(r"^capture round=(-?\d+) ((?:\w+=-?\d+ )+)(ok|FAIL)$")
ARMS = ("none", "p15d", "none2")
EVENTS = ("nullsys", "same", "distinct")
OPEN_EVENTS = ("same", "distinct")
CAP_KEYS = ("pid", "expected", "opens", "path_missing", "closes", "facts", "open_bytes", "close_bytes", "other_opens",
            "lost", "end", "state", "invariant", "stops", "exit", "idle_cpu_ns", "idle_wall_ns", "agent_cpu_ns",
            "agent_wall_ns")


class ParseError(Exception):
    pass


def parse(text: str):
    rows = defaultdict(dict)            # round -> (arm, event) -> row; timed rounds only
    caps, bad, config = {}, [], ""
    for line in text.splitlines():
        if line.startswith("row "):
            m = ROW.match(line)
            if not m:
                raise ParseError(f"unparsed row: {line}")
            rnd, arm, event, n, cpu, wall = m.groups()
            if arm not in ARMS or event not in EVENTS:
                raise ParseError(f"unknown arm or event: {line}")
            if int(n) <= 0 or int(cpu) <= 0 or int(wall) <= 0:
                bad.append(f"round {rnd} {arm} {event}: nothing measured")
            elif int(rnd) >= 0:
                if (arm, event) in rows[int(rnd)]:
                    raise ParseError(f"round {rnd}: {arm} {event} twice")
                rows[int(rnd)][(arm, event)] = {"n": int(n), "cpu_ns": int(cpu), "wall_ns": int(wall)}
        elif line.startswith("capture "):
            m = CAP.match(line)
            if not m:
                raise ParseError(f"unparsed capture: {line}")
            f = {k: int(v) for k, v in (kv.split("=") for kv in m[2].split())}
            if set(f) != set(CAP_KEYS):
                raise ParseError(f"capture line with other fields: {line}")
            if m[3] != "ok":
                bad.append(f"round {m[1]}: capture books: {m[2].strip()}")
            if int(m[1]) >= 0:
                caps[int(m[1])] = f
        elif line.startswith("error "):
            bad.append(line)
        elif line.startswith("config "):
            config = line[7:]
        elif line.strip():
            raise ParseError(f"unknown line: {line}")
    for r in sorted(rows):
        missing = [f"{a}/{e}" for a in ARMS for e in EVENTS if (a, e) not in rows[r]]
        if missing:
            raise ParseError(f"round {r}: missing {', '.join(missing)}")
        if r not in caps:
            raise ParseError(f"round {r}: no capture line")
    return rows, caps, bad, config


def per_op(rows, arm: str, event: str, metric: str) -> list[float]:
    return [rows[r][(arm, event)][metric] / rows[r][(arm, event)]["n"] for r in sorted(rows)]


def _ns(x: float) -> str:
    return f"{x:,.1f} ns"


def _span(ci) -> str:
    return f"{_ns(ci.lo)} to {_ns(ci.hi)}" if ci else "too few rounds"


def timing(rows, event: str, metric: str, null_ns: float) -> list[str]:
    t, u, aa = (per_op(rows, a, event, metric) for a in ("p15d", "none", "none2"))
    out = ["| arm | median per open+close | 95 % interval |", "|---|---|---|"]
    out += [f"| {a} | {_ns(P.median(x))} | {_span(P.median_ci(x))} |" for a, x in (("none", u), ("none2", aa), ("p15d", t))]
    r = P.paired_report(t, u, aa)
    diff = P.hodges_lehmann([a - b for a, b in zip(t, u)])
    out += ["", f"- **p15d against none:** {r.verdict()}",
            f"  - added per open+close {_ns(diff.estimate)} (95 % interval {_span(diff.ci)}), "
            f"{diff.estimate / null_ns:.2f} null syscalls; ratio of medians {r.ratio_of_medians:.4f}; "
            f"effect p = {r.effect_test.p_two_sided:.3g}"]
    if r.notes:
        out.append("  - notes: " + "; ".join(r.notes))
    return out + [""]


def capture_section(rows, caps) -> list[str]:
    rounds = sorted(rows)
    c = [caps[r] for r in rounds]
    opens = sum(x["opens"] for x in c)
    exp = sum(x["expected"] for x in c)
    recs = sum(x["opens"] + x["path_missing"] + x["closes"] for x in c)
    byts = sum(x["open_bytes"] + x["close_bytes"] for x in c)
    idle_rate = [x["idle_cpu_ns"] / (x["idle_wall_ns"] / 1e9) for x in c]                 # ns of CPU per second
    net = [(x["agent_cpu_ns"] - ir * x["agent_wall_ns"] / 1e9) / x["expected"] for x, ir in zip(c, idle_rate)]
    gross = [x["agent_cpu_ns"] / x["expected"] for x in c]
    open_cpu = [sum(rows[r][("none", e)]["cpu_ns"] for e in OPEN_EVENTS) for r in rounds]
    all_cpu = [sum(rows[r][("none", e)]["cpu_ns"] for e in EVENTS) for r in rounds]
    agent_net = [n * x["expected"] / b for n, x, b in zip(net, c, open_cpu)]
    agent_gross = [x["agent_cpu_ns"] / b for x, b in zip(c, all_cpu)]
    return [
        "## What the capture wrote and what it cost p15d", "",
        f"- opens expected {exp:,}; OPEN records with their path {opens:,}; PATH_MISSING records of the workload "
        f"{sum(x['path_missing'] for x in c):,}; CLOSE records {sum(x['closes'] for x in c):,}; lost to the ring "
        f"{sum(x['lost'] for x in c)}",
        f"- records per open+close: {recs / exp:.3f}; bytes per open+close in the WAL: {byts / exp:.1f} "
        f"(OPEN {sum(x['open_bytes'] for x in c) / max(opens, 1):.1f}, CLOSE "
        f"{sum(x['close_bytes'] for x in c) / max(sum(x['closes'] for x in c), 1):.1f})",
        f"- opens carrying the object's facts: {sum(x['facts'] for x in c) / max(opens, 1):.1%}",
        f"- opens by other processes during the traced arms: {sum(x['other_opens'] for x in c):,}",
        f"- p15d idle: {P.mean(idle_rate) / 1e6:.2f} ms of CPU per second (mean; median "
        f"{P.median(idle_rate) / 1e6:.2f})",
        f"- p15d per open+close of the workload: {_ns(P.mean(gross))} of CPU in the window (mean), "
        f"{_ns(P.mean(net))} after the idle rate is taken off (median {_ns(P.median(net))})",
        f"- agent overhead of the opens (p15d's CPU above its idle rate / the two open events' CPU time without "
        f"capture): mean {P.mean(agent_net):.1%}, median {P.median(agent_net):.1%}, range {min(agent_net):.1%} to "
        f"{max(agent_net):.1%}",
        f"- agent overhead of the whole workload, as eAudit defines it (all of p15d's CPU in the window / the "
        f"workload's CPU time without capture, null syscalls included): mean {P.mean(agent_gross):.1%}, median "
        f"{P.median(agent_gross):.1%}", ""]


def report(text: str) -> tuple[str, int]:
    rows, caps, bad, config = parse(text)
    out = ["# open_cost: what capture adds to an open and a close (decision 22a.4)", ""]
    if config:
        out += [f"Run: {config}.", ""]
    if bad:
        out += ["## Books that did not close: no timing is reported", ""] + [f"- {b}" for b in bad] + [""]
        return "\n".join(out), 1
    if not rows:
        raise ParseError("no timed rounds")
    null_ns = P.median(per_op(rows, "none", "nullsys", "cpu_ns"))
    out += [f"{len(rows)} rounds. Null syscall (getppid) without capture, median: {_ns(null_ns)}; with p15d: "
            f"{_ns(P.median(per_op(rows, 'p15d', 'nullsys', 'cpu_ns')))}.", ""]
    for event, what in (("same", "one file opened again and again (steady state)"),
                        ("distinct", "every open a first sighting (facts in the record)")):
        for metric, role in (("cpu_ns", "thread CPU time, primary"), ("wall_ns", "wall time, secondary")):
            out += [f"## {event}: {what}; {role}", ""] + timing(rows, event, metric, null_ns)
    out += capture_section(rows, caps)
    return "\n".join(out), 0


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
