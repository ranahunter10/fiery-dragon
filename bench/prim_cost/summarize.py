#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize prim_cost output (bench/prim_cost/prim_cost.c).

    python3 bench/prim_cost/summarize.py prim_cost.txt

Per primitive: the cost of one iteration, as the median over rounds of (its time - the empty
loop's time in the same round) / iterations, with the order-statistic interval of the median.
The warm-up round (-1) is checked but not timed. Nothing is reported unless every iteration of
every run did what it should and the ring handed over every record it was sent.
Exit 1 otherwise, or if a line does not parse or a round lacks a primitive.
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "quant"))
import paired as P  # noqa: E402

ROW = re.compile(r"^row round=(-?\d+) prim=(\w+) n=(\d+) ns=(\d+) ok=(\d+)$")
RING = re.compile(r"^ring sent=(\d+) consumed=(\d+) (ok|FAIL)$")
PRIMS = ("ring_reserve_submit", "ring_reserve_discard", "ring_output", "hash_lookup", "hash_update_delete", "counter",
         "percpu_copy", "ktime")
WHAT = {"ring_reserve_submit": "a 96-byte record reserved, filled and submitted to the ring (no wake-up)",
        "ring_reserve_discard": "the same reservation, discarded",
        "ring_output": "a 96-byte record copied into the ring (bpf_ringbuf_output)",
        "hash_lookup": "a lookup in a 65,536-entry hash map (hit)",
        "hash_update_delete": "an entry inserted into that map and deleted",
        "counter": "an atomic add to a global",
        "percpu_copy": "a 96-byte record copied into a per-CPU buffer",
        "ktime": "bpf_ktime_get_boot_ns"}


class ParseError(Exception):
    pass


def parse(text: str):
    rows = defaultdict(dict)
    bad, ring, config = [], None, ""
    for line in text.splitlines():
        if line.startswith("row "):
            m = ROW.match(line)
            if not m:
                raise ParseError(f"unparsed row: {line}")
            rnd, prim, n, ns, ok = m[1], m[2], int(m[3]), int(m[4]), int(m[5])
            if prim != "empty" and prim not in PRIMS:
                raise ParseError(f"unknown primitive: {line}")
            if ok != n:
                bad.append(f"round {rnd} {prim}: {ok} of {n} iterations did what they should")
            if n <= 0 or ns <= 0:
                bad.append(f"round {rnd} {prim}: nothing measured")
            elif int(rnd) >= 0:
                if prim in rows[int(rnd)]:
                    raise ParseError(f"round {rnd}: {prim} twice")
                rows[int(rnd)][prim] = ns / n
        elif line.startswith("ring "):
            m = RING.match(line)
            if not m:
                raise ParseError(f"unparsed ring line: {line}")
            ring = (int(m[1]), int(m[2]))
            if m[3] != "ok" or ring[0] != ring[1]:
                bad.append(f"the ring was sent {ring[0]} records and handed over {ring[1]}")
        elif line.startswith("config "):
            config = line[7:]
        elif line.strip():
            raise ParseError(f"unknown line: {line}")
    for r in sorted(rows):
        missing = [p for p in ("empty",) + PRIMS if p not in rows[r]]
        if missing:
            raise ParseError(f"round {r}: missing {', '.join(missing)}")
    if ring is None:
        bad.append("no ring line: the run did not finish")
    return rows, bad, config


def report(text: str) -> tuple[str, int]:
    rows, bad, config = parse(text)
    out = ["# prim_cost: what a capture program's building blocks cost on this host", ""]
    if config:
        out += [f"Run: {config}.", ""]
    if bad:
        return "\n".join(out + ["## Checks that failed: no cost is reported", ""] + [f"- {b}" for b in bad] + [""]), 1
    if not rows:
        raise ParseError("no timed rounds")
    rounds = sorted(rows)
    empty = [rows[r]["empty"] for r in rounds]
    out += [f"{len(rounds)} rounds. The empty loop: {P.median(empty):.1f} ns per iteration (subtracted below, round by round).",
            "", "| primitive | ns per iteration (median) | 95 % interval | what it is |", "|---|---|---|---|"]
    for p in PRIMS:
        net = [rows[r][p] - rows[r]["empty"] for r in rounds]
        ci = P.median_ci(net)
        span = f"{ci.lo:.1f} to {ci.hi:.1f}" if ci else "too few rounds"
        out.append(f"| {p} | {P.median(net):.1f} | {span} | {WHAT[p]} |")
    return "\n".join(out + [""]), 0


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
