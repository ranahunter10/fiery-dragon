# SPDX-License-Identifier: MIT
"""python3 -m p15.graph RUN_DIR OUT.duckdb [--pidsmaker DIR]: build a run's graph file, print its books."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import records as R
from .. import wal as W
from . import build as B
from . import pidsmaker as PM

MUST_BE_ZERO = ("edge_without_node", "obj_facts_conflict", "fid_two_objs")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="p15.graph", description=__doc__)
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("out", type=Path, help="the DuckDB file to write (must not exist)")
    ap.add_argument("--pidsmaker", type=Path, metavar="DIR", help="also write PIDSMaker's four tables as CSV into DIR")
    a = ap.parse_args(argv)
    try:
        res = B.build(a.run_dir, a.out)
    except (W.RunError, W.HeaderError, R.RecordError, OSError) as e:     # OSError: unreadable, missing, or OUT exists
        print(f"p15.graph: {e}", file=sys.stderr)
        return 2
    print(f"graph: {a.out}")
    print("records: " + ", ".join(f"{k} {v}" for k, v in res.raw_rows.items() if v))
    for k in sorted(res.counts):
        print(f"  {k:<28} {res.counts[k]}")
    print("tree: " + ", ".join(f"{k} {v}" for k, v in sorted(res.tree_counts.items()) if v))
    for s in res.stops:
        print(f"stop: {s}")
    bad = [k for k in MUST_BE_ZERO if res.counts.get(k, 0)]
    if res.raw_rows["record_error"]:
        bad.append("record_error")
    if a.pidsmaker:
        m = PM.export(a.out, a.pidsmaker)
        print(f"pidsmaker: {a.pidsmaker}: " + ", ".join(f"{k} {v}" for k, v in m["rows"].items()))
        print("  exported: " + ", ".join(f"{k} {v}" for k, v in m["events_exported"].items()))
        print("  not exported: " + (", ".join(f"{k}: {v}" for k, v in m["edges_not_exported"].items() if v) or "none"))
        print(f"  timed by the first clock anchor: {m['events_timed_by_the_first_anchor']}")
    if bad:
        print("INVALID: " + ", ".join(bad) + " must be 0", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
