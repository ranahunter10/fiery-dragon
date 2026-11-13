# SPDX-License-Identifier: MIT
"""Backward and forward tracking on a graph file (BackTracker's rule, King and Chen SOSP'03, R-046).

    python3 -m p15.graph.track GRAPH.duckdb --back NODE [--before NS] [--top N]
    python3 -m p15.graph.track GRAPH.duckdb --forward NODE [--after NS] [--top N]

NODE is a node_id or a node key (`p:TGID:START_NS`, a file key, `s:COOKIE`).

An edge covers a time interval [t0, t1]: one moment for an event (t0 = t1 = its time), the start
of the first transfer to the end of the last for a FLOW (`edge.ts_ns`, `edge.end_ns`; ADR-0005 rule 8).

**Backward** from (node, t): which nodes could have affected node before t. Each reached node gets
a threshold, the latest time at which it could still have passed something on (BackTracker §2.3):
    thr(start) = t;  an edge u -> v over [t0, t1] with t0 < thr(v) reaches u with min(thr(v), t1);
    u keeps the largest threshold any path gives it.
**Forward** from (node, t), the mirror: which nodes node could have affected from t on, each with
the earliest time it could have been affected:
    thr(start) = t;  an edge u -> v over [t0, t1] with t1 > thr(u) reaches v with max(thr(u), t0);
    v keeps the smallest.
A transfer still running when its other end is read or written counts as a dependency: the walk
never assumes an order inside an interval.

Both are one recursive query, `WITH RECURSIVE ... USING KEY (node)` (DuckDB 2.0, R-045): the keyed
table holds each node's best threshold so far, and an iteration passes on only the nodes whose
threshold improved, so the work is bounded by the improvements, never by the number of paths.

What a step may follow (`track_edge`, built once per connection as a temporary table):
- every edge that happened (`edge.ok`), at its time: ADR-0028 rule 6's direction is the way
  information can flow;
- a process that started before the capture, from the parent the opening snapshot names, at the
  process's start time (its fork, which the run does not hold as a CLONE edge);
- the two sockets of one TCP connection on this host (`sock_pair`, ADR-0022), client -> server, and
  an overlay file and its real file (`file_backing`, ADR-0015 rule 4), both ways. These are relations,
  not events: they have no time (NULL), so a step across one keeps the threshold it had.
Edges that did not happen (a denied open, a refused connect) are never followed.

Limits:
- a run captured without the flow programs (before step 2b, or `--flow` off) holds open-level edges
  only, file -> process whatever the access (ADR-0028): a backward walk then stops at every file it
  reaches, and a forward walk never leaves a process through a write;
- a transfer on a socket points at the socket's file object, which is not yet the socket node of
  the NET records (`graph_count.flow_sock_not_joined`): until NET carries the object id (step 2e) a
  walk does not pass from a SEND or RECV to the connection's other end.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import duckdb

TRACK_EDGE = """
CREATE TEMP TABLE IF NOT EXISTS track_edge AS
SELECT src, dst, ts_ns::BIGINT AS t0, end_ns::BIGINT AS t1, op FROM edge WHERE ok
UNION ALL SELECT parent_node, node_id, start_ns::BIGINT, start_ns::BIGINT, 'CLONE_BEFORE' FROM proc
          WHERE fork_ns IS NULL AND parent_node IS NOT NULL
UNION ALL SELECT client_node, server_node, NULL, NULL, 'PAIR' FROM sock_pair
UNION ALL SELECT real_node, user_node, NULL, NULL, 'BACKING' FROM file_backing
UNION ALL SELECT user_node, real_node, NULL, NULL, 'BACKING' FROM file_backing
"""

# a relation (t0 NULL) keeps the threshold; an edge over [t0, t1] is followed when it began before
# the threshold and narrows it to its end, if that is earlier
BACK = """
WITH RECURSIVE bt(node, thr) USING KEY (node) AS (
    SELECT ?::BIGINT, ?::BIGINT
    UNION
    SELECT e.src, max(CASE WHEN e.t0 IS NULL THEN bt.thr ELSE least(bt.thr, e.t1) END)
    FROM bt JOIN track_edge e ON e.dst = bt.node AND (e.t0 IS NULL OR e.t0 < bt.thr)
    LEFT JOIN recurring.bt r ON r.node = e.src
    WHERE r.thr IS NULL OR (CASE WHEN e.t0 IS NULL THEN bt.thr ELSE least(bt.thr, e.t1) END) > r.thr
    GROUP BY e.src
)
SELECT node, thr FROM bt ORDER BY node
"""

FORWARD = """
WITH RECURSIVE ft(node, thr) USING KEY (node) AS (
    SELECT ?::BIGINT, ?::BIGINT
    UNION
    SELECT e.dst, min(CASE WHEN e.t0 IS NULL THEN ft.thr ELSE greatest(ft.thr, e.t0) END)
    FROM ft JOIN track_edge e ON e.src = ft.node AND (e.t0 IS NULL OR e.t1 > ft.thr)
    LEFT JOIN recurring.ft r ON r.node = e.dst
    WHERE r.thr IS NULL OR (CASE WHEN e.t0 IS NULL THEN ft.thr ELSE greatest(ft.thr, e.t0) END) < r.thr
    GROUP BY e.dst
)
SELECT node, thr FROM ft ORDER BY node
"""


def prepare(con: duckdb.DuckDBPyConnection) -> None:
    """Build `track_edge` for this connection (a temporary table: the graph file is not changed)."""
    con.execute(TRACK_EDGE)


def backward(con: duckdb.DuckDBPyConnection, node: int, before_ns: int) -> dict[int, int]:
    """{node: threshold} of every node that could have affected `node` before `before_ns`, `node`
    itself included (with `before_ns`)."""
    prepare(con)
    return dict(con.execute(BACK, [node, before_ns]).fetchall())


def forward(con: duckdb.DuckDBPyConnection, node: int, after_ns: int) -> dict[int, int]:
    """{node: threshold} of every node `node` could have affected after `after_ns`, `node` itself
    included (with `after_ns`)."""
    prepare(con)
    return dict(con.execute(FORWARD, [node, after_ns]).fetchall())


def span(con: duckdb.DuckDBPyConnection) -> tuple[int | None, int | None]:
    """The start of the graph's first edge and the end of its last (a transfer ends after it starts)."""
    return con.execute("SELECT min(ts_ns), max(end_ns) FROM edge").fetchone()


def resolve(con: duckdb.DuckDBPyConnection, spec: str) -> int:
    """A node_id from a node_id or a node key; ValueError if there is no such node."""
    row = con.execute("SELECT node_id FROM node WHERE key = ? OR CAST(node_id AS VARCHAR) = ?", [spec, spec]).fetchone()
    if row is None:
        raise ValueError(f"no node {spec!r} (a node_id or a key such as p:TGID:START_NS)")
    return row[0]


def describe(con: duckdb.DuckDBPyConnection, nodes: list[int]) -> dict[int, str]:
    """A one-line label per node: a process's tgid and comm, a file's path or key, a socket's endpoints."""
    if not nodes:
        return {}
    rows = con.execute("""
        SELECT a.node_id, CASE n.kind
            WHEN 'proc' THEN 'proc ' || p.tgid || ' ' || coalesce(p.comm, '?') || coalesce(' (' || p.cmd || ')', '')
            WHEN 'file' THEN 'file ' || coalesce(f.path, f.kind || ' ' || nullif(f.name, '') || ' ' || f.key, f.key)
            ELSE 'sock ' || coalesce(s.laddr || ':' || s.lport || ' -> ' || s.raddr || ':' || s.rport, n.key) END
        FROM unnest(?::BIGINT[]) a(node_id) JOIN node n USING (node_id) LEFT JOIN proc p USING (node_id)
        LEFT JOIN file f USING (node_id) LEFT JOIN sock s USING (node_id)""", [nodes]).fetchall()
    return dict(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="p15.graph.track", description=__doc__.split("\n\n")[0])
    ap.add_argument("graph", type=Path)
    d = ap.add_mutually_exclusive_group(required=True)
    d.add_argument("--back", metavar="NODE")
    d.add_argument("--forward", metavar="NODE")
    ap.add_argument("--before", type=int, metavar="NS", help="backward: the time (boottime ns); default: after the last edge")
    ap.add_argument("--after", type=int, metavar="NS", help="forward: the time (boottime ns); default: before the first edge")
    ap.add_argument("--top", type=int, default=20, help="how many reached nodes to list (all are counted)")
    a = ap.parse_args(argv)
    if not a.graph.exists():
        print(f"p15.graph.track: {a.graph}: no such file", file=sys.stderr)
        return 2
    con = duckdb.connect(str(a.graph), read_only=True)
    try:
        lo, hi = span(con)
        try:
            start = resolve(con, a.back or a.forward)
        except ValueError as e:
            print(f"p15.graph.track: {e}", file=sys.stderr)
            return 2
        if a.back:
            t = a.before if a.before is not None else (hi or 0) + 1
            got = backward(con, start, t)
            order = sorted(got, key=lambda n: (-got[n], n))
        else:
            t = a.after if a.after is not None else max((lo or 1) - 1, 0)
            got = forward(con, start, t)
            order = sorted(got, key=lambda n: (got[n], n))
        kinds = dict(con.execute("SELECT node_id, kind FROM node").fetchall())
        by_kind: dict[str, int] = {}
        for n in got:
            by_kind[kinds[n]] = by_kind.get(kinds[n], 0) + 1
        print(f"{'backward' if a.back else 'forward'} from node {start} at {t}: {len(got)} nodes, "
              + ", ".join(f"{k} {v}" for k, v in sorted(by_kind.items())))
        labels = describe(con, order[:a.top])
        for n in order[:a.top]:
            print(f"  {got[n]:>20}  {n:>9}  {labels.get(n, '?')}")
        if len(order) > a.top:
            print(f"  ... {len(order) - a.top} more (--top)")
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
