# SPDX-License-Identifier: MIT
"""Rules over the graph for known fileless patterns: the first detection tier (Phase II report
§1.10.7). They need no training and fire when the graph is read.

    python3 -m p15.graph.rules GRAPH.duckdb [--json]

The four rules, each one query over the built graph (python/p15/graph/graph.sql):

  R1 dropper     a file written by one process and later executed by another. The writer is a WRITE
                 edge (the flow programs, --flow) or an OPEN for writing (open-level capture).
  R2 memfd-exec  a process image whose code lives only in memory: a memfd, or an unlinked file on
                 tmpfs (EXEC's exe_nlink and exe_fs_magic; ADR-0025, p15.provenance.backing).
  R3 deleted-exec a process image whose file was unlinked when it ran, on a disk filesystem.
  R4 net-shell   a shell started by a process that took input from the network before it: the
                 parent accepted a connection or received from a socket (ACCEPT, RECV, or a READ
                 of a socket) earlier than the child's fork. The alert names the parent's last such
                 input before the fork: the request that led to the shell.

What they are and are not. They are patterns, not verdicts: a compiler's output run by `make` is R1,
and an ssh daemon's login shell is R4. Each alert names the node to start an investigation from
(p15.graph.story). A rule cannot see what capture did not record: R1 needs the write (with --flow,
or an OPEN for writing), R4 needs the network records (network capture on).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import duckdb

SHELLS = r"(^|/)(sh|bash|dash|zsh|ksh|ash|mksh|busybox)$"

# Each query returns: ts_ns, the node to start from (its node_id), and a one-line detail.
RULES = {
    "R1": ("dropper", "a file written by one process and executed by another", """
        WITH writes AS (
            SELECT e.dst AS file, e.src AS proc, e.ts_ns FROM edge e WHERE e.op = 'WRITE' AND e.ok
            UNION ALL
            SELECT e.src, e.dst, e.ts_ns FROM edge e WHERE e.op = 'OPEN' AND e.ok AND e.access IN ('w', 'rw')
        ), runs AS (
            SELECT e.src AS file, e.dst AS proc, e.ts_ns FROM edge e WHERE e.op = 'EXECUTE' AND e.ok
        )
        SELECT x.ts_ns, x.proc AS node,
               'wrote ' || coalesce(f.path, f.name, f.key) || ' (pid ' || pw.tgid || ' ' || coalesce(pw.comm, '?')
               || '), ran it as pid ' || pr.tgid AS detail
        FROM runs x
        JOIN writes w ON w.file = x.file AND w.proc <> x.proc AND w.ts_ns <= x.ts_ns
        JOIN file f ON f.node_id = x.file
        JOIN proc pw ON pw.node_id = w.proc
        JOIN proc pr ON pr.node_id = x.proc
        QUALIFY row_number() OVER (PARTITION BY x.proc, x.file ORDER BY w.ts_ns DESC) = 1"""),
    "R2": ("memfd-exec", "code that ran from memory only (a memfd, or an unlinked tmpfs file)", """
        SELECT i.ts_ns, i.node_id AS node,
               'pid ' || p.tgid || ' ran ' || coalesce(i.filename, '?') || coalesce(' as ' || i.cmd, '') AS detail
        FROM proc_image i JOIN proc p USING (node_id)
        WHERE i.backing = 'memory' AND i.seen_in = 'exec'"""),
    "R3": ("deleted-exec", "a program whose file was deleted when it ran", """
        SELECT i.ts_ns, i.node_id AS node,
               'pid ' || p.tgid || ' ran ' || coalesce(i.filename, '?') || coalesce(' as ' || i.cmd, '') AS detail
        FROM proc_image i JOIN proc p USING (node_id)
        WHERE i.backing = 'deleted' AND i.seen_in = 'exec'"""),
    "R4": ("net-shell", "a shell started by a process that took input from the network", f"""
        WITH shells AS (
            SELECT c.node_id, c.tgid, c.parent_node, c.fork_ns, min(i.ts_ns) AS exec_ns, any_value(i.filename) AS prog
            FROM proc c JOIN proc_image i ON i.node_id = c.node_id AND i.seen_in = 'exec'
            WHERE regexp_matches(coalesce(i.filename, ''), '{SHELLS}')
            GROUP BY c.node_id, c.tgid, c.parent_node, c.fork_ns
        ), cand AS (                -- the parent's last network input before this shell was forked
            SELECT s.*, e.src AS sock
            FROM shells s
            JOIN edge e ON e.dst = s.parent_node AND e.ok AND e.op IN ('ACCEPT', 'RECV', 'READ')
                       AND e.ts_ns < coalesce(s.fork_ns, s.exec_ns)
            JOIN node n ON n.node_id = e.src AND n.kind = 'sock'
            QUALIFY row_number() OVER (PARTITION BY s.node_id ORDER BY e.ts_ns DESC, e.edge_id DESC) = 1
        )
        SELECT c.exec_ns AS ts_ns, c.node_id AS node,
               'pid ' || p.tgid || ' ' || coalesce(p.comm, '?') || ' (network input from '
               || coalesce(k.laddr || ':' || k.lport || ' <- ' || k.raddr || ':' || k.rport, 'a socket')
               || ') started ' || c.prog || ' as pid ' || c.tgid AS detail
        FROM cand c JOIN proc p ON p.node_id = c.parent_node LEFT JOIN sock k ON k.node_id = c.sock"""),
}


@dataclass
class Alert:
    rule: str
    name: str
    ts_ns: int
    node: int
    key: str
    detail: str


def run(con: duckdb.DuckDBPyConnection) -> list[Alert]:
    """Every rule's alerts, in time order."""
    keys = dict(con.execute("SELECT node_id, key FROM node").fetchall())
    out = []
    for rid, (name, _what, sql) in RULES.items():
        for ts, node, detail in con.execute(sql).fetchall():
            out.append(Alert(rid, name, int(ts or 0), int(node), keys.get(node, "?"), detail))
    out.sort(key=lambda a: (a.ts_ns, a.rule, a.node))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="p15.graph.rules", description=__doc__.split("\n\n")[0])
    ap.add_argument("graph", type=Path)
    ap.add_argument("--json", action="store_true", help="one JSON object per alert")
    a = ap.parse_args(argv)
    if not a.graph.exists():
        print(f"p15.graph.rules: {a.graph}: no such file", file=sys.stderr)
        return 2
    con = duckdb.connect(str(a.graph), read_only=True)
    try:
        alerts = run(con)
        t0 = con.execute("SELECT min(ts_ns) FROM edge").fetchone()[0] or 0
    finally:
        con.close()
    if a.json:
        for x in alerts:
            print(json.dumps(asdict(x)))
        return 0
    counts = {rid: sum(1 for x in alerts if x.rule == rid) for rid in RULES}
    print("rules: " + ", ".join(f"{rid} {RULES[rid][0]} {n}" for rid, n in counts.items()))
    for x in alerts:
        print(f"  +{(x.ts_ns - t0) / 1e9:8.3f}s  {x.rule} {x.name:<12} {x.key}  {x.detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
