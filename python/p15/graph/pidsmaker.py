# SPDX-License-Identifier: MIT
"""Export a graph file to the tables PIDSMaker reads (ADR-0028 rule 7).

PIDSMaker (ubc-provenance/PIDSMaker, Apache-2.0; read at commit 15e5515, nothing copied) builds
its graphs from four PostgreSQL tables: subject_node_table, file_node_table, netflow_node_table
and event_table (its postgres/init-create-databases.sh). This writes one CSV per table, with the
columns in that script's order, a psql script that loads them, and a manifest of what was and was
not exported. Nothing of PIDSMaker runs here.

What the export keeps to:
  - an event runs from the source of information to its destination, as PIDSMaker stores its own
    (its edge_reversed list: EXECUTE, OPEN and ACCEPT run object -> subject);
  - only operations the kernel let happen (`edge.ok`); the others are counted in the manifest;
  - only operations the capture observed: EVENT_CLONE, EVENT_EXECUTE, EVENT_OPEN, EVENT_CONNECT,
    EVENT_ACCEPT. An open is exported as EVENT_OPEN whatever access it asked for: capture does not
    measure reads and writes until step 2b, so no EVENT_READ or EVENT_WRITE is made up from an
    access mode;
  - timestamp_rec is wall-clock ns (PIDSMaker cuts its windows by calendar time), from the
    nearest earlier clock anchor; an event stamped before the first anchor (the hooks attach
    before the first segment header is written) uses the first one: an anchor is an offset
    between two clocks, and it holds a few milliseconds earlier as well;
  - hash_id is sha256 of node_uuid, as PIDSMaker's own loaders compute it; index_id is node_id.
"""

from __future__ import annotations

import json
from pathlib import Path

import duckdb

OPS = {"CLONE": "EVENT_CLONE", "EXECUTE": "EVENT_EXECUTE", "OPEN": "EVENT_OPEN", "CONNECT": "EVENT_CONNECT",
       "ACCEPT": "EVENT_ACCEPT"}
FLOW_WAITS = "a transfer: not exported until the export's rule for FLOW is decided"
NOT_EXPORTED = {"HELD": "a descriptor already open at a snapshot: a state, not an event",
                "LISTEN": "no flow", "BIND": "no flow",
                "READ": FLOW_WAITS, "WRITE": FLOW_WAITS, "RECV": FLOW_WAITS, "SEND": FLOW_WAITS}
NULL = "null"      # PIDSMaker's loaders write the string 'null' for an attribute they do not have

QUERIES = {
    "subject_node_table": f"""
        SELECT u.uuid AS node_uuid, sha256(u.uuid) AS hash_id, coalesce(p.exe_path, '{NULL}') AS path,
               coalesce(p.cmd, p.comm, '{NULL}') AS cmd, p.node_id AS index_id
        FROM proc p JOIN uuid u USING (node_id) ORDER BY p.node_id""",
    "file_node_table": f"""
        SELECT u.uuid AS node_uuid, sha256(u.uuid) AS hash_id, coalesce(f.path, '{NULL}') AS path, f.node_id AS index_id
        FROM file f JOIN uuid u USING (node_id) ORDER BY f.node_id""",
    "netflow_node_table": """
        SELECT u.uuid AS node_uuid, sha256(u.uuid) AS hash_id, s.laddr AS src_addr, s.lport::VARCHAR AS src_port,
               s.raddr AS dst_addr, s.rport::VARCHAR AS dst_port, s.node_id AS index_id
        FROM sock s JOIN uuid u USING (node_id) ORDER BY s.node_id""",
    "event_table": """
        SELECT sha256(su.uuid) AS src_node, e.src::VARCHAR AS src_index_id, o.name AS operation,
               sha256(du.uuid) AS dst_node, e.dst::VARCHAR AS dst_index_id,
               (SELECT run FROM run_id) || ':' || e.ring || ':' || e.seq || ':' || e.op AS event_uuid,
               w.wall_ns AS timestamp_rec
        FROM edge e JOIN ops o ON o.op = e.op JOIN uuid su ON su.node_id = e.src JOIN uuid du ON du.node_id = e.dst
        JOIN wall w ON w.edge_id = e.edge_id
        WHERE e.ok ORDER BY e.edge_id""",
}
# every edge's wall time: the nearest earlier anchor, or the first anchor for an edge before it
WALL = """
CREATE TEMP TABLE wall AS
SELECT e.edge_id, (coalesce(c.realtime_ns, f.realtime_ns)::BIGINT
                   + (e.ts_ns::BIGINT - coalesce(c.boottime_ns, f.boottime_ns)::BIGINT))::BIGINT AS wall_ns
FROM edge e ASOF LEFT JOIN clock c ON e.ts_ns >= c.boottime_ns
CROSS JOIN (SELECT boottime_ns, realtime_ns FROM clock ORDER BY boottime_ns LIMIT 1) f"""
COLUMNS = {"subject_node_table": 5, "file_node_table": 4, "netflow_node_table": 7, "event_table": 7}


def export(graph: Path, out: Path) -> dict:
    """Write OUT/{table}.csv, OUT/load.sql and OUT/manifest.json from a graph file. Returns the manifest."""
    out.mkdir(parents=True, exist_ok=False)
    con = duckdb.connect(str(graph), read_only=True)
    try:
        meta = dict(con.execute("SELECT key, value FROM run_meta WHERE seg = 0").fetchall())
        con.execute("CREATE TEMP TABLE run_id AS SELECT ?::VARCHAR AS run", [meta["run.id"]])
        # a node's name outside this run: the boot, the run and the node's own key
        con.execute("CREATE TEMP TABLE uuid AS SELECT node_id, ? || '/' || ? || '/' || key AS uuid FROM node",
                    [meta["boot_id"], meta["run.id"]])
        con.execute("CREATE TEMP TABLE ops (op VARCHAR, name VARCHAR)")
        con.executemany("INSERT INTO ops VALUES (?, ?)", sorted(OPS.items()))
        con.execute(WALL)
        before_clock = con.execute(
            "SELECT count(*) FROM edge e WHERE e.ok AND e.ts_ns < (SELECT min(boottime_ns) FROM clock)").fetchone()[0]
        rows = {}
        for table, q in QUERIES.items():
            con.execute(f"COPY ({q}) TO '{(out / (table + '.csv')).as_posix()}' (FORMAT csv, HEADER false)")
            rows[table] = con.execute(f"SELECT count(*) FROM ({q})").fetchone()[0]
        exported = dict(con.execute(
            f"SELECT operation, count(*) FROM ({QUERIES['event_table']}) GROUP BY operation ORDER BY operation").fetchall())
        by_op = con.execute("SELECT op, ok, count(*) FROM edge GROUP BY op, ok ORDER BY op, ok").fetchall()
        span = con.execute("SELECT min(w.wall_ns), max(w.wall_ns) FROM edge e JOIN wall w USING (edge_id) "
                           "JOIN ops o ON o.op = e.op WHERE e.ok").fetchone()
    finally:
        con.close()
    manifest = {
        "run.id": meta["run.id"], "boot_id": meta["boot_id"], "schema.hash": meta["schema.hash"],
        "rows": rows,
        "events_exported": exported,      # counted from the rows written, not from the graph
        "edges_not_exported": {
            **{f"{op} (not allowed by the kernel)": n for op, ok, n in by_op if not ok},
            **{f"{op} ({NOT_EXPORTED[op]})": n for op, ok, n in by_op if ok and op in NOT_EXPORTED},
            },
        "events_timed_by_the_first_anchor": before_clock,     # stamped before it; exported
        "wall_ns": {"first": span[0], "last": span[1]},
        "absent_by_design": ["EVENT_READ", "EVENT_WRITE", "EVENT_SENDTO", "EVENT_SENDMSG", "EVENT_RECVFROM",
                             "EVENT_RECVMSG"],
        "absent_why": "capture step 2b (measured transfers) is not built yet; an access mode is not a transfer",
    }
    unknown = sorted({op for op, _, _ in by_op} - OPS.keys() - NOT_EXPORTED.keys())
    if unknown:
        raise ValueError(f"edge operations with no export rule: {unknown}")
    if sum(exported.values()) != sum(n for op, ok, n in by_op if ok and op in OPS):
        raise ValueError("the export's books do not close: every allowed edge with a rule must be an event written "
                         "(a run with no clock anchor has no wall time)")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    load = ["-- Load into a database whose four tables PIDSMaker's postgres/init-create-databases.sh created.",
            "-- psql -U postgres -d <dataset> -f load.sql   (run from this directory)"]
    for table, n in COLUMNS.items():
        cols = ", ".join(_columns(table))
        assert len(_columns(table)) == n
        load.append(f"\\copy {table} ({cols}) FROM '{table}.csv' WITH (FORMAT csv)")
    (out / "load.sql").write_text("\n".join(load) + "\n")
    return manifest


def _columns(table: str) -> list[str]:
    return {"subject_node_table": ["node_uuid", "hash_id", "path", "cmd", "index_id"],
            "file_node_table": ["node_uuid", "hash_id", "path", "index_id"],
            "netflow_node_table": ["node_uuid", "hash_id", "src_addr", "src_port", "dst_addr", "dst_port", "index_id"],
            "event_table": ["src_node", "src_index_id", "operation", "dst_node", "dst_index_id", "event_uuid",
                            "timestamp_rec"]}[table]
