# SPDX-License-Identifier: MIT
"""Graph v0 (ADR-0028): a run's WAL -> a DuckDB file with the raw record tables and the graph.

    python3 -m p15.graph RUN_DIR OUT.duckdb [--pidsmaker DIR]

Three steps, each its own module or file:
  raw.py     every record into its generated raw table (no interpretation);
  here       the process tree (p15/proctree.py, the one implementation of ADR-0009 and ADR-0023's
             inputs) into `proc_src`, and every process a non-spine record names into the tree;
  graph.sql  nodes, edges and the books, in SQL over those tables.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path

import duckdb

from .. import proctree as P
from .. import records as R
from .. import snapshot as S
from .. import wal as W
from . import raw

SQL = Path(__file__).with_name("graph.sql")

PROC_SRC_DDL = """
CREATE TABLE proc_src (
    tgid UINTEGER, start_ns UBIGINT, parent_tgid UINTEGER, parent_start_ns UBIGINT, first_ns UBIGINT,
    fork_ns UBIGINT, exit_ns UBIGINT, exit_code INTEGER, exe_path VARCHAR, cmd VARCHAR, comm VARCHAR,
    origin VARCHAR, kthread BOOLEAN, in_gap BOOLEAN, n_images UINTEGER);
CREATE TABLE tree_count (name VARCHAR, n BIGINT);
"""


def text(b: bytes) -> str:
    """Kernel bytes (a path, a comm) as text: UTF-8, anything else escaped, as the reader does."""
    return bytes(b).decode("utf-8", "backslashreplace")


def addr(raw_addr: bytes, family: int) -> str:
    """A NET record's 16 address bytes as text (records.net_addr's rule)."""
    if family == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, bytes(raw_addr)[:4])
    if family == socket.AF_INET6:
        return socket.inet_ntop(socket.AF_INET6, bytes(raw_addr))
    raise R.RecordError(f"NET family {family} is neither AF_INET nor AF_INET6", -1)


@dataclass
class Result:
    raw_rows: dict[str, int]
    counts: dict[str, int]          # graph_count
    tree_counts: dict[str, int]
    stops: list[str]                # how each segment that did not end cleanly stopped


def read(path: Path):
    """A run's records by ring, its record errors, and its process tree with every process that a
    bulk or snapshot record names (a placeholder where the spine holds nothing: counted)."""
    run = W.read_run(path)
    errors: list = []
    rings = {i: list(run.ring_records(i, errors)) for i in range(len(W.RINGS))}
    start = int(run.meta["clock.boottime_ns"]) if "clock.boottime_ns" in run.meta else None
    snaps = S.collect(rings[2])
    opening = next((s for s in snaps if s.kind == "opening"), None)
    tree = P.build(rings[0] + [r for r in rings[2] if r.name == "GAP"], start, opening)
    first: dict[P.Key, int] = {}
    for ring in (0, 1, 2):
        for r in rings[ring]:
            keys = [r.proc] if ring < 2 or r.name in ("PROC", "FD") else []
            if r.name == "FORK" and r.f["kind"] == 1:
                keys.append((r.f["child_tgid"], r.f["child_start_ns"]))
            for k in keys:
                tree.get(k)
                if k not in first or r.h["ts_ns"] < first[k]:
                    first[k] = r.h["ts_ns"]
    return run, rings, errors, tree, first


def proc_rows(tree: P.Tree, first: dict[P.Key, int]) -> list[tuple]:
    out = []
    for k in sorted(tree.procs):
        p = tree.procs[k]
        im = p.images[-1] if p.images else None
        par = p.parent or (None, None)
        seen = [t for t in (first.get(k), p.fork_ns) if t is not None]
        out.append((k[0], k[1], par[0], par[1], min(seen) if seen else k[1], p.fork_ns, p.exit_ns, p.exit_code,
                    im.filename if im else None, " ".join(im.argv) if im and im.argv else None, p.comm,
                    p.origin or "forked in the run", p.kthread, p.in_gap,   # the tree names every other origin
                    len(p.images)))
    return out


def build(run_dir: Path, out: Path) -> Result:
    """Build OUT.duckdb from RUN_DIR. Refuses to overwrite: a graph file is evidence of one run."""
    if out.exists():
        raise FileExistsError(f"{out} exists: a graph file is written once")
    run, rings, errors, tree, first = read(run_dir)
    con = duckdb.connect(str(out))
    done = False
    try:
        con.create_function("p15_text", text, ["BLOB"], "VARCHAR")
        con.create_function("p15_addr", addr, ["BLOB", "USMALLINT"], "VARCHAR")
        raw_rows = raw.load(con, run, rings, errors)
        con.execute(PROC_SRC_DDL)
        rows = proc_rows(tree, first)
        if rows:
            con.executemany("INSERT INTO proc_src VALUES (" + ", ".join("?" * 15) + ")", rows)
        con.executemany("INSERT INTO tree_count VALUES (?, ?)", sorted(tree.counts.items()))
        con.execute(SQL.read_text())
        counts = dict(con.execute("SELECT name, n FROM graph_count").fetchall())
        done = True
    finally:
        con.close()
        if not done:
            out.unlink(missing_ok=True)     # never leave half a graph behind
    return Result(raw_rows, counts, dict(tree.counts), [f"{s.path.name}: {st.describe()}" for s, st in run.stops])
