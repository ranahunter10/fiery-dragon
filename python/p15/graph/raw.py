# SPDX-License-Identifier: MIT
"""Raw record tables: every record of a run, one DuckDB table per record type.

The tables (`schema/generated/p15_records.sql`) and the column list this loader fills
(`SQL_COLUMNS` of the generated layouts) come from one generator function, so this module names no
field (ADR-0019 G1, the Python -> DuckDB boundary). Nothing is interpreted here: a column holds the
record's field as decoded; a column that the row's version does not have is NULL.

A record that fails its check is not loaded: it goes to `record_error` (ring, seq, why), and the
count is in the load's result. There is no other way for a record to be left out.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from .. import records as R

DDL = Path(__file__).resolve().parents[3] / "schema" / "generated" / "p15_records.sql"
NP_TYPES = {"UTINYINT": "<u1", "USMALLINT": "<u2", "UINTEGER": "<u4", "UBIGINT": "<u8", "INTEGER": "<i4",
            "BIGINT": "<i8"}
HEADER_COLUMNS = ("version", "flags", "ts_ns", "tgid", "tid", "start_ns")
FLUSH_ROWS = 50_000

EXTRA_DDL = """
CREATE TABLE run_meta (seg UINTEGER, key VARCHAR, value VARCHAR);   -- every segment header's metadata
CREATE TABLE record_error (ring UTINYINT, seq UBIGINT, why VARCHAR);  -- records that failed their check
"""


def row(r: R.Record) -> dict:
    """One record as {column: value} for its raw table. Every key is a column of SQL_COLUMNS for
    the record's name (a test checks it for every type and version)."""
    out = {"ring": r.ring, "seq": r.seq}
    for k in HEADER_COLUMNS:
        out[k] = r.h[k]
    for k, v in r.f.items():
        out[k] = v
    for k, v in r.var.items():
        if isinstance(v, dict):
            for pk, pv in v.items():
                out[f"{k}_{pk}"] = pv
        elif v is not None:           # an absent part is None: its columns stay NULL
            out[k] = v
    return out


class Loader:
    """Buffers rows per table and appends them as numpy columns (DuckDB scans a dict of arrays)."""

    def __init__(self, con):
        self.con = con
        self.buf: dict[str, list[dict]] = {n: [] for n in R.gen.SQL_COLUMNS}
        self.rows: dict[str, int] = dict.fromkeys(R.gen.SQL_COLUMNS, 0)

    def add(self, r: R.Record) -> None:
        b = self.buf[r.name]
        b.append(row(r))
        if len(b) >= FLUSH_ROWS:
            self.flush(r.name)

    def flush(self, name: str) -> None:
        rows = self.buf[name]
        if not rows:
            return
        cols = R.gen.SQL_COLUMNS[name]
        known = {c for c, _ in cols}
        for rw in rows:
            extra = rw.keys() - known
            if extra:
                raise KeyError(f"{name}: no raw column for {sorted(extra)}")
        data, select = {}, []
        for c, t in cols:
            vals = [rw.get(c) for rw in rows]
            if t == "BLOB":
                data[c] = np.array(vals + [None], dtype=object)[:-1]   # never a 2-D array of equal-length bytes
            else:
                mask = [v is None for v in vals]
                data[c] = np.ma.masked_array(np.array([0 if v is None else v for v in vals], dtype=NP_TYPES[t]),
                                             mask=mask)
            select.append(f"{c}::{t} AS {c}")
        self.con.register("p15_raw_chunk", data)
        try:
            self.con.execute(f"INSERT INTO raw_{name.lower()} BY NAME SELECT {', '.join(select)} FROM p15_raw_chunk")
        finally:
            self.con.unregister("p15_raw_chunk")
        self.rows[name] += len(rows)
        rows.clear()

    def finish(self) -> dict[str, int]:
        for n in self.buf:
            self.flush(n)
        return self.rows


def create(con) -> None:
    con.execute(DDL.read_text())
    con.execute(EXTRA_DDL)


def load(con, run, rings: dict[int, list[R.Record]], errors: list) -> dict[str, int]:
    """Create the raw tables in `con` and fill them from a run's decoded records (`rings`: ring
    number -> records) and its record errors [(ring, seq, RecordError)]. Returns rows per record
    name, plus 'record_error'."""
    create(con)
    ld = Loader(con)
    for ring in sorted(rings):
        for r in rings[ring]:
            ld.add(r)
    counts = ld.finish()
    if errors:
        con.executemany("INSERT INTO record_error VALUES (?, ?, ?)", [(g, s, e.why) for g, s, e in errors])
    meta = [(i, k, v) for i, seg in enumerate(run.segments) for k, v in seg.meta.items()]
    con.executemany("INSERT INTO run_meta VALUES (?, ?, ?)", meta)
    counts["record_error"] = len(errors)
    return counts
