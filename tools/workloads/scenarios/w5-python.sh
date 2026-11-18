#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# trace: full
# Python: an SQLite database of 20,000 rows written in one transaction and queried, its result
# dumped as JSON; then the repo's python package byte-compiled in a copy.
set -eu
W=$1
python3 - "$W" <<'PY'
import json, sqlite3, sys
w = sys.argv[1]
con = sqlite3.connect(f"{w}/db.sqlite")
con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, k TEXT, v REAL)")
with con:
    con.executemany("INSERT INTO t (k, v) VALUES (?, ?)", ((f"k{i % 97}", i * 0.5) for i in range(20000)))
rows = con.execute("SELECT k, count(*), sum(v) FROM t GROUP BY k ORDER BY k").fetchall()
json.dump(rows, open(f"{w}/agg.json", "w"))
print(len(rows), "groups")
PY
cp -r "$P15_REPO/python" "$W/py"
python3 -m compileall -q "$W/py" >/dev/null
find "$W/py" -name '*.pyc' | wc -l
