# SPDX-License-Identifier: MIT
"""BackTracker's time-threshold rule (King and Chen, SOSP'03, sec. 2.3) as a DuckDB USING KEY fixpoint:
a hand-made graph with the answer known, then a random graph for scale. Research note 2026-11-12."""
import time

import duckdb

QUERY = """
WITH RECURSIVE bt(node, thr) USING KEY (node) AS (
    SELECT {poi}, {t}::BIGINT
    UNION
    SELECT e.src, max(least(bt.thr, e.t1))
    FROM bt JOIN edge e ON e.dst = bt.node AND e.t0 < bt.thr
    LEFT JOIN recurring.bt r ON r.node = e.src
    WHERE r.thr IS NULL OR least(bt.thr, e.t1) > r.thr
    GROUP BY e.src
)
SELECT node, thr FROM bt ORDER BY thr DESC, node"""

print("duckdb", duckdb.__version__)
c = duckdb.connect()
c.execute("CREATE TABLE edge(src VARCHAR, dst VARCHAR, t0 BIGINT, t1 BIGINT)")
c.execute("""INSERT INTO edge VALUES
 ('net','P1',10,11), ('P1','X',20,21), ('X','P2',30,31), ('P2','F',40,41),
 ('Y','P2',50,51),   -- after P2's write to F ends (41): must be excluded
 ('P3','X',35,36),   -- X written after P2 read it (31): must be excluded
 ('Z','P1',15,16),   -- before P1 wrote X (21): included
 ('F','P2',60,61)    -- a cycle back, later: must not matter""")
got = c.execute(QUERY.format(poi="'F'", t=100)).fetchall()
want = [("F", 100), ("P2", 41), ("X", 31), ("P1", 21), ("Z", 16), ("net", 11)]
print("hand-made:", got, "EQUAL" if got == want else "DIFFERENT")

c = duckdb.connect()
N, E = 150_000, 900_000
c.execute("SELECT setseed(0.15)")
c.execute(f"""CREATE TABLE edge AS
  SELECT (random()*{N})::INT AS src, (random()*{N})::INT AS dst, t0, t0 + 1 AS t1
  FROM (SELECT (random()*3.6e12)::BIGINT AS t0 FROM range({E})) ORDER BY t0""")
for k in range(3):
    t = time.monotonic()
    r = c.execute(f"SELECT count(*), min(thr), max(thr) FROM ({QUERY.format(poi=0, t=3600000000000)})").fetchone()
    print(f"random {N} nodes {E} edges, round {k}: {time.monotonic() - t:.3f} s, nodes reached {r[0]}")

# Hubs, as shells and shared libraries are: half the edges start or end at 1 % of the nodes.
c = duckdb.connect()
c.execute("SELECT setseed(0.15)")
H = N // 100
c.execute(f"""CREATE TABLE edge AS
  SELECT CASE WHEN random() < 0.5 THEN (random()*{H})::INT ELSE (random()*{N})::INT END AS src,
         CASE WHEN random() < 0.5 THEN (random()*{H})::INT ELSE (random()*{N})::INT END AS dst,
         t0, t0 + 1 AS t1
  FROM (SELECT (random()*3.6e12)::BIGINT AS t0 FROM range({E})) ORDER BY t0""")
for k in range(3):
    t = time.monotonic()
    r = c.execute(f"SELECT count(*), min(thr), max(thr) FROM ({QUERY.format(poi=0, t=3600000000000)})").fetchone()
    print(f"hubs {H} of {N} nodes, {E} edges, round {k}: {time.monotonic() - t:.3f} s, nodes reached {r[0]}")
