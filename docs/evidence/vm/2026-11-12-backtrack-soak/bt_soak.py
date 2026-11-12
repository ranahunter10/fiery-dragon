import sys, time, duckdb
con = duckdb.connect(sys.argv[1], read_only=True)
print("duckdb", duckdb.__version__)
print("edges", con.execute("SELECT count(*) FROM edge").fetchone()[0], "nodes", con.execute("SELECT count(*) FROM node").fetchone()[0])
poi, t = con.execute("""SELECT e.dst, e.ts_ns FROM edge e JOIN node n ON n.node_id = e.dst
                    WHERE n.kind = 'proc' ORDER BY e.ts_ns DESC LIMIT 1""").fetchone()
q = """WITH RECURSIVE bt(node, thr) USING KEY (node) AS (
    SELECT ?::BIGINT, ?::BIGINT
    UNION
    SELECT e.src, max(least(bt.thr, e.ts_ns))
    FROM bt JOIN edge e ON e.dst = bt.node AND e.ts_ns < bt.thr
    LEFT JOIN recurring.bt r ON r.node = e.src
    WHERE r.thr IS NULL OR least(bt.thr, e.ts_ns) > r.thr
    GROUP BY e.src)
SELECT n.kind, count(*) FROM bt JOIN node n ON n.node_id = bt.node GROUP BY n.kind ORDER BY n.kind"""
for i in range(3):
    t0 = time.perf_counter(); r = con.execute(q, [poi, t + 1]).fetchall(); dt = time.perf_counter() - t0
    print(f"round {i}: {dt:.3f} s, reached {r}")
