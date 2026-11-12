import sys, time, duckdb
con = duckdb.connect(sys.argv[1], read_only=True)
one = lambda q, p=(): con.execute(q, list(p)).fetchone()
all_ = lambda q, p=(): con.execute(q, list(p)).fetchall()
Q = """WITH RECURSIVE bt(node, thr) USING KEY (node) AS (
    SELECT ?::BIGINT, ?::BIGINT
    UNION
    SELECT e.src, max(least(bt.thr, e.ts_ns))
    FROM bt JOIN edge e ON e.dst = bt.node AND e.ts_ns < bt.thr
    LEFT JOIN recurring.bt r ON r.node = e.src
    WHERE r.thr IS NULL OR least(bt.thr, e.ts_ns) > r.thr
    GROUP BY e.src)
SELECT n.kind, count(*) FROM bt JOIN node n ON n.node_id = bt.node GROUP BY n.kind ORDER BY n.kind"""
print("duckdb", duckdb.__version__)
print("edges into nodes, by node kind and op:")
for r in all_("SELECT n.kind, e.op, count(*) FROM edge e JOIN node n ON n.node_id = e.dst GROUP BY ALL ORDER BY ALL"):
    print("  ", r)
poi, t = one("""SELECT e.dst, e.ts_ns FROM edge e JOIN node n ON n.node_id = e.dst
                WHERE n.kind = 'proc' ORDER BY e.ts_ns DESC LIMIT 1""")
print("run 1's start:", one("SELECT tgid, comm, origin, parent_node, fork_ns FROM proc WHERE node_id = ?", [poi]))
print("  its in-edges by op:", all_("SELECT op, count(*) FROM edge WHERE dst = ? GROUP BY op ORDER BY op", [poi]))
# a process the soak started: the last one with a CLONE edge in and an EXECUTE edge in
row = one("""SELECT p.node_id, max(e.ts_ns) FROM proc p JOIN edge e ON e.dst = p.node_id
             WHERE p.node_id IN (SELECT dst FROM edge WHERE op = 'CLONE')
               AND p.node_id IN (SELECT dst FROM edge WHERE op = 'EXECUTE')
             GROUP BY p.node_id ORDER BY max(e.ts_ns) DESC LIMIT 1""")
poi2, t2 = row
print("run 2's start:", one("SELECT tgid, comm, origin, parent_node, fork_ns FROM proc WHERE node_id = ?", [poi2]))
for i in range(3):
    t0 = time.perf_counter(); r = all_(Q, [poi2, t2 + 1]); dt = time.perf_counter() - t0
    print(f"run 2 round {i}: {dt:.3f} s, reached {r}")
