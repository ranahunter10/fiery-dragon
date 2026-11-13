# SPDX-License-Identifier: MIT
"""p15.graph.track: the USING KEY queries against a plain-Python BackTracker on hand-made and random
graphs (events at one moment and transfers over an interval), and on built graphs: a TCP connection
crossed by its exact pairing, an overlay file and its real file, a file crossed from its reader to
its writer by FLOW records, and edges that did not happen never followed."""

import contextlib
import heapq
import io
import random
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scenario as SC  # noqa: E402

from p15.graph import build as B  # noqa: E402
from p15.graph import track as T  # noqa: E402


def spans(edges):
    """(src, dst, t0, t1) from (src, dst, ts or None) or (src, dst, t0, t1)."""
    return [(e[0], e[1], e[2], e[2]) if len(e) == 3 else e for e in edges]


def ref_backward(edges, start, t):
    """BackTracker by hand: a widest-path search. edges: (src, dst, ts or None) or (src, dst, t0, t1)."""
    into: dict[int, list] = {}
    for s, d, t0, t1 in spans(edges):
        into.setdefault(d, []).append((s, t0, t1))
    best = {start: t}
    heap = [(-t, start)]
    while heap:
        nt, v = heapq.heappop(heap)
        if -nt != best[v]:
            continue
        for u, t0, t1 in into.get(v, ()):
            if t0 is None:
                cand = best[v]
            elif t0 < best[v]:
                cand = min(best[v], t1)
            else:
                continue
            if cand > best.get(u, -1):
                best[u] = cand
                heapq.heappush(heap, (-cand, u))
    return best


def ref_forward(edges, start, t):
    out: dict[int, list] = {}
    for s, d, t0, t1 in spans(edges):
        out.setdefault(s, []).append((d, t0, t1))
    best = {start: t}
    heap = [(t, start)]
    while heap:
        bt, u = heapq.heappop(heap)
        if bt != best[u]:
            continue
        for v, t0, t1 in out.get(u, ()):
            if t0 is None:
                cand = best[u]
            elif t1 > best[u]:
                cand = max(best[u], t0)
            else:
                continue
            if cand < best.get(v, 1 << 62):
                best[v] = cand
                heapq.heappush(heap, (cand, v))
    return best


def db_of(edges, pairs=(), backing=(), failed=()):
    """A graph with only what track reads: edge, sock_pair, file_backing, and proc (empty here)."""
    con = duckdb.connect()
    con.execute("CREATE TABLE edge (src BIGINT, dst BIGINT, ts_ns UBIGINT, end_ns UBIGINT, op VARCHAR, ok BOOLEAN)")
    rows = [(s, d, t0, t1, "X", True) for s, d, t0, t1 in spans(edges)] + \
           [(s, d, t0, t1, "X", False) for s, d, t0, t1 in spans(failed)]
    if rows:
        con.executemany("INSERT INTO edge VALUES (?, ?, ?, ?, ?, ?)", rows)
    con.execute("CREATE TABLE sock_pair (client_node BIGINT, server_node BIGINT)")
    if pairs:
        con.executemany("INSERT INTO sock_pair VALUES (?, ?)", list(pairs))
    con.execute("CREATE TABLE proc (node_id BIGINT, parent_node BIGINT, fork_ns UBIGINT, start_ns UBIGINT)")
    con.execute("CREATE TABLE file_backing (real_node BIGINT, user_node BIGINT)")
    if backing:
        con.executemany("INSERT INTO file_backing VALUES (?, ?)", list(backing))
    return con


class HandMade(unittest.TestCase):
    # BackTracker's own shape (SOSP'03 fig. 2): P1 wrote X at 30, P2 read X at 40 and wrote F at 60;
    # Z wrote X at 50, after P2 had read it; the point of interest is F read at 100
    F, P2, X, P1, Z, NET = 1, 2, 3, 4, 5, 6
    E = [(P2, F, 60), (X, P2, 40), (P1, X, 30), (Z, X, 50), (NET, P1, 20), (F, P2, 70)]

    def test_the_threshold_rule(self):
        con = db_of(self.E)
        got = T.backward(con, self.F, 100)
        self.assertEqual(got, {self.F: 100, self.P2: 60, self.X: 40, self.P1: 30, self.NET: 20})
        self.assertNotIn(self.Z, got)          # wrote X after P2 had read it
        self.assertEqual(got, ref_backward(self.E, self.F, 100))

    def test_forward_is_the_mirror(self):
        con = db_of(self.E)
        self.assertEqual(T.forward(con, self.NET, 0), {self.NET: 0, self.P1: 20, self.X: 30, self.P2: 40, self.F: 60})
        self.assertEqual(T.forward(con, self.Z, 0), {self.Z: 0, self.X: 50})     # X was read before Z wrote it

    def test_relations_keep_the_threshold_and_failed_edges_are_not_followed(self):
        # client process 10 -> client socket 11 (CONNECT at 5); 11 ~ 12 server socket (PAIR);
        # 12 -> server 13 (ACCEPT at 6); overlay file 20 ~ real file 21; 21 -> 13 at 7; a denied 22 -> 13
        con = db_of([(10, 11, 5), (12, 13, 6), (21, 13, 7)], pairs=[(11, 12)], backing=[(21, 20)], failed=[(22, 13, 8)])
        got = T.backward(con, 13, 100)
        self.assertEqual(got, {13: 100, 12: 6, 11: 6, 10: 5, 21: 7, 20: 7})
        self.assertEqual(T.forward(con, 10, 0), {10: 0, 11: 5, 12: 5, 13: 6})
        # the pairing is one way: a server's reply needs its SEND joined to the socket node (step 2e)
        self.assertEqual(T.forward(con, 13, 0), {13: 0})
        self.assertEqual(T.backward(con, 10, 100), {10: 100})

    def test_a_transfer_is_followed_by_its_interval(self):
        # W wrote F over [10, 35]; R read F over [30, 40]: the write began before the read ended
        W, F, R, LATE, EARLY = 1, 2, 3, 4, 5
        e = [(W, F, 10, 35), (F, R, 30, 40), (LATE, F, 41, 50), (EARLY, W, 5, 5)]
        con = db_of(e)
        # backward from R at 100: F by the read's end, W by its write's end (earlier than F's
        # threshold), EARLY by its moment; LATE began after the read had ended
        self.assertEqual(T.backward(con, R, 100), {R: 100, F: 40, W: 35, EARLY: 5})
        # a threshold inside the read: only what began before it
        self.assertEqual(T.backward(con, R, 31), {R: 31, F: 31, W: 31, EARLY: 5})
        self.assertEqual(T.backward(con, R, 30), {R: 30})                 # the read had not begun
        self.assertEqual(T.backward(con, F, 10), {F: 10})                 # nor the write
        # forward from W affected at 20: the write was still running, so F from 20 and R from its read's start
        self.assertEqual(T.forward(con, W, 20), {W: 20, F: 20, R: 30})
        self.assertEqual(T.forward(con, W, 35), {W: 35})                  # the write had ended
        self.assertEqual(T.forward(con, EARLY, 0), {EARLY: 0, W: 5, F: 10, R: 30})
        self.assertEqual(T.forward(con, LATE, 0), {LATE: 0, F: 41})       # the read ended at 40
        self.assertEqual(T.span(con), (5, 50))                            # the last edge's end, not its start
        for v, t in ((R, 100), (R, 31), (F, 36), (W, 7)):
            self.assertEqual(T.backward(con, v, t), ref_backward(e, v, t))
            self.assertEqual(T.forward(con, v, t), ref_forward(e, v, t))

    def test_a_cycle_ends(self):
        e = [(1, 2, 10), (2, 1, 20), (2, 3, 30), (3, 2, 40)]
        con = db_of(e, backing=[(1, 3)])
        self.assertEqual(T.backward(con, 3, 50), ref_backward(e + [(1, 3, None), (3, 1, None)], 3, 50))
        self.assertEqual(T.forward(con, 1, 0), ref_forward(e + [(1, 3, None), (3, 1, None)], 1, 0))


class Random(unittest.TestCase):
    def test_against_the_reference(self):
        for seed in range(40):
            rnd = random.Random(seed)
            n = rnd.randint(5, 120)
            hubs = rnd.sample(range(n), max(1, n // 20))
            edges = []
            for _ in range(rnd.randint(0, 8 * n)):
                s = rnd.choice(hubs) if rnd.random() < 0.3 else rnd.randrange(n)
                d = rnd.choice(hubs) if rnd.random() < 0.3 else rnd.randrange(n)
                t0 = rnd.randint(1, 1000)                 # half are events, half transfers over an interval
                edges.append((s, d, t0, t0 if rnd.random() < 0.5 else t0 + rnd.randint(0, 200)))
            pairs = [(rnd.randrange(n), rnd.randrange(n)) for _ in range(rnd.randint(0, 3))]
            backing = [(rnd.randrange(n), rnd.randrange(n)) for _ in range(rnd.randint(0, 2))]
            rel = [(a, b, None) for a, b in pairs] + [(a, b, None) for a, b in backing] + \
                  [(b, a, None) for a, b in backing]
            con = db_of(edges, pairs, backing)
            for _ in range(3):
                v, t = rnd.randrange(n), rnd.randint(0, 1100)
                with self.subTest(seed=seed, node=v, t=t):
                    self.assertEqual(T.backward(con, v, t), ref_backward(edges + rel, v, t))
                    self.assertEqual(T.forward(con, v, t), ref_forward(edges + rel, v, t))
            con.close()


class Built(unittest.TestCase):
    """On a graph built from a synthetic run (python/tests/scenario.py's story)."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        SC.build(self.d / "run", snap=True)
        B.build(self.d / "run", self.d / "g.duckdb")
        self.con = duckdb.connect(str(self.d / "g.duckdb"), read_only=True)

    def tearDown(self):
        self.con.close()
        shutil.rmtree(self.d)

    def proc(self, tgid):
        return self.con.execute("SELECT node_id FROM proc WHERE tgid = ?", [tgid]).fetchone()[0]

    def tgids(self, got):
        rows = self.con.execute("SELECT node_id, tgid FROM proc").fetchall()
        return sorted(t for n, t in rows if n in got)

    def test_backward_from_the_server_crosses_its_connections(self):
        got = T.backward(self.con, self.proc(600), 1 << 62)
        # the two local curls reached the server through their exact ISN pairs (ADR-0022); bash forked
        # them, and init forked bash before the capture (the snapshot's parent, at bash's start); the
        # server's own children forked after it: not backward of it
        self.assertEqual(self.tgids(got), [1, 500, 600, 610, 620])
        # the curl reached through the pair keeps the accept's time as its threshold, narrowed by its connect
        acc = self.con.execute("SELECT min(ts_ns) FROM edge WHERE op = 'ACCEPT'").fetchone()[0]
        self.assertLessEqual(got[self.proc(610)], acc)

    def test_a_process_from_the_snapshot_reaches_its_parent_at_its_start(self):
        got = T.backward(self.con, self.proc(500), 1 << 62)
        self.assertEqual(self.tgids(got), [1, 500])
        self.assertEqual(got[self.proc(1)], SC.BASH[1])             # bash's start: when init forked it
        self.assertEqual(self.tgids(T.backward(self.con, self.proc(500), SC.BASH[1])), [500])

    def test_a_refused_connect_reaches_nothing(self):
        got = T.forward(self.con, self.proc(640), 0)
        self.assertEqual(self.tgids(got), [640])
        kinds = self.con.execute("SELECT node_id, kind FROM node").fetchall()
        self.assertEqual([k for n, k in kinds if n in got], ["proc"])

    def test_resolve_and_cli(self):
        key = self.con.execute("SELECT key FROM node WHERE node_id = ?", [self.proc(600)]).fetchone()[0]
        self.assertEqual(T.resolve(self.con, key), self.proc(600))
        self.assertEqual(T.resolve(self.con, str(self.proc(600))), self.proc(600))
        with self.assertRaises(ValueError):
            T.resolve(self.con, "p:1:2")
        self.con.close()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(T.main([str(self.d / "g.duckdb"), "--back", key, "--top", "2"]), 0)
        text = out.getvalue()
        self.assertIn("backward from node", text)
        self.assertIn("proc 600 python3 (python3 -m http.server 18077)", text)
        self.assertIn("more (--top)", text)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(T.main([str(self.d / "g.duckdb"), "--forward", "nope"]), 2)
            self.assertEqual(T.main([str(self.d / "none.duckdb"), "--back", "1"]), 2)
        self.assertIn("no node 'nope'", err.getvalue())
        self.con = duckdb.connect(str(self.d / "g.duckdb"), read_only=True)


if __name__ == "__main__":
    unittest.main()
