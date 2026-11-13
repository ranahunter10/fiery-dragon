# SPDX-License-Identifier: MIT
"""Tests for the soak's checks and report (bench/soak/check.py, summarize.py, soak.py's parsers)."""

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check as C  # noqa: E402
import soak as SK  # noqa: E402
import summarize as S  # noqa: E402

STEPS = [
    {"step": "compile", "i": 0, "t0": 100, "t1": 200, "ok": True,
     "expect": {"open_w": ["/w/c0/m.o", "/w/c0/prog0"], "open_r": ["/w/c0/m.c"], "exec": {"/usr/bin/cc": 2, "/w/c0/prog0": 1}}},
    {"step": "http", "i": 1, "t0": 300, "t1": 400, "ok": True, "expect": {"accept": {"5000": 2}, "connect": {"5000": 2}}},
    {"step": "memfd", "i": 2, "t0": 500, "t1": 600, "ok": True, "expect": {"argv0": {"p15-soak-memfd-2": 1}}},
    {"step": "git", "i": 3, "t0": 700, "t1": 800, "ok": False, "expect": {}},
]


def opn(ts, path, flags):
    return NS(name="OPEN", h={"ts_ns": ts}, f={"f_flags": flags}, var={"path": path.encode()})


def exe(ts, fn, argv0="x"):
    return NS(name="EXEC", h={"ts_ns": ts}, f={}, var={"filename": fn.encode(), "argv": argv0.encode() + b"\0-c\0"})


def net(ts, op, lport=0, rport=0):
    return NS(name="NET", h={"ts_ns": ts}, f={"op": op, "lport": lport, "rport": rport}, var={})


class Truth(unittest.TestCase):
    def full(self):
        return [opn(110, "/w/c0/m.o", 0o101), opn(120, "/w/c0/prog0", 0o1101), opn(105, "/w/c0/m.c", 0),
                exe(101, "/usr/bin/cc"), exe(150, "/usr/bin/cc"), exe(190, "/w/c0/prog0"),
                net(310, 2, lport=5000), net(311, 2, lport=5000), net(305, 1, rport=5000), net(306, 1, rport=5000),
                exe(550, "/proc/self/fd/3", "p15-soak-memfd-2")]

    def test_all_found(self):
        t = C.Truth(STEPS)
        for r in self.full():
            t.see(r)
        res = t.results()
        self.assertEqual({k: (v["expected"], v["found"]) for k, v in res.items()},
                         {"compile": (5, 5), "http": (2, 2), "memfd": (1, 1)})
        self.assertEqual([s["step"] for s in t.failed], ["git"])

    def test_misses_and_windows(self):
        t = C.Truth(STEPS)
        recs = self.full()
        recs[0] = opn(110, "/w/c0/m.o", 0)          # opened read-only: not the write it must be
        recs[4] = exe(250, "/usr/bin/cc")             # outside every window
        recs[6] = net(410, 2, lport=5000)             # after the http step's window
        recs.append(opn(650, "/w/c0/m.c", 0))         # in another step's window: not credited
        for r in recs:
            t.see(r)
        res = t.results()
        self.assertEqual(res["compile"]["found"], 3)
        self.assertIn("compile-0 open_w /w/c0/m.o", res["compile"]["missing"])
        self.assertIn("compile-0 exec /usr/bin/cc: 1 of 2", res["compile"]["missing"])
        self.assertIn("http-1 accept 5000: 1 of 2", res["http"]["missing"])
        t2 = C.Truth(STEPS)
        t2.see(opn(99, "/w/c0/m.c", 0))
        t2.see(exe(50, "/proc/self/fd/3", "p15-soak-memfd-2"))   # before every step: not the last step's
        t2.see(net(320, 3, rport=5000))                          # a LISTEN is not a connect
        t2.see(net(321, 3, rport=5000))
        self.assertEqual(t2.results()["memfd"]["found"], 0)
        self.assertEqual(t2.results()["http"]["found"], 0)
        t2.see(NS(name="FORK", h={"ts_ns": 150}, f={}, var={}))
        self.assertEqual(t2.results()["compile"]["found"], 0)

    def test_graph_wants(self):
        w = C.graph_wants(C.Truth(STEPS))
        self.assertEqual(w["dropper_chain"], (["/w/c0/prog0"], 1))
        self.assertEqual(w["sock_pairs"], ([(5000, 300, 400)], 2))
        self.assertEqual(w["memfd_exec"], (["p15-soak-memfd-2"], 1))
        two = STEPS + [{"step": "http", "i": 4, "t0": 900, "t1": 990, "ok": True,
                        "expect": {"accept": {"5000": 8}, "connect": {"5000": 8}}}]   # a port reused (E-0202)
        self.assertEqual(C.graph_wants(C.Truth(two))["sock_pairs"], ([(5000, 300, 400), (5000, 900, 990)], 10))


class Prom(unittest.TestCase):
    def test_prom(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "p.prom"
            p.write_text('# HELP x\np15_run_state 1\np15_spine_events_total{type="exec",cause="drained"} 5\n'
                         'p15_spine_events_total{type="fork",cause="drained"} 7\n'
                         'p15_spine_events_total{type="fork",cause="seen"} 99\np15_poll_gap_max_seconds 0.2\n')
            m = SK.prom(p)
            self.assertEqual((m["p15_run_state"], m["p15_spine_events_total:drained"], m["p15_poll_gap_max_seconds"]),
                             (1.0, 12.0, 0.2))
            self.assertEqual(SK.prom(Path(d) / "none")["p15_run_state"], 0.0)


def soak_text(found=78, end="end exit=0 end=1 state=0 invariant=1 records=100 read_errors=0 stops=0 read_s=1",
              graph="graph rc=0 build_s=3 bytes=1048576", gt=(4, 4), rss_last=13000, failed=0, books_bad=0):
    L = ["config duration=3600 sample=60 settle=10 pause=1 p15d_args=- ncpu=3"]
    for k in range(3):
        L.append(f"sample t={60 * (k + 1)} cpu_ms_per_s={20 + k} drain_ms_per_s={10 + k} writer_ms_per_s=1 "
                 f"rss_kb={13000 if k < 2 else rss_last} wal_bytes={1048576 * (k + 1)} state=0 spine_drained={100 * k} "
                 f"spine_skipped=0 bulk_written=5 net_skipped=0 queue_full=0 gaps=0 poll_gap_max_s=0.200")
    L += ["workload exit=0", end, f"truth step=archive steps=30 expected=78 found={found}",
          "truth step=memfd steps=3 expected=3 found=3"]
    L += [f"step_failed git-{k} " for k in range(failed)]
    L += ["file_stats open_emitted=10 missing_emitted=2 walked=2 walk_raced=0 walk_unnamed=0",
          "graph_out graph: /x", "graph_out   edge_without_node            %d" % books_bad, "graph_out   node_proc 516",
          graph, f"graph_truth dropper_chain found={gt[0]} expected={gt[1]}"]
    return "\n".join(L) + "\n"


class Report(unittest.TestCase):
    def test_pass(self):
        out, rc = S.report(soak_text())
        self.assertEqual(rc, 0, out)
        self.assertIn("| p15d CPU, ms/s | 21.00 | 22.00 | 20.00 | 22.00 |", out)
        self.assertIn("| archive | 30 | 78 | 78 | 100.00% |", out)
        self.assertIn("| dropper_chain | 4 | 4 |", out)
        self.assertIn("WAL: 3.0 MiB, 17.1 KiB/s.", out)
        self.assertIn("bulk-ring records written (NET and file identity): 5;", out)
        self.assertIn("node_proc 516", out)
        self.assertIn("- PASS", out)

    def test_fails(self):
        for t, why in ((soak_text(found=77), "step archive: 1 of 78 items not in the WAL"),
                       (soak_text(end="end exit=0 end=1 state=1 invariant=1 records=1 read_errors=0 stops=0 read_s=1"),
                        "state 1"),
                       (soak_text(end="end exit=0 end=1 state=0 invariant=1 records=1 read_errors=2 stops=0 read_s=1"),
                        "2 read errors"),
                       (soak_text(graph="graph rc=1 build_s=3 bytes=0"), "the graph build exited 1"),
                       (soak_text(gt=(3, 4)), "graph check dropper_chain: 3 of 4"),
                       (soak_text(books_bad=2), "graph book edge_without_node = 2"),
                       (soak_text(failed=4), "workload steps failed: more than 10 %"),
                       (soak_text() + "soak_error p15d exited 4 during the soak\n", "p15d exited 4 during the soak"),
                       (soak_text().replace("end exit=0 end=1 state=0 invariant=1 records=100 read_errors=0 stops=0 read_s=1\n", ""),
                        "no end line")):
            out, rc = S.report(t)
            self.assertEqual(rc, 1, why)
            self.assertIn(why, out)

    def test_graph_time(self):
        out, rc = S.report(soak_text(graph="graph rc=0 build_s=80 bytes=1048576"))
        self.assertEqual(rc, 0)
        self.assertIn("Graph build: 80 s per hour of workload, target under 60 s: over (not judged before gate 10).", out)
        out, rc = S.report(soak_text(graph="graph rc=0 build_s=80 bytes=1048576"), strict_graph_time=True)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL: the graph build took 80 s per hour of workload (target under 60)", out)
        out, rc = S.report(soak_text(graph="graph rc=0 build_s=59 bytes=1048576"), strict_graph_time=True)
        self.assertEqual(rc, 0)
        self.assertIn("target under 60 s: met.", out)
        half = soak_text(graph="graph rc=0 build_s=40 bytes=1048576").replace("duration=3600", "duration=1800")
        self.assertIn("80 s per hour of workload", S.report(half)[0])

    def test_notes(self):
        out, rc = S.report(soak_text(failed=0, rss_last=40000))
        self.assertEqual(rc, 0)
        self.assertNotIn("memory grew", out)       # under a quarter hour of samples: not judged
        txt = soak_text(rss_last=40000).replace("sample t=180", "sample t=1800")
        self.assertIn("resident memory grew from 12.7 to 39.1 MiB", S.report(txt)[0])
        txt = soak_text() + "step_failed git-9 FileNotFoundError: git\n"
        out, rc = S.report(txt)
        self.assertEqual(rc, 0)
        self.assertIn("1 workload steps failed (not checked)", out)

    def test_stall(self):
        out, rc = S.report(soak_text())
        self.assertNotIn("STALL", out)             # samples 60 s apart: no stall
        # E-0249's samples: the first at t=454 with 60 s planned, then 60 s apart
        txt = soak_text().replace("sample t=60 ", "sample t=454 ").replace("sample t=120 ", "sample t=514 ") \
            .replace("sample t=180 ", "sample t=574 ")
        out, rc = S.report(txt)
        self.assertEqual(rc, 0, out)               # reported, not judged: recall and the books decide
        self.assertIn("STALL: the sample at t=454 s came 454 s after the one before it (planned every 60 s): "
                      "about 394 s of the run lost to a stall. The rates above are not quotable (E-0249).", out)
        self.assertIn("- note: a stall touched the soak (about 394 s): its rates are not quotable", out)
        # 1.5 times the plan is the threshold: 90 s is not a stall, 91 s is
        self.assertNotIn("STALL", S.report(soak_text().replace("sample t=60 ", "sample t=90 "))[0])
        self.assertIn("STALL", S.report(soak_text().replace("sample t=60 ", "sample t=91 "))[0])

    def test_malformed(self):
        for t, why in ((soak_text() + "hello\n", "unknown line"),
                       (soak_text().replace("config duration", "configx duration"), "unknown line"),
                       ("sample t=1\n", "no config"),
                       (soak_text() + "end exit=0 end=1 state=0 invariant=1 records=1 read_errors=0 stops=0 read_s=1\n",
                        "a second end line")):
            with self.assertRaisesRegex(S.ParseError, why):
                S.report(t)


if __name__ == "__main__":
    unittest.main()
