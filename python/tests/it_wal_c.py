# SPDX-License-Identifier: MIT
"""The Python reader against the C writer: decode, field by field, the run that
daemon/tests/wal_fixture.c wrote through daemon/wal.c. Run by `make it-pyreader`, which writes
the run and passes its directory in P15_WAL_FIXTURE. Without it the test fails (it is not
skipped: a skipped cross-check would pass silently)."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from p15 import records as R  # noqa: E402
from p15 import wal  # noqa: E402


class CWriterRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = os.environ.get("P15_WAL_FIXTURE")
        if not d:
            raise AssertionError("P15_WAL_FIXTURE is not set: run `make it-pyreader`")
        cls.run_ = wal.read_run(Path(d))
        cls.recs = list(cls.run_.records())
        cls.by = {}
        for r in cls.recs:
            cls.by.setdefault(r.name, []).append(r)

    def test_run_shape(self):
        run = self.run_
        self.assertGreaterEqual(len(run.segments), 2, "1 KiB segments must rotate")
        self.assertEqual(run.stops, [])
        self.assertEqual(run.meta["run.id"], "20261102T000000Z-fixture0")
        self.assertEqual(run.meta["schema.hash"], R.SCHEMA_HASH)
        for s in run.segments:     # the writer's own keys, in every segment
            for k in ("clock.boottime_ns", "seq.next.spine", "seq.next.bulk", "seq.next.daemon", "rotate.max_bytes"):
                self.assertIn(k, s.meta)
        self.assertEqual({k: len(v) for k, v in self.by.items()},
                         {"FORK": 1, "EXEC": 1, "EXIT": 1, "RENAME": 1, "NET": 3, "CLOCK_SYNC": 1,
                          "STATS": 2, "NET_STATS": 2, "GAP": 2, "END": 1})

    def test_sequences_per_ring(self):
        for ring, n in ((0, 4), (1, 3), (2, 8)):
            self.assertEqual([r.seq for r in self.run_.ring_records(ring)], list(range(n)))

    def test_daemon_v2(self):
        """STATS, GAP and NET_STATS version 2 (ADR-0020): the kernel's skips."""
        s2, g2, n2 = self.by["STATS"][1], self.by["GAP"][1], self.by["NET_STATS"][1]
        self.assertEqual([r.h["version"] for r in (s2, g2, n2)], [2, 2, 2])
        self.assertEqual([s2.f[f"{t}_missed"] for t in ("fork", "exec", "exit", "rename")], [1, 77, 3, 4])
        self.assertEqual((g2.f["from_ns"], g2.f["to_ns"], g2.f["exec_missed"], g2.f["fork_missed"]), (9500, 10001, 5, 0))
        self.assertEqual((n2.f["net_missed"], n2.f["bulk_ring_bytes"]), (9, 4194304))

    def test_merged_by_time(self):
        ts = [r.h["ts_ns"] for r in self.recs]
        self.assertEqual(ts, sorted(ts))

    def test_spine(self):
        f = self.by["FORK"][0]
        self.assertEqual(f.proc, (100, 50))
        self.assertEqual(f.f, {"child_start_ns": 990, "child_task_start_ns": 990, "child_tgid": 200,
                               "child_tid": 200, "kind": 1})
        e = self.by["EXEC"][0]
        self.assertEqual(e.proc, (200, 990))
        self.assertEqual(e.var, {"filename": b"/bin/sh", "argv": b"sh\0-c\0id"})
        self.assertEqual(R.argv(e), ["sh", "-c", "id"])
        self.assertEqual(R.kdev(e.f["exe_dev"]), (8, 1))
        self.assertEqual((e.f["exe_ino"], e.f["exe_gen"], e.f["old_tid"]), (4242, 7, 200))
        rn = self.by["RENAME"][0]
        self.assertEqual((R.comm(rn.f["old_comm"]), R.comm(rn.f["new_comm"])), ("bash", "sh"))
        x = self.by["EXIT"][0]
        self.assertEqual((x.f["exit_code"], x.f["group_dead"]), (256, 1))

    def test_net_v2(self):
        """NET version 2 (ADR-0022): the client ISN and its flag, next to v1 records in the same run."""
        v2 = self.by["NET"][2]
        self.assertEqual((v2.h["version"], v2.h["flags"] & R.F_ISN), (2, R.F_ISN))
        self.assertEqual((v2.f["tcp_isn"], v2.f["reserved"], v2.f["sock_cookie"]), (0xFEDCBA98, 0, 4107))
        self.assertEqual(R.endpoint(v2, "l"), "127.0.0.1:41510")

    def test_net(self):
        c, a = self.by["NET"][:2]
        self.assertEqual((c.f["op"], c.f["ret"], c.f["sock_cookie"], c.f["peer_cookie"]), (1, -111, 4105, 0))
        self.assertEqual((R.endpoint(c, "l"), R.endpoint(c, "r")), ("127.0.0.1:41508", "10.0.0.0:4444"))
        self.assertEqual((c.f["proto"], c.f["netns"]), (6, 4026531840))
        self.assertEqual((a.f["op"], a.f["sock_cookie"], a.f["peer_cookie"]), (2, 4106, 4105))
        self.assertEqual((R.endpoint(a, "l"), R.endpoint(a, "r")), ("[::1]:8080", "[fe80::1]:50000"))
        self.assertEqual(a.proc, (100, 50))

    def test_daemon(self):
        c = self.by["CLOCK_SYNC"][0].f
        self.assertEqual(c, {"boottime_ns": 500, "monotonic_ns": 400, "realtime_ns": 1793577600000000000,
                             "read_spread_ns": 3})
        s = self.by["STATS"][0].f
        u64 = [k for k in R.gen.RECORDS[(33, 1)].dtype.names if k not in ("h", "_pad")][:-4]
        self.assertEqual([s[k] for k in u64], [1000 + i for i in range(len(u64))])
        self.assertEqual((s["spine_ring_bytes"], s["queue_depth_max"], s["queue_batches"], s["run_state"]),
                         (4194304, 3, 64, 1))
        ns = self.by["NET_STATS"][0].f
        self.assertEqual([ns[k] for k in list(ns)[:9]], [2000 + i for i in range(9)])
        self.assertEqual(ns["bulk_ring_bytes"], 4194304)
        g = self.by["GAP"][0].f
        self.assertEqual([g[k] for k in g], [5500, 6000, 4, 1, 2, 3, 4, 5, 6, 7, 8])
        e = self.by["END"][0]
        self.assertEqual((e.f["exit_code"], e.f["run_state"], e.f["invariant"], e.f["signal"]), (3, 1, 1, 15))
        self.assertEqual(e.var["reason"], b"stop requested")


if __name__ == "__main__":
    unittest.main()
