# SPDX-License-Identifier: MIT
"""Tests for the process snapshots (snapshot.py), the tree's use of the opening one (proctree.py)
and the ADR-0023 reconciliation (reconcile.py), on scenario.py's run with snapshots. ADR-0023's
confirmation 1: a FORK removed is located and repaired, an EXIT removed is located, and a count
above the counted losses is INVALID.

    python3 -m unittest -v python/tests/test_reconcile.py
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scenario as S  # noqa: E402

from p15 import trace as T  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.dir = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def ctx(self, **kw):
        return T.load(S.build(self.dir / "run", **kw))


class Snapshots(Base):
    def test_collected_and_complete(self):
        c = self.ctx(snap=True)
        self.assertEqual([(s.snap_id, s.kind, len(s.procs)) for s in c.snapshots], [(0, "opening", 2), (1, "closing", 3)])
        self.assertTrue(all(s.complete for s in c.snapshots))

    def test_books_that_dont_close(self):
        c = self.ctx(snap=True, closing_books={"tasks": 4})
        self.assertFalse(c.snapshots[1].complete)
        self.assertIn("tasks 4 != threads 0 + emitted 3", " ".join(c.snapshots[1].problems()))
        self.assertEqual(c.recon.verdict, "not possible")

    def test_records_p15d_did_not_account_for(self):
        c = self.ctx(snap=True, closing_books={"tasks": 4, "emitted": 4})
        self.assertIn("emitted 4 != entries 3 + invalid 0 + unwritten 0", " ".join(c.snapshots[1].problems()))

    def test_entries_the_wal_does_not_hold(self):
        c = self.ctx(snap=True, closing_books={"entries": 4, "emitted": 4, "tasks": 4})
        self.assertIn("SNAP_DONE counts 4 entries, the WAL holds 3", " ".join(c.snapshots[1].problems()))


class FdPass(unittest.TestCase):
    """The FD rows of a snapshot and SNAP_DONE v2's fd books (ADR-0015 rule 7)."""

    def snap(self, n_fd=3, **books):
        import numpy as np
        from p15 import records as R
        from p15 import snapshot as SN
        facts = np.zeros(1, R.gen.PARTS["OBJFACTS"])
        facts["seen"] = 2
        out = S.snapshot(10, 0, 1, S.OPENING[:1])
        done = out.pop()
        fds = [S.rec("FD", var={"facts": facts.tobytes(), "path": b"/dev/null"}, h_tgid=1, fd=i, fid=10 + i, obj=20 + i,
                     snap_id=0) for i in range(n_fd)]
        f = {"tasks": 1, "threads": 0, "emitted": 1, "entries": 1, "fd_pass": 1, "fd_files": 3, "fd_emitted": 3,
             "fd_entries": 3, "fd_registered": 2, "fd_known": 1, **books}
        done = S.rec("SNAP_DONE", h_ts_ns=2000, duration_ns=100, snap_id=0, kind=1, **f)
        recs = [R.decode(memoryview(b), 0, 0, i) for i, b in enumerate(out + fds + [done])]
        return SN.collect(recs)[0]

    def test_complete_with_its_fd_rows(self):
        s = self.snap()
        self.assertEqual((len(s.fds), s.kind, s.problems()), (3, "opening", []))

    def test_fd_books_that_dont_close(self):
        self.assertIn("fd_files 4 != fd_no_inode 0 + fd_emitted 3", " ".join(self.snap(fd_files=4).problems()))
        self.assertIn("fd_emitted 3 != fd_known 1 + fd_registered 1", " ".join(self.snap(fd_registered=1).problems()))
        self.assertIn("SNAP_DONE counts 3 FD rows, the WAL holds 2", " ".join(self.snap(n_fd=2).problems()))
        self.assertIn("reading the FD iterator failed (-5)", " ".join(self.snap(fd_error=-5).problems()))
        self.assertIn("FD rows: 1 not written", " ".join(self.snap(fd_files=4, fd_write_failed=1).problems()))

    def test_fd_rows_without_a_pass(self):
        s = self.snap(fd_pass=0)
        self.assertIn("3 FD rows without an FD pass", " ".join(s.problems()))


class TreeFromSnapshot(Base):
    def test_parents_and_programs_of_preexisting_processes(self):
        t = self.ctx(snap=True).tree
        bash = t.procs[S.BASH]
        self.assertEqual(bash.parent, S.INIT)
        self.assertEqual((bash.name, bash.images[0].seen_in, bash.images[0].argv), ("bash", "snapshot", ["-bash"]))
        self.assertIn(S.BASH, t.procs[S.INIT].children)
        self.assertEqual(t.procs[S.INIT].parent, None)        # parent tgid 0: the kernel's root
        self.assertEqual((t.counts["from_snapshot"], t.counts["pre_existing_unlisted"]), (2, 0))
        self.assertEqual([p.name for p in t.lineage(S.NC)], ["nc", "sh", "python3", "bash", "systemd"])

    def test_without_snapshots_nothing_is_invented(self):
        t = self.ctx().tree
        self.assertIsNone(t.procs[S.BASH].parent)
        self.assertEqual((t.counts["from_snapshot"], t.counts["pre_existing_unlisted"]), (0, 1))


class Reconcile(Base):
    def test_complete(self):
        r = self.ctx(snap=True).recon
        self.assertEqual((r.verdict, r.fork_unexplained, r.exit_unexplained), ("complete", [], []))
        self.assertIn("complete", r.line())

    def test_lost_fork_is_located_and_repaired(self):
        c = self.ctx(snap=True, drop={("FORK", S.SRV)}, fork_lost=1)
        r = c.recon
        self.assertEqual((r.verdict, r.fork_unexplained), ("repaired", [S.SRV]))
        srv = c.tree.procs[S.SRV]
        self.assertEqual(srv.parent, S.BASH)
        self.assertIn("parent repaired from the closing snapshot", srv.origin)
        self.assertIn("FORK lost: parent from the closing snapshot", T.chain(c, S.SRV))

    def test_lost_exit_is_located(self):
        r = self.ctx(snap=True, drop={("EXIT", S.C1)}, exit_lost=1).recon
        self.assertEqual((r.verdict, r.exit_unexplained), ("repaired", [S.C1]))
        self.assertIn("1 lost EXIT(s) located", r.line())

    def test_a_lost_fork_nothing_counted_is_invalid(self):
        r = self.ctx(snap=True, drop={("FORK", S.SRV)}).recon
        self.assertEqual(r.verdict, "INVALID")
        self.assertIn("1 forks unexplained but 0 counted lost", r.line())

    def test_born_during_the_closing_snapshot_is_set_aside(self):
        r = self.ctx(snap=True, late_fork=True).recon
        self.assertEqual((r.verdict, r.exit_unexplained, r.born_during_closing), ("complete", [], 1))

    def test_more_unexplained_than_counted_is_invalid(self):
        r = self.ctx(snap=True, drop={("FORK", S.SRV), ("EXIT", S.C1)}, fork_lost=1).recon
        self.assertEqual(r.verdict, "INVALID")
        self.assertIn("1 exits unexplained but 0 counted lost", r.line())

    def test_not_possible_without_a_closing_snapshot(self):
        self.assertIn("END says the closing snapshot was not taken (0)", self.ctx().recon.line())
        self.assertIn("did not end in order", self.ctx(snap=True, end=False).recon.line())

    def test_trust_block_carries_it(self):
        c = self.ctx(snap=True)
        self.assertTrue(any(x.startswith("process tree check (ADR-0023): complete") for x in c.verdict()))


if __name__ == "__main__":
    unittest.main()
