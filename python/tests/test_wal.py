# SPDX-License-Identifier: MIT
"""Tests for the P15W reader (python/p15/wal.py) against docs/formats/p15w-v1.md: every header
check, every §4 stop cause and its torn/corrupt verdict, the run rules, and random damage.

    python3 -m unittest -v python/tests/test_wal.py
"""

import contextlib
import io
import random
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from p15w_build import R, W, batch, header, meta_for, rec, write_run  # noqa: E402

FORK = rec("FORK", h_ts_ns=10, h_tgid=1, h_start_ns=1, child_tgid=2, kind=1)
EXIT = rec("EXIT", h_ts_ns=20, h_tgid=2, h_start_ns=5, group_dead=1)


class Tmp(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.dir = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def seg(self, data: bytes, index=0) -> W.Segment:
        p = self.dir / f"seg-{index:08d}.p15w"
        p.write_bytes(data)
        return W.read_segment(p)


class Crc(unittest.TestCase):
    def test_check_value(self):
        self.assertEqual(W.crc32c(b"123456789"), 0xE3069283)

    def test_c_implementation(self):
        self.assertEqual(W.google_crc32c.implementation, "c")


class Header(Tmp):
    def bad(self, data, words):
        with self.assertRaises(W.HeaderError) as cm:
            self.seg(data)
        self.assertIn(words, str(cm.exception))

    def test_valid(self):
        s = self.seg(header(0, meta_for((5, 6, 7))))
        self.assertEqual((s.index, s.seq_next, s.batches, s.stop), (0, {0: 5, 1: 6, 2: 7}, [], None))
        self.assertEqual(s.meta["run.id"], "r1")

    def test_prefix(self):
        m = meta_for()
        self.bad(b"P15W", "shorter")
        self.bad(header(0, m, magic=b"P15X"), "magic")
        self.bad(header(0, m, major=2), "version 2.0")
        self.bad(header(0, m, minor=1), "version 1.1")
        self.bad(header(0, m, bo=0x04030201), "byte_order")
        self.bad(header(0, m, rsv=1), "reserved")
        self.bad(header(0, m, bad_crc=True), "CRC")
        self.bad(header(0, m)[:40], "header_len")
        for hlen in (24, 36):     # below the prefix; not a multiple of 8
            h = bytearray(header(0, m))
            h[12:16] = struct.pack("<I", hlen)
            self.bad(bytes(h), f"header_len {hlen}")

    def test_index_must_match_the_name(self):
        with self.assertRaises(W.HeaderError):
            self.seg(header(3, meta_for()), index=0)

    def test_entries(self):
        def ent(k: bytes, v: bytes, klen=None, rsv=0, pad=b""):
            e = struct.pack("<HHI", len(k) if klen is None else klen, rsv, len(v)) + k + v
            return e + (pad or b"\0" * (-len(e) % 8))

        seqs = b"".join(ent(f"seq.next.{r}".encode(), b"0") for r in W.RINGS)

        def hdr(extra, n=4):
            return header(0, {}, raw_entries=seqs + extra, count=n)

        self.assertEqual(self.seg(hdr(ent(b"k", b"v"))).meta["k"], "v")
        self.bad(hdr(ent(b"Bad", b"v")), "outside")
        self.bad(hdr(ent(b"k", b"\xff")), "UTF-8")
        self.bad(hdr(ent(b"k", b"v", rsv=1)), "reserved")
        self.bad(hdr(ent(b"", b"v", klen=0)), "key_len 0")
        self.bad(hdr(ent(b"k", b"v", pad=b"\0\0\0\0\0\x01")), "padding")
        self.bad(hdr(ent(b"seq.next.spine", b"1")), "repeated")
        self.bad(hdr(b"", n=4), "past header_len")
        self.bad(hdr(ent(b"k", b"v"), n=3), "metadata ends at")
        self.bad(header(0, {"run.id": "r1"}), "seq.next.spine missing")
        self.bad(header(0, meta_for(), extra_len=8), "metadata ends at")
        self.bad(header(0, meta_for(("x", 0, 0))), "decimal")


class Batches(Tmp):
    def stop(self, tail: bytes, seq=(0, 0, 0)):
        s = self.seg(header(0, meta_for(seq)) + batch(0, seq[0], [FORK]) + tail)
        self.assertEqual(len(s.batches), 1, "the good batch before the stop is kept")
        return s.stop

    def test_valid_to_the_end(self):
        s = self.seg(header(0, meta_for()) + batch(0, 0, [FORK, EXIT]) + batch(2, 0, [FORK]))
        self.assertIsNone(s.stop)
        self.assertEqual([(b.ring, b.count, b.first_seq) for b in s.batches], [(0, 2, 0), (2, 1, 0)])
        self.assertEqual(s.seq_next, {0: 2, 1: 0, 2: 1})

    def test_causes_and_verdicts(self):
        good = batch(0, 1, [EXIT])
        cases = [
            # (tail, cause, torn)
            (good[:39], 1, True),
            (batch(0, 1, [EXIT], magic=b"XXXX") + b"\x01", 2, False),
            (batch(0, 1, [EXIT], bad_hcrc=True), 3, False),
            (batch(0, 1, [EXIT], flags=1), 4, False),
            (batch(0, 1, [EXIT], rsv=1), 4, False),
            (batch(3, 1, [EXIT]), 4, False),
            (batch(0, 1, [EXIT], count=0), 5, False),
            (batch(0, 1, [EXIT], count=2), 5, False),          # payload < 32 x count
            (batch(0, 1, [EXIT], plen=44), 5, False),           # not a multiple of 8
            (good[:-8], 6, True),                               # payload cut short
            (batch(0, 1, [EXIT], bad_pcrc=True), 7, True),      # bad CRC ending exactly at EOF
            (batch(0, 1, [EXIT], bad_pcrc=True) + good, 7, False),
            (batch(0, 1, [EXIT, EXIT], count=1), 8, False),
            (batch(0, 1, [rec("EXIT", h_len=48)]), 8, False),   # record len past the payload
            (batch(0, 5, [EXIT]), 9, False),                    # first_seq skips
            (batch(1, 1, [EXIT]), 9, False),                    # bulk starts at 0, not 1
        ]
        for tail, cause, torn in cases:
            with self.subTest(cause=cause, torn=torn):
                st = self.stop(tail)
                self.assertIsNotNone(st)
                self.assertEqual((st.cause, st.torn), (cause, torn), st.describe())

    def test_zero_tail_is_torn(self):
        st = self.stop(b"\0" * 4096)
        self.assertEqual((st.cause, st.torn), (2, True))
        st = self.stop(b"\0" * 4095 + b"\x01")
        self.assertEqual((st.cause, st.torn), (2, False))

    def test_describe(self):
        self.assertIn("CORRUPTION", self.stop(batch(0, 7, [EXIT])).describe())
        self.assertIn("torn tail", self.stop(b"P15B").describe())


class Runs(Tmp):
    def run_of(self, *segs):
        return W.read_run(write_run(self.dir / "run", list(segs)))

    def test_sequence_crosses_segments(self):
        r = self.run_of(header(0, meta_for()) + batch(0, 0, [FORK]),
                        header(1, meta_for((1, 0, 0))) + batch(0, 1, [EXIT]))
        self.assertEqual([x.seq for x in r.ring_records(0)], [0, 1])
        self.assertFalse(r.corrupt)

    def test_seq_next_must_continue(self):
        with self.assertRaises(W.HeaderError) as cm:
            self.run_of(header(0, meta_for()) + batch(0, 0, [FORK]), header(1, meta_for((0, 0, 0))))
        self.assertIn("previous segment", str(cm.exception))

    def test_missing_segment(self):
        d = write_run(self.dir / "run", [header(0, meta_for())])
        (d / "seg-00000002.p15w").write_bytes(header(2, meta_for()))
        with self.assertRaises(W.RunError):
            W.read_run(d)

    def test_empty_dir(self):
        (self.dir / "e").mkdir()
        with self.assertRaises(W.RunError):
            W.read_run(self.dir / "e")

    def test_identity_must_hold_across_segments(self):
        for k in ("run.id", "boot_id", "schema.hash"):
            with self.subTest(key=k), self.assertRaises(W.RunError):
                m = meta_for(**{k: "other"})
                self.run_of(header(0, meta_for()), header(1, m))
            (self.dir / "run").exists() and [p.unlink() for p in (self.dir / "run").iterdir()]

    def test_schema_must_be_this_readers(self):
        with self.assertRaises(W.RunError) as cm:
            self.run_of(header(0, meta_for(**{"schema.hash": "0" * 64})))
        self.assertIn("schema", str(cm.exception))
        m = meta_for()
        del m["schema.hash"]
        with self.assertRaises(W.RunError):
            self.run_of(header(0, m))

    def test_stops_are_reported(self):
        r = self.run_of(header(0, meta_for()) + batch(0, 0, [FORK]) + batch(0, 9, [EXIT]) + batch(0, 1, [EXIT]))
        self.assertTrue(r.corrupt)
        self.assertEqual([st.cause for _, st in r.stops], [9])

    def test_merge_by_time(self):
        late = rec("FORK", h_ts_ns=30, h_tgid=1, h_start_ns=1)
        early, last = rec("EXIT", h_ts_ns=5), rec("EXIT", h_ts_ns=40)
        r = self.run_of(header(0, meta_for()) + batch(0, 0, [FORK, late]) + batch(2, 0, [early, last]))
        self.assertEqual([(x.h["ts_ns"], x.ring) for x in r.records()], [(5, 2), (10, 0), (30, 0), (40, 2)])


class BadRecords(Tmp):
    """A record that tiles but fails its check: strict by default, collected on request."""

    def setUp(self):
        super().setUp()
        bad = rec("FORK", length=72)            # tiles (72, a multiple of 8) but FORK is 64
        self.d = write_run(self.dir / "run", [header(0, meta_for()) + batch(0, 0, [FORK, bad, EXIT])])

    def test_strict(self):
        with self.assertRaises(R.RecordError):
            list(W.read_run(self.d).ring_records(0))

    def test_collected_and_the_walk_goes_on(self):
        errs: list = []
        got = list(W.read_run(self.d).ring_records(0, errs))
        self.assertEqual([(r.name, r.seq) for r in got], [("FORK", 0), ("EXIT", 2)])
        self.assertEqual([(ring, seq, e.why) for ring, seq, e in errs], [(0, 1, "len differs from the fixed size")])

    def test_summary_and_exit(self):
        lines, problems = W.summary(W.read_run(self.d))
        self.assertEqual(lines[:3], ["records: spine 2, bulk 0, daemon 0; invalid 1", "  FORK       1", "  EXIT       1"])
        self.assertIn("invalid record: spine seq 1: len differs from the fixed size", lines)
        self.assertEqual(problems, 1)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(W.main([str(self.d)]), 1)
            good = write_run(self.dir / "good", [header(0, meta_for()) + batch(0, 0, [FORK]) + b"P15B"])
            self.assertEqual(W.main([str(good)]), 0, "a torn tail is reported, not a failure")
        (self.dir / "empty").mkdir()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(W.main([]), 2)
            self.assertEqual(W.main([str(self.dir / "empty")]), 1)

    def test_corruption_fails_the_summary(self):
        d = write_run(self.dir / "c", [header(0, meta_for()) + batch(0, 0, [FORK]) + batch(0, 3, [EXIT]) + batch(0, 1, [EXIT])])
        lines, problems = W.summary(W.read_run(d))
        self.assertEqual(problems, 1)
        self.assertTrue(any("CORRUPTION" in x for x in lines))


class Damage(Tmp):
    """Random damage never escapes as anything but a reported stop, a HeaderError or a
    RecordError, and the reader never decodes a byte past a stop."""

    def test_random_flips(self):
        rnd = random.Random(1102)
        exe = rec("EXEC", var={"filename": b"/bin/x", "argv": b"x\0y"}, h_ts_ns=5, h_tgid=3, h_start_ns=3)
        good = header(0, meta_for()) + batch(0, 0, [FORK, exe, EXIT]) + batch(2, 0, [EXIT])
        outcomes = {"stop": 0, "header": 0, "record": 0, "clean": 0}
        d = self.dir / "run"
        d.mkdir()
        p = d / "seg-00000000.p15w"
        for _ in range(3000):
            b = bytearray(good)
            for _ in range(rnd.randint(1, 4)):
                b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
            if rnd.random() < 0.2:
                b = b[:rnd.randrange(len(b))]
            p.write_bytes(bytes(b))
            try:
                run = W.read_run(d)
                list(run.records())
                outcomes["stop" if run.stops else "clean"] += 1
            except W.HeaderError:
                outcomes["header"] += 1
            except (W.RunError, R.RecordError):
                outcomes["record"] += 1
        self.assertEqual(sum(outcomes.values()), 3000)
        self.assertGreater(outcomes["stop"], 0)
        self.assertGreater(outcomes["header"], 0)


if __name__ == "__main__":
    unittest.main()
