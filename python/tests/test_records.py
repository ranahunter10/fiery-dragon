# SPDX-License-Identifier: MIT
"""Tests for the record decoder (python/p15/records.py): every refusal p15_rec_check makes
(daemon/records.c, same wording), no defaults, and the field helpers.

    python3 -m unittest -v python/tests/test_records.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from p15w_build import R, rec  # noqa: E402


def dec(b: bytes, off=0):
    return R.decode(memoryview(b), off, 0, 0)


class Refusals(unittest.TestCase):
    def why(self, b: bytes, words: str):
        with self.assertRaises(R.RecordError) as cm:
            dec(b)
        self.assertEqual(cm.exception.why, words)

    def test_every_refusal(self):
        exe = rec("EXEC", var={"filename": b"/bin/xy", "argv": b"x\0"})   # 73 bytes: 7 of padding
        self.why(b"\0" * 31, "shorter than the header")
        self.why(rec("EXIT")[:32], "len beyond the bytes received")
        self.why(rec("EXIT", h_len=36) + b"\0" * 4, "len not a multiple of 8")
        self.why(rec("EXIT", h_type=99, h_len=40), "unknown type or version")
        self.why(rec("EXIT", h_version=2, h_len=40), "unknown type or version")
        self.why(rec("EXIT", h_len=32), "len shorter than the fixed part")
        self.why(rec("FORK", length=72), "len differs from the fixed size")
        self.why(rec("EXEC", filename_len=257, length=64 + 264), "variable field beyond len")
        self.why(rec("EXEC", var={"filename": b"/bin/x"}, filename_len=40), "variable field beyond len")
        self.why(rec("EXEC", var={"filename": b"/bin/x"}, length=80), "len larger than its fields need")
        bad_tail = bytearray(exe)
        bad_tail[-1] = 1
        self.why(bytes(bad_tail), "non-zero bytes after the variable fields")
        self.why(rec("END", var={"reason": b"x"}, length=80, h_flags=R.F_READ_FAILED),
                 "len larger than its fields need")   # slack only on a BPF-built (SPINE) record

    def test_slack_after_a_failed_read(self):
        r = dec(rec("EXEC", var={"filename": b"/bin/x"}, length=80, h_flags=R.F_READ_FAILED))
        self.assertEqual(r.var, {"filename": b"/bin/x", "argv": b""})

    def test_offset_and_wording(self):
        with self.assertRaises(R.RecordError) as cm:
            R.decode(memoryview(rec("EXIT") + b"\0" * 31), 40, 0, 0)
        self.assertEqual(cm.exception.offset, 40)
        self.assertIn("payload offset 40", str(cm.exception))


class Decoding(unittest.TestCase):
    def test_no_defaults(self):
        r = dec(rec("EXIT", h_tgid=7, h_start_ns=9, exit_code=-1, group_dead=1))
        self.assertEqual((r.proc, r.f["exit_code"], r.f["group_dead"]), ((7, 9), -1, 1))
        with self.assertRaises(KeyError):
            r.f["exit_status"]          # a renamed or missing field is an error, never 0 (L7)
        self.assertNotIn("_pad", dec(rec("FORK")).f)

    def test_every_type_round_trips(self):
        for name, t in R.TYPES.items():
            with self.subTest(name=name):
                r = dec(rec(name, h_ts_ns=123))
                self.assertEqual((r.name, r.h["type"], r.h["ts_ns"]), (name, t, 123))
                self.assertIsInstance(r.h["ts_ns"], int)

    def test_char_fields_keep_every_byte(self):
        n = dec(rec("NET", family=2, laddr=b"\x0a", lport=1, raddr=b"", rport=2))
        self.assertEqual(len(n.f["laddr"]), 16)
        self.assertEqual((R.endpoint(n, "l"), R.endpoint(n, "r")), ("10.0.0.0:1", "0.0.0.0:2"))
        n6 = dec(rec("NET", family=10, laddr=b"\0" * 15 + b"\1", lport=80))
        self.assertEqual(R.endpoint(n6, "l"), "[::1]:80")
        with self.assertRaises(R.RecordError):
            R.endpoint(dec(rec("NET", family=1)), "l")


class Helpers(unittest.TestCase):
    def test_kdev(self):
        self.assertEqual(R.kdev((259 << 20) | 3), (259, 3))
        self.assertEqual(R.kdev(0), (0, 0))

    def test_comm_and_argv(self):
        self.assertEqual(R.comm(b"sh\0garbage\0\0\0\0\0\0"), "sh")
        self.assertEqual(R.argv(dec(rec("EXEC", var={"argv": b"a\0b c\0"}))), ["a", "b c"])
        self.assertEqual(R.argv(dec(rec("EXEC", var={"argv": b"a\0b"}))), ["a", "b"])  # cut, no final NUL
        self.assertEqual(R.argv(dec(rec("EXEC"))), [])


if __name__ == "__main__":
    unittest.main()
