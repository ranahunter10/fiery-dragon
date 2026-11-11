# SPDX-License-Identifier: MIT
"""Tests for the record decoder (python/p15/records.py): every refusal p15_rec_check makes
(daemon/records.c, same wording), no defaults, and the field helpers.

    python3 -m unittest -v python/tests/test_records.py
"""

import sys
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

from p15w_build import R, rec  # noqa: E402


def dec(b: bytes, off=0):
    return R.decode(memoryview(b), off, 0, 0)


def facts(**kw) -> bytes:
    """An OBJFACTS part (schema/records.toml): seen 1 (open) unless given."""
    a = np.zeros(1, R.gen.PARTS["OBJFACTS"])
    a["seen"] = 1
    for k, v in kw.items():
        a[k] = v
    return a.tobytes()


class Refusals(unittest.TestCase):
    def why(self, b: bytes, words: str):
        with self.assertRaises(R.RecordError) as cm:
            dec(b)
        self.assertEqual(cm.exception.why, words)

    def test_every_refusal(self):
        exe = rec("EXEC", version=1, var={"filename": b"/bin/xy", "argv": b"x\0"})   # v1: 73 bytes, 7 of padding
        self.why(b"\0" * 31, "shorter than the header")
        self.why(rec("EXIT")[:32], "len beyond the bytes received")
        self.why(rec("EXIT", h_len=36) + b"\0" * 4, "len not a multiple of 8")
        self.why(rec("EXIT", h_type=99, h_len=40), "unknown type or version")
        self.why(rec("EXIT", h_version=2, h_len=40), "unknown type or version")
        self.why(rec("EXIT", h_len=32), "len shorter than the fixed part")
        self.why(rec("FORK", length=72), "len differs from the fixed size")
        self.why(rec("EXEC", version=1, filename_len=257, length=64 + 264), "variable field beyond len")
        self.why(rec("EXEC", version=1, var={"filename": b"/bin/x"}, filename_len=40), "variable field beyond len")
        self.why(rec("EXEC", version=1, var={"filename": b"/bin/x"}, length=80), "len larger than its fields need")
        bad_tail = bytearray(exe)
        bad_tail[-1] = 1
        self.why(bytes(bad_tail), "non-zero bytes after the variable fields")
        self.why(rec("END", var={"reason": b"x"}, length=80, h_flags=R.F_READ_FAILED),
                 "len larger than its fields need")   # slack only on a BPF-built (SPINE) record

    def test_flags_and_net_v2(self):
        """The same rules as records.c (ADR-0022): known flag bits only, the ISN flag only on NET v2,
        and NET v2's reserved field and unflagged ISN are zero."""
        self.why(rec("EXIT", h_flags=1 << 7), "unknown flag bits")
        self.why(rec("EXIT", h_flags=R.F_ISN), "ISN flag on a record that has no ISN")
        self.why(rec("NET", version=1, h_flags=R.F_ISN), "ISN flag on a record that has no ISN")
        self.why(rec("NET", reserved=1), "NET v2: non-zero reserved, or tcp_isn without P15_F_ISN")
        self.why(rec("NET", tcp_isn=5), "NET v2: non-zero reserved, or tcp_isn without P15_F_ISN")
        r = dec(rec("NET", h_flags=R.F_ISN, tcp_isn=0xFFFFFFFF))
        self.assertEqual((r.h["version"], r.f["tcp_isn"]), (2, 0xFFFFFFFF))
        self.assertEqual(dec(rec("NET", h_flags=R.F_ISN, tcp_isn=0)).f["tcp_isn"], 0)
        self.assertEqual(dec(rec("NET", version=1)).h["version"], 1)

    def test_snapshot_and_end_v2(self):
        """PROC, SNAP_DONE (ADR-0007 rule 3) and END v2 (ADR-0023 rule 1): records.c's rules."""
        p = dec(rec("PROC", kind=2, pflags=3, var={"exe_path": b"/usr/bin/x", "argv": b"x\0-v\0"}))
        self.assertEqual((p.var["exe_path"], R.argv(p), R.SNAP_KINDS[p.f["kind"]]), (b"/usr/bin/x", ["x", "-v"], "closing"))
        why = "PROC: non-zero reserved, unknown kind or unknown pflags"
        self.why(rec("PROC", kind=3), why)
        self.why(rec("PROC", kind=1, pflags=4), why)
        self.why(rec("PROC", kind=1, reserved=1), why)
        self.why(rec("PROC", kind=1, var={"exe_path": b"/x"}, length=200), "len larger than its fields need")
        self.why(rec("PROC", version=1, kind=1, argv_len=1025), "variable field beyond len")
        self.why(rec("SNAP_DONE", kind=0), "SNAP_DONE: unknown kind")
        e = dec(rec("END", closing_snapshot=-71, var={"reason": b"stop requested"}))
        self.assertEqual((e.h["version"], e.f["closing_snapshot"], e.var["reason"]), (2, -71, b"stop requested"))
        self.why(rec("END", reserved=1), "END v2: non-zero reserved")
        self.assertEqual(dec(rec("END", version=1, var={"reason": b"x"})).h["version"], 1)

    def test_slack_after_a_failed_read(self):
        r = dec(rec("EXEC", version=1, var={"filename": b"/bin/x"}, length=80, h_flags=R.F_READ_FAILED))
        self.assertEqual(r.var, {"filename": b"/bin/x", "argv": b""})

    def test_offset_and_wording(self):
        with self.assertRaises(R.RecordError) as cm:
            R.decode(memoryview(rec("EXIT") + b"\0" * 31), 40, 0, 0)
        self.assertEqual(cm.exception.offset, 40)
        self.assertIn("payload offset 40", str(cm.exception))


class FileIdentity(unittest.TestCase):
    """OPEN, OPEN_VERDICT, BACKING, CLOSE and FD (ADR-0015, STATE decision 19): the parts, the fflags
    and the rules every byte of them follows."""

    def why(self, b: bytes, words: str):
        with self.assertRaises(R.RecordError) as cm:
            dec(b)
        self.assertEqual(cm.exception.why, words)

    def test_open_with_facts_and_path(self):
        r = dec(rec("OPEN", fid=2, obj=1, fflags=R.gen.FF_OBJ_NEW, f_flags=0o100000,
                    var={"facts": facts(ino=3933235, dev=(8 << 20) | 2, gen=7, mode=0o100640, fs_magic=0xEF53, nlink=1),
                         "path": b"/var/tmp/f1"}))
        self.assertEqual((r.f["fid"], r.f["obj"], r.var["path"]), (2, 1, b"/var/tmp/f1"))
        self.assertEqual((r.var["facts"]["ino"], R.kdev(r.var["facts"]["dev"]), r.var["facts"]["seen"]),
                         (3933235, (8, 2), 1))
        known = dec(rec("OPEN", fid=3, obj=1, var={"path": b"/var/tmp/f1"}))
        self.assertIsNone(known.var["facts"])                    # an object already described

    def test_part_presence_follows_its_flag(self):
        self.why(rec("OPEN", var={"facts": facts()}), "OPEN: facts present without its flag, or its flag without it")
        self.why(rec("OPEN", fflags=R.gen.FF_OBJ_NEW), "OPEN: facts present without its flag, or its flag without it")
        self.why(rec("OPEN", fflags=R.gen.FF_OBJ_NEW, var={"facts": facts()[:24]}),
                 "OPEN: facts is neither absent nor a whole OBJFACTS")
        self.why(rec("OPEN", fflags=R.gen.FF_OBJ_NEW, var={"facts": facts()}, facts_len=40, facts_full=0),
                 "OPEN: facts is neither absent nor a whole OBJFACTS")      # _full says how much there is
        self.why(rec("FD", var={"path": b"x"}), "FD: facts present without its flag, or its flag without it")
        self.why(rec("FD", var={"facts": facts(oflags=2)}), "OBJFACTS: unknown oflags bits or an unknown 'seen'")
        self.why(rec("FD", var={"facts": facts(seen=0)}), "OBJFACTS: unknown oflags bits or an unknown 'seen'")
        b = dec(rec("BACKING", fflags=R.gen.FF_USER_OBJ_NEW, var={"user_facts": facts(fs_magic=0x794C7630)}))
        self.assertEqual((b.var["facts"], b.var["user_facts"]["fs_magic"]), (None, 0x794C7630))
        self.why(rec("BACKING", fflags=R.gen.FF_OBJ_NEW, var={"user_facts": facts()}),
                 "BACKING: facts present without its flag, or its flag without it")

    def test_fflags_each_record_may_carry(self):
        self.why(rec("CLOSE", fflags=R.gen.FF_OBJ_NEW), "CLOSE: fflags bits this record never carries")
        self.why(rec("OPEN", fflags=1 << 7), "OPEN: fflags bits this record never carries")
        self.why(rec("FD", fflags=R.gen.FF_KTHREAD, var={"facts": facts()}), "FD: fflags bits this record never carries")
        c = dec(rec("CLOSE", fid=4, fflags=R.gen.FF_NEVER_OPENED | R.gen.FF_KTHREAD))
        self.assertEqual(c.f["fflags"], R.gen.FF_NEVER_OPENED | R.gen.FF_KTHREAD)

    def test_verdicts_and_path_errors(self):
        self.why(rec("OPEN", verdict=-13), "OPEN: a verdict on an OPEN the fentry wrote (a denial is OPEN_VERDICT)")
        m = dec(rec("OPEN", fflags=R.gen.FF_PATH_MISSING, verdict=-13))
        self.assertEqual((m.f["verdict"], m.var["path"]), (-13, b""))
        self.why(rec("OPEN_VERDICT", verdict=0), "OPEN_VERDICT: the verdict is not a denial")
        self.why(rec("OPEN", path_err=-22), "OPEN: path_err without PATH_ERROR, or PATH_ERROR without path_err")
        self.why(rec("OPEN", fflags=R.gen.FF_PATH_ERROR), "OPEN: path_err without PATH_ERROR, or PATH_ERROR without path_err")
        self.assertEqual(dec(rec("OPEN", fflags=R.gen.FF_PATH_ERROR, path_err=-22)).f["path_err"], -22)

    def test_full_size_open(self):
        lay = R.gen.RECORDS[(R.TYPES["OPEN"], 1)]
        full = rec("OPEN", fflags=R.gen.FF_FULL_SIZE, var={"path": b"/a"}, length=lay.max_size)
        self.assertEqual(dec(full).var["path"], b"/a")
        dirty = bytearray(full)
        dirty[-1] = 1
        self.why(bytes(dirty), "non-zero bytes after the variable fields")
        self.why(rec("OPEN", fflags=R.gen.FF_FULL_SIZE, var={"path": b"/a"}, length=lay.max_size - 8),
                 "len larger than its fields need")
        self.why(rec("OPEN", var={"path": b"/a"}, length=lay.max_size), "len larger than its fields need")


class SnapDoneV2(unittest.TestCase):
    def test_fd_pass_is_zero_or_one(self):
        self.assertEqual(dec(rec("SNAP_DONE", kind=1, fd_pass=1, fd_entries=3)).f["fd_entries"], 3)
        with self.assertRaises(R.RecordError) as cm:
            dec(rec("SNAP_DONE", kind=1, fd_pass=2))
        self.assertEqual(cm.exception.why, "SNAP_DONE: fd_pass is neither 0 nor 1")

    def test_v1_still_reads(self):
        self.assertEqual(dec(rec("SNAP_DONE", version=1, kind=2)).f["kind"], 2)


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
                extra = {"kind": 1} if name in ("PROC", "SNAP_DONE") else {}   # kind 0 is not a kind
                if name == "OPEN_VERDICT":
                    extra = {"verdict": -13}                                      # only a denial is a verdict
                if name == "FD":
                    extra = {"var": {"facts": facts()}}                           # FD always carries its facts
                r = dec(rec(name, h_ts_ns=123, **extra))
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
