# SPDX-License-Identifier: MIT
"""Tests for the P8 analysis (no root, no BPF). Run: python3 -m unittest -v bench/probes/p8_compat/test_run.py"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run as R  # noqa: E402

GOOD_OPS_64 = """OP native_read x64 0 1111
OP compat_open int80 5 3
OP compat_read int80 3 2222
OP compat_open_w int80 5 3
OP compat_write int80 4 3333
OP compat_execve int80 11 pending
"""

# What a correct 64-bit run should print (one line per expectation, plus noise records).
GOOD_PROBE_64 = [
    "SYS 7 257 0", "OPEN 7 0 0 p8-src.dat", "SYS 7 0 0", "VFS_READ 7 1111 0",
    "SYS 7 5 1", "OPEN 7 0 1 p8-src.dat", "SYS 7 3 1", "VFS_READ 7 2222 1", "SYS 7 6 1",
    "SYS 7 5 1", "OPEN 7 0 1 p8-dst.dat", "SYS 7 4 1", "VFS_WRITE 7 3333 1", "SYS 7 6 1",
    "SYS 7 1 0", "VFS_WRITE 7 40 0",
    "SYS 7 11 1", "EXEC 7 0 /bin/true",
]


def probe(lines, preamble=()):
    return "\n".join([*preamble, "P8 start", *lines, "P8 end"]) + "\n"


class AnalyzeTest(unittest.TestCase):
    def test_good_run_has_no_misses(self):
        r = R.analyze("64", probe(GOOD_PROBE_64, preamble=("warning: x",)), GOOD_OPS_64)
        self.assertEqual(r["missed"], [])
        self.assertEqual(r["op_problems"], [])
        self.assertEqual(r["unknown_lines"], 0)
        self.assertEqual(r["preamble_lines"], 1)
        self.assertEqual(r["compat_ids_seen"], [3, 4, 5, 6, 11])
        self.assertEqual(r["x64_misreading"][3], "read would read as close")
        self.assertEqual(r["x64_misreading"][11], "execve would read as munmap")
        self.assertEqual(r["native_exec_ids_seen"], 0)
        self.assertEqual(r["exec_compat_bit"], [0])

    def test_real_vm_output_passes(self):
        # Raw output of the first VM run (7.0.0-38, 2026-10-25). compat.bt prints TS_COMPAT as 2;
        # the first analyzer required 1 and reported 9 false misses on this exact file.
        td = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")
        with open(os.path.join(td, "vm-7.0-probe-64-2026-10-25.txt")) as p, \
                open(os.path.join(td, "vm-7.0-program-64-2026-10-25.txt")) as o:
            r = R.analyze("64", p.read(), o.read())
        self.assertEqual(r["missed"], [])
        self.assertEqual(r["op_problems"], [])
        self.assertEqual(r["unknown_lines"], 0)
        self.assertEqual(r["preamble_lines"], 3)          # bpftrace's delete() warning
        self.assertEqual(r["exec_compat_bit"], [0])

    def test_real_vm_output_32bit_passes(self):
        # Raw output of the i386 build (vDSO entry) after gcc-multilib, same VM and kernel.
        td = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")
        with open(os.path.join(td, "vm-7.0-probe-32-2026-10-25.txt")) as p, \
                open(os.path.join(td, "vm-7.0-program-32-2026-10-25.txt")) as o:
            r = R.analyze("32", p.read(), o.read())
        self.assertEqual(r["missed"], [])
        self.assertEqual(r["op_problems"], [])
        self.assertEqual(r["native_exec_ids_seen"], 0)
        self.assertEqual(len(r["compat_ids_seen"]), 17)   # every syscall of an i386 program is compat
        # the same output read as a 64-bit run must fail: the native read is compat here
        self.assertNotEqual(R.analyze("64", open(os.path.join(td, "vm-7.0-probe-32-2026-10-25.txt")).read(),
                                      open(os.path.join(td, "vm-7.0-program-32-2026-10-25.txt")).read())["missed"], [])

    def test_compat_bit_value_two_counts_as_set(self):
        recs, _, _ = R.parse_probe(probe(["SYS 7 3 2", "VFS_READ 7 2222 2", "SYS 7 0 0"]))
        self.assertEqual([r["compat"] for r in recs], [1, 1, 0])

    def test_native_execve_ids_are_counted(self):
        r = R.analyze("64", probe(GOOD_PROBE_64 + ["SYS 7 59 0", "SYS 7 322 0", "SYS 7 59 1"]), GOOD_OPS_64)
        self.assertEqual(r["native_exec_ids_seen"], 3)

    def test_missing_vfs_read_is_a_miss(self):
        lines = [l for l in GOOD_PROBE_64 if l != "VFS_READ 7 2222 1"]
        r = R.analyze("64", probe(lines), GOOD_OPS_64)
        self.assertEqual(r["missed"], ["compat_read: no VFS_READ {'ret': 2222, 'compat': 1}"])

    def test_compat_bit_is_required(self):
        lines = ["SYS 7 3 0" if l == "SYS 7 3 1" else l for l in GOOD_PROBE_64]
        r = R.analyze("64", probe(lines), GOOD_OPS_64)
        self.assertEqual(r["missed"], ["compat_read: no SYS {'id': 3, 'compat': 1}"])

    def test_32bit_variant_expects_compat_native_read(self):
        lines = [l.replace("SYS 7 0 0", "SYS 7 3 1").replace("VFS_READ 7 1111 0", "VFS_READ 7 1111 1")
                 for l in GOOD_PROBE_64]
        self.assertEqual(R.analyze("32", probe(lines), GOOD_OPS_64)["missed"], [])
        self.assertNotEqual(R.analyze("32", probe(GOOD_PROBE_64), GOOD_OPS_64)["missed"], [])

    def test_failed_operations_are_problems(self):
        ops = GOOD_OPS_64.replace("compat_read int80 3 2222", "compat_read int80 3 -14") \
                         .replace("compat_open_w int80 5 3", "compat_open_w int80 5 -13") \
                         + "OP compat_execve_failed int80 11 -2\n"
        probs = R.analyze("64", probe(GOOD_PROBE_64), ops)["op_problems"]
        self.assertIn("compat_read returned -14, expected 2222", probs)
        self.assertIn("compat_open_w returned -13", probs)
        self.assertIn("compat execve failed: -2", probs)

    def test_unknown_lines_and_missing_marker(self):
        r = R.analyze("64", probe(GOOD_PROBE_64 + ["SYS x y z", "garbage"]), GOOD_OPS_64 + "stray\n")
        self.assertEqual(r["unknown_lines"], 3)
        r = R.analyze("64", "\n".join(GOOD_PROBE_64), GOOD_OPS_64)
        self.assertEqual(r["records"], 0)                 # nothing before the marker is trusted
        self.assertEqual(r["unknown_lines"], 1)
        self.assertEqual(len(r["missed"]), len(R.expectations("64")))

    def test_file_names_with_spaces_survive(self):
        recs, unknown, _ = R.parse_probe(probe(["OPEN 7 0 1 a name with spaces"]))
        self.assertEqual(unknown, 0)
        self.assertEqual(recs[0]["name"], "a name with spaces")

    def test_render_shows_skip_and_zero(self):
        lines = [l for l in GOOD_PROBE_64 if not l.startswith("EXEC")]
        r = R.analyze("64", probe(lines), GOOD_OPS_64)
        conds = {"utc_start": "t", "kernel": "k", "bpftrace": "b", "gcc": "g", "git_commit": "c" * 40,
                 "git_dirty": False, "kconfig_ia32": ["CONFIG_IA32_EMULATION=y"]}
        md = R.render(conds, {"64": r}, {"32": "build failed (x)"})
        self.assertIn("**Variant 32-bit SKIPPED:** build failed (x)", md)
        self.assertIn("| compat_execve | EXEC | name=/bin/true | **0** |", md)


if __name__ == "__main__":
    unittest.main()
