# SPDX-License-Identifier: MIT
"""Tests for tools/ci/check_hardening.py, on readelf/nm lines copied from build/p15-spine."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_hardening  # noqa: E402

GOOD = {
    "h": "  Type:                              DYN (Position-Independent Executable file)\n",
    "d": (" 0x000000000000001e (FLAGS)              BIND_NOW\n"
          " 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE\n"),
    "lw": ("  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10\n"
           "  GNU_RELRO      0x1536f0 0x00000000001546f0 0x00000000001546f0 0x002910 0x002910 R   0x1\n"),
    "n": "      Properties: x86 feature: IBT, SHSTK\n",
    "syms": ("                 U __fprintf_chk@GLIBC_2.3.4\n"
             "                 U __stack_chk_fail@GLIBC_2.4\n"),
}


def verdict(**over):
    a = dict(GOOD, **over)
    return check_hardening.checks(a["h"], a["d"], a["lw"], a["n"], a["syms"])


class CheckHardening(unittest.TestCase):
    def test_hardened_binary_passes_all(self):
        self.assertTrue(all(verdict().values()), verdict())

    def test_each_property_missing(self):
        cases = {
            "pie": {"h": "  Type:                              EXEC (Executable file)\n"},
            "relro": {"lw": GOOD["lw"].splitlines()[0] + "\n"},
            "now": {"d": " 0x000000006ffffffb (FLAGS_1)            Flags: PIE\n"},
            "nx-stack": {"lw": GOOD["lw"].replace("RW  0x10", "RWE 0x10")},
            "canary": {"syms": "                 U __fprintf_chk@GLIBC_2.3.4\n"},
            "fortify": {"syms": "                 U __stack_chk_fail@GLIBC_2.4\n"},
            "cet": {"n": "      Properties: x86 feature: IBT\n"},
        }
        for prop, over in cases.items():
            got = verdict(**over)
            self.assertFalse(got[prop], prop)
            self.assertTrue(all(v for k, v in got.items() if k != prop), (prop, got))

    def test_pie_needs_the_flag_not_only_dyn(self):
        self.assertFalse(verdict(d=" 0x000000000000001e (FLAGS)              BIND_NOW\n")["pie"])

    def test_now_from_either_dynamic_flag(self):
        self.assertTrue(verdict(d=" 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE\n")["now"])
        self.assertTrue(verdict(d=GOOD["d"].replace("Flags: NOW PIE", "Flags: PIE"))["now"])

    def test_missing_stack_segment_is_not_nx(self):
        self.assertFalse(verdict(lw=GOOD["lw"].splitlines()[1] + "\n")["nx-stack"])


if __name__ == "__main__":
    unittest.main()
