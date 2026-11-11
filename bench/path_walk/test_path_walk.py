# SPDX-License-Identifier: MIT
"""Tests for the path_walk report (bench/path_walk/summarize.py)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import summarize as S  # noqa: E402


def case(name, verdict="equal", flags=0, dpath="/a/b", walk="/a/b"):
    return (f"case {name} verdict={verdict} flags=0x{flags:x} dpath_rc={len(dpath) + 1} dpath_len={len(dpath)} "
            f"walk_len={len(walk)} dpath={dpath} walk={walk}")


def run(over=None, race="race opens=100 renames=900 samples=100 equal=90 flagged=3 moved=7 raced=1 retried=2 mismatch=0 "
        "dpath_failed=0 open_failed=0", times=True, drop=None, extra="", end="end lost=4 kprobe_flags=0x100"):
    over = over or {}
    L = ["config dir=/x rounds=3 n=100 kallsyms_rename_lock=1 kallsyms_mount_lock=1"]
    for c in S.CASES:
        if c == drop:
            continue
        if c in over:
            L.append(over[c])
        elif c == "deep70":
            L.append(case(c, "flagged", 1, "/d/e", "/e"))
        elif c == "pipe":
            L.append(case(c, "flagged", 4, "pipe:[5]", ""))
        else:
            L.append(case(c))
    if race:
        L.append(race)
    if times:
        for r in range(-1, 3):
            L.append(f"time round={r} path=short fentry_runs=100 dpath_ns={9000 + r} walk_fentry_ns={12000 + 100 * r * r} "
                     f"kprobe_runs=100 walk_kprobe_ns={11000 + r}")
    if end:
        L.append(end)
    return "\n".join(L) + "\n" + extra


class Report(unittest.TestCase):
    def test_pass(self):
        out, rc = S.report(run())
        self.assertEqual(rc, 0)
        self.assertIn("PASS", out)
        self.assertIn("| short | 3 | 90.0 ns | 121.0 ns | 110.0 ns |", out)
        self.assertIn("| deep70 | flagged | flagged | TRUNCATED |", out)
        self.assertIn("**0 wrong without a flag**", out)
        self.assertIn("7 not compared", out)
        self.assertIn("no room for (fentry, all parts): 4. Flags the walk set in the kprobe.session: RETRIED.", out)

    def test_a_mismatch_fails(self):
        out, rc = S.report(run({"bind": case("bind", "MISMATCH", 0, "/x/y", "/q/y")}))
        self.assertEqual(rc, 1)
        self.assertIn("FAIL: case bind: the walk gave another path and did not say so", out)

    def test_a_race_mismatch_fails(self):
        out, rc = S.report(run(race="race opens=100 renames=9 samples=100 equal=90 flagged=9 moved=0 raced=1 retried=0 "
                               "mismatch=1 dpath_failed=0 open_failed=0", extra="race_mismatch flags=0x0 dpath=/a walk=/b\n"))
        self.assertEqual(rc, 1)
        self.assertIn("the rename race: 1 samples wrong without a flag", out)
        self.assertIn("race_mismatch flags=0x0 dpath=/a walk=/b", out)

    def test_unexpected_flag_is_a_note_and_failures_are_failures(self):
        out, rc = S.report(run({"memfd": case("memfd", "flagged", 16, "/memfd:x", "/m")}))
        self.assertEqual(rc, 0)
        self.assertIn("note: case memfd: flagged, expected equal", out)
        out, rc = S.report(run({"bind": "case bind mount_failed errno=1"}))
        self.assertEqual(rc, 1)
        out, rc = S.report(run({"deep70": case("deep70")}))
        self.assertEqual(rc, 0)
        self.assertIn("note: case deep70: equal, expected flagged", out)
        out, rc = S.report(run(race="race opens=1 renames=1 samples=0 equal=0 flagged=0 moved=0 raced=0 retried=0 mismatch=0 "
                               "dpath_failed=0 open_failed=1"))
        self.assertEqual(rc, 1)
        out, rc = S.report(run(race="race opens=5 renames=1 samples=5 equal=0 flagged=0 moved=5 raced=0 retried=0 mismatch=0 "
                               "dpath_failed=0 open_failed=0"))
        self.assertEqual(rc, 1)
        self.assertIn("compared no sample", out)
        out, rc = S.report(run(times=False))
        self.assertEqual(rc, 1)
        self.assertIn("no timing rounds", out)

    def test_malformed(self):
        for t, why in ((run(drop="chroot"), "missing cases: chroot"), (run(race=None), "one race line"),
                       (run(extra="race opens=1 renames=1 samples=1 equal=1 flagged=0 moved=0 raced=0 retried=0 mismatch=0 "
                                  "dpath_failed=0 open_failed=0\n"), "one race line"),
                       (run(extra="case plain verdict=equal\n"), "unparsed case"),
                       (run(extra=case("plain") + "\n"), "case plain twice"),
                       (run(extra="time round=1 path=x fentry_runs=99 dpath_ns=1 walk_fentry_ns=1 kprobe_runs=100 walk_kprobe_ns=1\n"),
                        "not 100 each"),
                       (run(extra="time round=1 path=x fentry_runs=100 dpath_ns=1 walk_fentry_ns=1 kprobe_runs=99 walk_kprobe_ns=1\n"),
                        "not 100 each"),
                       (run(extra="config dir=/x rounds=3 n=100 kallsyms_rename_lock=1 kallsyms_mount_lock=1\n"), "config line"),
                       ("time round=1 path=x fentry_runs=1 dpath_ns=1 walk_fentry_ns=1 kprobe_runs=1 walk_kprobe_ns=1\n" + run(),
                        "before the config"),
                       (run(extra="hello\n"), "unknown line"), (run(end=None), "one end line"),
                       (run(extra="end lost=1 kprobe_flags=0x0\n"), "one end line"),
                       (run(end="end lost=x"), "unparsed end")):
            with self.assertRaisesRegex(S.ParseError, why):
                S.report(t)


if __name__ == "__main__":
    unittest.main()
