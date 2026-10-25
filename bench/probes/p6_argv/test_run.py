# SPDX-License-Identifier: MIT
"""Tests for the P6 analysis (no root, no BPF). Run: python3 -m unittest -v bench/probes/p6_argv/test_run.py"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run as R  # noqa: E402

A, B, MIX = "A" * 16, "B" * 16, "AAAABBBBAAAABBBB"


def probe(*lines, preamble=()):
    return "\n".join([*preamble, "P6 start", *lines, "P6 end"]) + "\n"


def racer(*rows):
    return "\n".join(f"TRUTH {pid} {val} {st}" for pid, val, st in rows) + "\n"


class ParseAnalyzeTest(unittest.TestCase):
    def go(self, p, r):
        return R.analyze(R.parse(p, r))

    def test_clean_control(self):
        res = self.go(probe(f"ENTER 10 {A}", f"EXEC 10 {A}", f"ENTER 11 {A}", f"EXEC 11 {A}"),
                      racer((10, A, 0), (11, A, 0)))
        self.assertEqual(res["trials"], 2)
        self.assertEqual(res["ENTER"]["match"], 2)
        self.assertEqual(res["EXEC"]["match"], 2)
        self.assertEqual(R.problems("control", res, 2), [])

    def test_race_mismatch_is_a_finding_not_a_problem(self):
        res = self.go(probe(f"ENTER 10 {A}", f"EXEC 10 {MIX}"), racer((10, MIX, 0)))
        self.assertEqual(res["ENTER"]["mismatch"], 1)
        self.assertEqual(res["EXEC"]["match"], 1)
        self.assertEqual(res["truth_all_A"], 0)
        self.assertEqual(R.problems("race", res, 1), [])

    def test_control_mismatch_invalidates(self):
        res = self.go(probe(f"ENTER 10 {B}", f"EXEC 10 {A}"), racer((10, A, 0)))
        self.assertTrue(any("harness is broken" in p for p in R.problems("control", res, 1)))

    def test_missing_empty_and_unmatched_are_counted(self):
        # pid 10: no EXEC; pid 11: ENTER read failed (empty); pid 99: an event with no trial
        res = self.go(probe(f"ENTER 10 {A}", "ENTER 11", f"EXEC 11 {A}", f"EXEC 99 {A}"),
                      racer((10, A, 0), (11, A, 0)))
        self.assertEqual(res["EXEC"]["missing"], 1)
        self.assertEqual(res["ENTER"]["empty"], 1)
        self.assertEqual(res["EXEC"]["unmatched_events"], 1)
        probs = R.problems("race", res, 2)
        self.assertTrue(any(p.startswith("ENTER:") for p in probs))
        self.assertTrue(any(p.startswith("EXEC:") for p in probs))

    def test_preamble_is_counted_not_fatal_but_junk_after_start_is(self):
        res = self.go(probe(f"ENTER 10 {A}", f"EXEC 10 {A}", preamble=("warning: x", "Attaching 4 probes...")),
                      racer((10, A, 0)))
        self.assertEqual(res["preamble_lines"], 2)
        self.assertEqual(R.problems("control", res, 1), [])
        res = self.go(probe(f"ENTER 10 {A}", "garbage", f"EXEC 10 {A}"), racer((10, A, 0)))
        self.assertEqual(res["unknown_lines"], 1)
        self.assertNotEqual(R.problems("control", res, 1), [])

    def test_no_start_marker_is_a_problem(self):
        res = self.go(f"ENTER 10 {A}\nEXEC 10 {A}\n", racer((10, A, 0)))
        self.assertEqual(res["ENTER"]["missing"], 1)   # nothing before the marker is trusted
        self.assertNotEqual(R.problems("control", res, 1), [])

    def test_duplicate_and_short_runs_and_echo_failure(self):
        res = self.go(probe(f"ENTER 10 {A}", f"ENTER 10 {A}", f"EXEC 10 {A}"), racer((10, A, 3)))
        self.assertEqual(res["duplicate_reads"], 1)
        self.assertEqual(res["echo_failed"], 1)
        probs = R.problems("control", res, 5)
        self.assertTrue(any("1 of 5 trials" in p for p in probs))
        self.assertTrue(any("echo failed" in p for p in probs))

    def test_render_marks_unusable(self):
        res = self.go(probe(f"ENTER 10 {A}"), racer((10, A, 0)))
        res["problems"] = R.problems("control", res, 1)
        conds = {"utc_start": "t", "kernel": "k", "bpftrace": "b", "gcc": "g", "git_commit": "c" * 40,
                 "git_dirty": False, "trials": 1}
        md = R.render(conds, {"control": res})
        self.assertIn("| control | 1 | 1 | 1 (100.0 %) | 0 (0.0 %) |", md)
        self.assertIn("NO: EXEC: 1 missing", md)


if __name__ == "__main__":
    unittest.main()
