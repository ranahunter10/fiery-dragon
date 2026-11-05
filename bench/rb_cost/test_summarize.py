# SPDX-License-Identifier: MIT
"""Tests for bench/rb_cost/summarize.py on synthetic exec_cost output."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import summarize  # noqa: E402


def row(rnd, way, argv=20, t=1000, cnt=10, ours=10, **bad):
    f = dict(invalid=0, wrong_size=0, wrong_argv=0, foreign=0)
    f.update(bad)
    return (f"row round={rnd} way={way} argv={argv} execs=10 run_cnt={cnt} run_time_ns={t} ours={ours} "
            f"foreign={f['foreign']} invalid={f['invalid']} wrong_size={f['wrong_size']} wrong_argv={f['wrong_argv']}")


GOOD = [
    "exec_cost: libbpf v1.7, 3 rounds x 10 execs, ways fixed/output/dynptr",
    "selftest way=fixed FAIL failed_checks=1",
    "selftest way=output PASS failed_checks=0",
    "selftest way=dynptr PASS failed_checks=0",
    "nullsys round=0 calls=1000 total_ns=100000",
    "nullsys round=1 calls=1000 total_ns=200000",
    "nullsys round=2 calls=1000 total_ns=300000",
    # ns/run: fixed 120, 110, 130; output 100, 90, 140; dynptr 150, 80, 160
    row(0, "fixed", t=1200), row(0, "output", t=1000), row(0, "dynptr", t=1800, cnt=12, foreign=2),
    row(1, "fixed", t=1100), row(1, "output", t=900), row(1, "dynptr", t=800),
    row(2, "fixed", t=1300), row(2, "output", t=1400), row(2, "dynptr", t=1600),
    "exec_cost: ok",
]


class Summarize(unittest.TestCase):
    def test_report_numbers(self):
        d = summarize.parse(GOOD)
        self.assertEqual(summarize.problems(d), [])
        out = summarize.report(d)
        self.assertIn("median 200.0, min 100.0, max 300.0", out)               # null syscall ns/call
        self.assertIn("| fixed | 3 | 120 | 110 | 130 | 0.6 |", out)            # 120 / 200
        self.assertIn("| output | 3 | 100 | 90 | 140 | 0.5 |", out)
        self.assertIn("| dynptr | 3 | 150 | 80 | 160 | 0.8 |", out)
        # paired minus output: fixed +20, +20, -10; dynptr +50, -10, +20
        self.assertIn("| fixed | +20 | -10 | +20 | 1 of 3 |", out)
        self.assertIn("| dynptr | +20 | -10 | +50 | 1 of 3 |", out)
        self.assertIn("other processes' execs during the measurements: 2", out)
        self.assertIn("| fixed | FAIL | 1 |", out)

    def test_bad_rows_are_problems(self):
        for bad in (dict(ours=9), dict(invalid=1), dict(wrong_size=1), dict(wrong_argv=1)):
            lines = GOOD[:-2] + [row(2, "dynptr", t=1600, **bad)]
            self.assertEqual(len(summarize.problems(summarize.parse(lines))), 1, bad)

    def test_missing_round_is_a_problem(self):
        lines = [x for x in GOOD if not x.startswith("row round=2 way=fixed")]
        self.assertIn("same rounds", summarize.problems(summarize.parse(lines))[0])

    def test_malformed_result_lines_refused(self):
        for line in ("row round=0 way=fixed argv=20",                        # missing keys
                     row(0, "other"),                                        # unknown way
                     row(0, "fixed", cnt=0),                                 # nothing ran
                     row(0, "fixed").replace("run_time_ns=1000", "run_time_ns=x"),
                     "selftest way=fixed MAYBE failed_checks=1",
                     "nullsys round=0 calls=1000"):
            with self.assertRaises(summarize.ParseError, msg=line):
                summarize.parse([line])

    def test_extra_key_refused(self):
        with self.assertRaises(summarize.ParseError):
            summarize.parse([row(0, "fixed") + " extra=1"])

    def test_ties_are_not_cheaper(self):
        lines = [row(0, "fixed", t=1000), row(0, "output", t=1000), row(0, "dynptr", t=900)]
        out = summarize.report(summarize.parse(lines))
        self.assertIn("| fixed | +0 | +0 | +0 | 0 of 1 |", out)
        self.assertIn("| dynptr | -10 | -10 | -10 | 1 of 1 |", out)

    def test_main_exit_status(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt") as f:
            f.write("\n".join(GOOD) + "\n")
            f.flush()
            self.assertEqual(summarize.main([f.name]), 0)
        with tempfile.NamedTemporaryFile("w", suffix=".txt") as f:
            f.write("\n".join(GOOD[:-2] + [row(2, "dynptr", t=1600, invalid=1)]) + "\n")
            f.flush()
            self.assertEqual(summarize.main([f.name]), 1)
        with tempfile.NamedTemporaryFile("w", suffix=".txt") as f:
            f.write("row round=x\n")
            f.flush()
            self.assertEqual(summarize.main([f.name]), 1)

    def test_other_lines_counted_not_parsed(self):
        self.assertEqual(summarize.parse(["6.18.44", "[exit 0]"])["other"], 2)


if __name__ == "__main__":
    unittest.main()
