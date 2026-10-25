# SPDX-License-Identifier: MIT
"""Tests for baseline.py and jobs.py. Run: python3 -m unittest -v bench/baseline/test_baseline.py"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import baseline as B  # noqa: E402
import jobs as J  # noqa: E402


def res(job, cfg, vals):
    return [{"round": i + 1, "config": cfg, "job": job, "value": v} for i, v in enumerate(vals)]


class OrderTest(unittest.TestCase):
    def test_counterbalanced(self):
        self.assertEqual(B.round_order(1, True), ["none", "traced"])
        self.assertEqual(B.round_order(2, True), ["traced", "none"])
        self.assertEqual(B.round_order(3, True), ["none", "traced"])

    def test_untraced_only(self):
        self.assertEqual(B.round_order(2, False), ["none"])


class AggregateTest(unittest.TestCase):
    def test_mean_sd_cv_and_slowdown_for_time(self):
        rows = B.aggregate(res("find-serial", "none", [2.0, 2.0, 2.0]) + res("find-serial", "traced", [2.4, 2.6, 2.5]))
        none = next(r for r in rows if r["config"] == "none")
        traced = next(r for r in rows if r["config"] == "traced")
        self.assertAlmostEqual(none["mean"], 2.0)
        self.assertAlmostEqual(none["cv_pct"], 0.0)
        self.assertAlmostEqual(traced["mean"], 2.5)
        self.assertAlmostEqual(traced["sd"], 0.1)
        self.assertAlmostEqual(traced["cv_pct"], 4.0)
        self.assertAlmostEqual(traced["tracing_slowdown_pct"], 25.0)   # 2.5 s vs 2.0 s

    def test_slowdown_for_throughput_is_also_positive_when_slower(self):
        rows = B.aggregate(res("churn", "none", [1000.0, 1000.0]) + res("churn", "traced", [800.0, 800.0]))
        self.assertAlmostEqual(rows[0]["tracing_slowdown_pct"], 25.0)  # 1000/800 - 1

    def test_failed_values_excluded_and_counted_out(self):
        rows = B.aggregate(res("exec", "none", [1.0, None, 3.0]))
        self.assertEqual(rows[0]["n"], 2)
        self.assertAlmostEqual(rows[0]["mean"], 2.0)

    def test_no_slowdown_without_both_configs(self):
        rows = B.aggregate(res("exec", "none", [1.0, 1.0]))
        self.assertNotIn("tracing_slowdown_pct", rows[0])


class RenderTest(unittest.TestCase):
    CONDS = {"utc_start": "t", "kernel": "7.0", "bpftrace": "bpftrace v0.25.0", "git_commit": "0" * 40, "git_dirty": False,
             "cpus": 4, "mem_total_kb": 1, "hypervisor_vendor": "KVM", "virt": "oracle", "swap_before": "none",
             "host_note": "n", "snapshot": "s"}

    def test_unstable_measurement_flagged_and_slowdown_not_quotable(self):
        rows = B.aggregate(res("churn", "none", [50000.0, 14000.0]) + res("churn", "traced", [20000.0, 22000.0]))
        md = B.render(self.CONDS, rows, "x")
        self.assertIn("⚠ not quotable", md)

    def test_stable_measurement_not_flagged(self):
        rows = B.aggregate(res("exec", "none", [2.0, 2.02]) + res("exec", "traced", [2.2, 2.21]))
        md = B.render(self.CONDS, rows, "x")
        self.assertNotIn("⚠ not quotable", md)
        self.assertIn("+10 %", md)


class WarmupTest(unittest.TestCase):
    def test_dry_run_states_the_warmup(self):
        import contextlib, io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            B.main(["--label", "x", "--rounds", "1", "--dry-run"])
        self.assertIn("untimed warm-up run, then timed run", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            B.main(["--label", "x", "--rounds", "1", "--dry-run", "--no-warmup"])
        self.assertIn("timed run only", out.getvalue())

    def test_report_states_warmup(self):
        conds = dict(RenderTest.CONDS, warmup=False)
        self.assertIn("warm-up before each job: NO", B.render(conds, [], "x"))


class ParseTest(unittest.TestCase):
    def test_job_line_is_last_json_with_job_and_value(self):
        log = '{"job": "exec", "value": 9.9}\nwarn\n{"job": "exec", "value": 1.5}\n{"other": 1}\n'
        self.assertEqual(B.parse_job_line(log)["value"], 1.5)   # the last result line wins

    def test_no_job_line(self):
        self.assertIsNone(B.parse_job_line("Traceback...\n"))

    def test_fio_json_with_leading_notice(self):
        text = 'note: both iodepth >= 1 and synchronous I/O engine are selected\n{"jobs": [{"write": {"bw_bytes": 63700000}}]}'
        self.assertAlmostEqual(J.parse_fio_write_mbps(text), 63.7)


class JobsTest(unittest.TestCase):
    def test_every_job_has_unit_and_direction(self):
        for name, (unit, better, desc) in J.JOBS.items():
            with self.subTest(name):
                self.assertIn(better, ("lower", "higher"))
                self.assertTrue(unit and desc)

    def test_exec_job_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertGreater(J.run_job("exec", tmp), 0)

    def test_unknown_job_rejected(self):
        with self.assertRaises(ValueError):
            J.run_job("nope", "/tmp")


class CliTest(unittest.TestCase):
    def test_unknown_job_is_an_error(self):
        import contextlib, io
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            B.main(["--label", "x", "--jobs", "exec,nope", "--dry-run"])


if __name__ == "__main__":
    unittest.main()
