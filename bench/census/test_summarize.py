# SPDX-License-Identifier: MIT
"""Tests for summarize.py. Run: python3 -m unittest -v bench/census/test_summarize.py"""

import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import summarize as S  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "testdata", "container-tracepoints-2026-10-25.jsonl")


def T(ns):
    return json.dumps({"type": "printf", "data": f"T {ns}\n"})


def C(**counts):
    return json.dumps({"type": "map", "data": {"@c": counts}})


def B(**payload):
    return json.dumps({"type": "map", "data": {"@b": payload}})


START = json.dumps({"type": "printf", "data": "CENSUS v1 start\n"})
END = json.dumps({"type": "printf", "data": "CENSUS end\n"})
MS = 1_000_000


def run(lines, **kw):
    args = dict(label="t", disk_mbps=63.7, headroom=3.0, sizes={}, default_size=64)
    args.update(kw)
    return S.summarize(S.parse(lines), **args)


def row(s, cls):
    return next(r for r in s["rows"] if r["class"] == cls)


class RealOutputTest(unittest.TestCase):
    """Real bpftrace 0.20.2 output (tracepoint subset of census.bt) from the dev container.

    The run did 30 prctl(PR_SET_NAME), 50 execs of /bin/true and 1000 TCP sends of
    1000 B on loopback, plus whatever else the container did meanwhile.
    """

    def setUp(self):
        with open(FIXTURE, encoding="utf-8") as f:
            self.s = run(f)

    def test_complete_and_no_losses(self):
        self.assertTrue(self.s["complete"])
        self.assertEqual(self.s["lost_events"], 0)
        self.assertEqual(self.s["unknown_classes"], [])

    def test_prctl_renames_counted_apart_from_exec_renames(self):
        self.assertEqual(row(self.s, "rename")["total"], 30)
        self.assertEqual(row(self.s, "rename_exec")["total"], row(self.s, "exec")["total"])
        self.assertGreaterEqual(row(self.s, "exec")["total"], 50)

    def test_sends_and_bytes(self):
        self.assertGreaterEqual(row(self.s, "snd")["total"], 1000)
        self.assertGreaterEqual(row(self.s, "snd")["payload_mb_per_s"] * self.s["duration_s"] * 1e6, 1_000_000)

    def test_rename_exec_not_emitted(self):
        self.assertFalse(row(self.s, "rename_exec")["emitted"])
        self.assertFalse(row(self.s, "sys")["emitted"])


class ParseContractTest(unittest.TestCase):
    def test_deltas_and_rates(self):
        s = run([START, T(100 * MS), C(exec=10), T(200 * MS), C(exec=30), END])
        r = row(s, "exec")
        self.assertEqual(r["total"], 30)
        self.assertAlmostEqual(r["max_per_s"], 200.0)   # 20 in 0.1 s
        self.assertAlmostEqual(r["p50_per_s"], 100.0)   # nearest-rank of [100, 200]
        self.assertAlmostEqual(r["mean_per_s"], 150.0)  # 30 in 0.2 s

    def test_class_appearing_later_counts_zero_before(self):
        s = run([START, T(100 * MS), C(exec=1), T(200 * MS), C(exec=1, snd=5), END])
        self.assertEqual(row(s, "snd")["total"], 5)
        self.assertAlmostEqual(row(s, "snd")["max_per_s"], 50.0)

    def test_empty_map_window_is_zero_not_missing(self):
        # bpftrace prints nothing for an empty map: windows come from T markers only.
        s = run([START, T(100 * MS), T(200 * MS), C(exec=4), END])
        self.assertEqual(s["windows"], 2)
        self.assertAlmostEqual(row(s, "exec")["p50_per_s"], 0.0)

    def test_counter_decrease_is_an_error(self):
        with self.assertRaises(S.CensusError):
            run([START, T(100 * MS), C(exec=10), T(200 * MS), C(exec=9), END])

    def test_key_vanishing_is_an_error(self):
        # Counters are never cleared, so a key cannot disappear from a later print.
        with self.assertRaises(S.CensusError):
            run([START, T(100 * MS), C(exec=10, snd=1), T(200 * MS), C(exec=11), END])

    def test_time_going_backwards_is_an_error(self):
        with self.assertRaises(S.CensusError):
            run([START, T(200 * MS), C(exec=1), T(100 * MS), END])

    def test_map_before_first_marker_is_an_error(self):
        with self.assertRaises(S.CensusError):
            run([START, C(exec=1), T(100 * MS), END])

    def test_bad_json_reports_line_number(self):
        with self.assertRaisesRegex(S.CensusError, "line 3"):
            S.parse([START, T(100 * MS), "{not json"])

    def test_preamble_warnings_accepted_and_reported(self):
        # Exact shape printed by bpftrace 0.25 on the VM (2026-10-25) before the JSON stream.
        pre = ["bench/census/census.bt:43:82-102: WARNING: Return value discarded.",
               'tracepoint:sched:sched_process_exit /comm != "bpftrace"/ { @c["exit"] = count(); }',
               "                                     ~~~~~~~~~~~~~~~~~~~~"]
        attached = json.dumps({"type": "attached_probes", "count": 23, "data": {"probes": 23}})
        s = run(pre + [attached, START, T(100 * MS), C(exec=1), END])
        self.assertEqual(s["preamble_lines"], 3)
        self.assertEqual(s["preamble_warnings"], 1)
        self.assertEqual(s["attached_probes"], 23)
        self.assertIn("3 non-JSON lines before starting", S.to_markdown(s))

    def test_non_json_after_start_is_still_an_error(self):
        with self.assertRaisesRegex(S.CensusError, "line 3"):
            S.parse([START, T(100 * MS), "WARNING: something mid-stream"])

    def test_no_markers_is_an_error(self):
        with self.assertRaises(S.CensusError):
            run([START, END])

    def test_short_final_window_merged(self):
        # END fires 5 ms after the last tick; that window must not create a fake spike.
        s = run([START, T(100 * MS), C(exec=10), T(105 * MS), C(exec=12), END])
        self.assertEqual(s["windows"], 1)
        self.assertAlmostEqual(row(s, "exec")["max_per_s"], 12 / 0.105)


class ReportingTest(unittest.TestCase):
    def test_unknown_class_reported_not_dropped(self):
        s = run([START, T(100 * MS), C(exec=1, mystery=7), END])
        self.assertEqual(s["unknown_classes"], ["mystery"])
        self.assertEqual(row(s, "mystery")["family"], "UNKNOWN")
        self.assertFalse(row(s, "mystery")["emitted"])

    def test_unknown_map_and_line_type_counted(self):
        odd_map = json.dumps({"type": "map", "data": {"@z": {"a": 1}}})
        odd_line = json.dumps({"type": "something_new", "data": {}})
        s = run([START, T(100 * MS), odd_map, odd_line, END])
        self.assertEqual(s["unknown_maps"], {"@z": 1})
        self.assertEqual(s["unknown_line_types"], {"something_new": 1})

    def test_lost_events_counted(self):
        lost = json.dumps({"type": "lost_events", "data": {"events": 12}})
        s = run([START, T(100 * MS), lost, END])
        self.assertEqual(s["lost_events"], 12)

    def test_missing_end_marker_flags_incomplete(self):
        s = run([START, T(100 * MS), C(exec=1)])
        self.assertFalse(s["complete"])
        self.assertIn("INCOMPLETE", S.to_markdown(s))


class BudgetTest(unittest.TestCase):
    def test_budget_math_and_sizes(self):
        # 1000 FILE_FLOW + 10 exec in 0.1 s: 10,000 rec/s * 64 B + 100 exec/s * 256 B = 665,600 B/s
        s = run([START, T(100 * MS), C(rd_reg=1000, exec=10), END], sizes={"exec": 256})
        self.assertAlmostEqual(s["log_bytes_p99_per_s"], 665_600.0)
        self.assertAlmostEqual(s["budget_bytes_per_s"], 63.7e6 / 3)
        self.assertEqual(s["verdict"], "WITHIN BUDGET")

    def test_not_emitted_classes_cost_nothing(self):
        s = run([START, T(100 * MS), C(rd_sock=10_000, rd_chr=10_000, sys=99_999), END])
        self.assertEqual(s["log_bytes_p99_per_s"], 0.0)

    def test_exceeds_budget(self):
        # 40,000 records in 0.1 s at 64 B = 25.6 MB/s > 21.23 MB/s
        s = run([START, T(100 * MS), C(wr_reg=40_000), END])
        self.assertEqual(s["verdict"], "EXCEEDS BUDGET")

    def test_selectivity(self):
        s = run([START, T(100 * MS), C(rd_reg=25, sys=100), END])
        self.assertAlmostEqual(s["selectivity"], 0.25)


class CliTest(unittest.TestCase):
    def test_cli_markdown_on_real_fixture(self):
        out = io.StringIO()
        rc = S.main([FIXTURE, "--label", "fixture"], stdout=out)
        self.assertEqual(rc, 0)
        self.assertIn("Verdict (p99 vs budget): WITHIN BUDGET", out.getvalue())

    def test_cli_json_and_size_override(self):
        out = io.StringIO()
        S.main([FIXTURE, "--format", "json", "--size", "snd=100"], stdout=out)
        s = json.loads(out.getvalue())
        self.assertEqual(s["assumptions"]["record_bytes"]["snd"], 100)

    def test_cli_rejects_bad_size(self):
        err = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):  # keep test output clean
            S.main([FIXTURE, "--size", "snd=big"], stdout=io.StringIO())
        self.assertIn("--size expects CLASS=BYTES", err.getvalue())

    def test_cli_exit_code_2_when_incomplete(self):
        path = os.path.join(HERE, "testdata", "_incomplete.tmp.jsonl")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join([START, T(100 * MS), C(exec=1)]) + "\n")
            self.assertEqual(S.main([path], stdout=io.StringIO()), 2)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
