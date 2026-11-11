# SPDX-License-Identifier: MIT
"""Tests for the idle-cost harness (bench/idle_cost/run.py, summarize.py)."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run as RN  # noqa: E402
import summarize as S  # noqa: E402

CFG = "config rounds=2 settle=5.0 window=20.0 arms=a:--poll-max-ms 10;b:--poll-max-ms 200\n"


def run_line(arm, rnd, cpu_ms_per_s, polls=99.0, spine=40, bulk=60, ok="ok"):
    return (f"run arm={arm} round={rnd} window_ns=20000000000 cpu_ns={int(cpu_ms_per_s * 20e6)} spine={spine} bulk={bulk} "
            f"polls_per_s={polls} exit=0 end=1 state=0 invariant=1 {ok}\n")


def thread(arm, rnd, name, ms):
    return f"thread arm={arm} round={rnd} name={name} cpu_ns={int(ms * 20e6)}\n"


def good():
    t = CFG
    for rnd in range(2):
        t += thread("a", rnd, "p15d", 12 + rnd) + thread("a", rnd, "p15d-writer", 1) + run_line("a", rnd, 13 + rnd)
        t += thread("b", rnd, "p15d", 1) + thread("b", rnd, "p15d-writer", 0.5) + run_line("b", rnd, 1.5 + rnd * 0.2, 6.0)
    return t


class Summary(unittest.TestCase):
    def test_report(self):
        out, rc = S.report(good())
        self.assertEqual(rc, 0)
        self.assertIn("| a | 13.500 | 13.000 .. 14.000 | 99.0 | 5.0 | 1.00x | no |", out)
        self.assertIn("| b | 1.600 | 1.500 .. 1.700 | 6.0 | 5.0 | 8.44x | yes |", out)
        self.assertIn("| a | 12.500 | 1.000 |", out)
        self.assertIn("| b | 1.000 | 0.500 |", out)

    def test_threads_of_one_name_add_up(self):
        two = good().replace(thread("b", 0, "p15d", 1), thread("b", 0, "p15d", 0.5) + thread("b", 0, "p15d", 0.5))
        self.assertIn("| b | 1.000 | 0.500 |", S.report(two)[0])

    def test_budget_needs_the_dearest_round_under_it(self):
        out, rc = S.report(good(), budget=1.65)
        self.assertIn("| b | 1.600 | 1.500 .. 1.700 | 6.0 | 5.0 | 8.44x | no |", out)

    def test_failures(self):
        out, rc = S.report(good().replace(run_line("b", 1, 1.7, 6.0), run_line("b", 1, 1.7, 6.0, ok="FAIL")))
        self.assertEqual(rc, 1)
        self.assertIn("arm b round 1 failed", out)
        self.assertNotIn("| b |", out)
        out, rc = S.report(good().replace(run_line("a", 1, 14), ""))
        self.assertEqual(rc, 1)
        self.assertIn("arm a: rounds [0], expected 0..1", out)
        out, rc = S.report(good() + "run_error p15d did not start\n")
        self.assertEqual(rc, 1)
        self.assertIn("the harness stopped: p15d did not start", out)

    def test_malformed(self):
        for t, why in ((good() + "hello\n", "unknown line"), (good() + CFG, "second config"),
                       (good().replace(CFG, ""), "no config"), (good() + run_line("a", 0, 1), "round 0 twice"),
                       (good() + run_line("c", 0, 1), "not in the config")):
            with self.assertRaisesRegex(S.ParseError, why):
                S.report(t)


class Harness(unittest.TestCase):
    def test_arm_args(self):
        self.assertEqual(RN.arm_args("max200=--poll-max-ms=200,--no-net"), ("max200", ["--poll-max-ms", "200", "--no-net"]))
        self.assertEqual(RN.arm_args("plain="), ("plain", []))
        for bad in ("=--x", "1a=--x", "a b=--x"):
            with self.assertRaises(RN.RunError):
                RN.arm_args(bad)

    def test_rotation(self):
        self.assertEqual([RN.rotation(["a", "b", "c"], r) for r in range(4)],
                         [["a", "b", "c"], ["b", "c", "a"], ["c", "a", "b"], ["a", "b", "c"]])

    def test_threads_cpu(self):
        with tempfile.TemporaryDirectory() as d:
            for tid, comm, ns in (("10", "p15d", 500), ("11", "p15d-writer", 70)):
                t = Path(d) / "7" / "task" / tid
                t.mkdir(parents=True)
                (t / "comm").write_text(comm + "\n")
                (t / "schedstat").write_text(f"{ns} 3 4\n")
            (Path(d) / "7" / "task" / "12").mkdir()      # a thread gone between the listing and the read
            self.assertEqual(RN.threads_cpu(7, Path(d)), {"p15d/10": 500, "p15d-writer/11": 70})


if __name__ == "__main__":
    unittest.main()
