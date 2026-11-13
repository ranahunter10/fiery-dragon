# SPDX-License-Identifier: MIT
"""Tests for tools/vm/stalls.py, on the guest's own lines from E-0250 (2026-11-13)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stalls  # noqa: E402

WAKE = 1794538294.709
# E-0250's lines, in journalctl's short-unix form (docs/evidence/vm/2026-11-13-matrix-pr90-default/)
LOG_E0250 = f"""\
{WAKE:.6f} p15-dev kernel: watchdog: BUG: soft lockup - CPU#1 stuck for 379s! [snapd:1062]
{WAKE + 0.0004:.6f} p15-dev kernel: RIP: 0010:_raw_spin_unlock_irqrestore+0x21/0x60
{WAKE + 0.0016:.6f} p15-dev kernel: clocksource: Long readout interval, skipping watchdog check: cs_nsec: 406098549870 wd_nsec: 406098452586
{WAKE + 0.0030:.6f} p15-dev kernel: loop4: detected capacity change from 0 to 8
"""
STEPS = f"""\
idle rc=0 seconds=148.0 start={WAKE - 1100:.3f} end={WAKE - 950:.3f}
soak rc=0 seconds=654.6 start={WAKE - 500:.3f} end={WAKE + 150:.3f}
soak_report rc=0 seconds=0.0 start={WAKE + 151:.3f} end={WAKE + 151.1:.3f}
"""


class Stalls(unittest.TestCase):
    def test_e0250_is_one_stall_of_406_s(self):
        st = stalls.stalls(stalls.signs(LOG_E0250))
        self.assertEqual(len(st), 1)
        self.assertAlmostEqual(st[0]["gap_s"], 406.1, places=1)
        self.assertEqual(st[0]["signs"], ["soft_lockup", "clocksource"])

    def test_only_the_soak_is_touched(self):
        out = stalls.report(LOG_E0250, STEPS)
        self.assertIn("touched soak gap_s=406.1", out)
        self.assertNotIn("touched idle", out)
        self.assertNotIn("touched soak_report", out)
        self.assertTrue(out.endswith("stalls 1\n"))

    def test_a_step_that_ended_inside_the_stall_is_touched(self):
        # the stall ran from WAKE - 406 to WAKE: a step ending 100 s before the wake overlaps it
        sp = f"open_cost rc=0 seconds=10 start={WAKE - 300:.3f} end={WAKE - 100:.3f}\n"
        self.assertIn("touched open_cost", stalls.report(LOG_E0250, sp))

    def test_short_readouts_are_not_stalls(self):
        log = f"{WAKE:.6f} h kernel: clocksource: Long readout interval, skipping watchdog check: cs_nsec: 600000000 wd_nsec: 600000000\n"
        self.assertEqual(stalls.report(log, STEPS), "stalls 0\n")

    def test_rcu_stall_counts_without_a_length(self):
        log = f"{WAKE:.6f} h kernel: rcu: INFO: rcu_preempt self-detected stall on CPU\n"
        st = stalls.stalls(stalls.signs(log))
        self.assertEqual((len(st), st[0]["gap_s"]), (1, 0.0))

    def test_signs_far_apart_are_two_stalls(self):
        log = (f"{WAKE:.6f} h kernel: watchdog: BUG: soft lockup - CPU#0 stuck for 30s! [x:1]\n"
               f"{WAKE + 100:.6f} h kernel: watchdog: BUG: soft lockup - CPU#2 stuck for 25s! [y:2]\n")
        self.assertIn("stalls 2", stalls.report(log, ""))

    def test_lines_without_a_time_and_old_steps_lines_are_skipped(self):
        log = "-- No entries --\n" + LOG_E0250
        self.assertIn("stalls 1", stalls.report(log, "it_p15d rc=0 seconds=132.6\n"))


if __name__ == "__main__":
    unittest.main()
