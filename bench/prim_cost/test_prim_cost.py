# SPDX-License-Identifier: MIT
"""Tests for the prim_cost report and the per-program statistics (bench/prim_cost)."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import prog_stats as PS  # noqa: E402
import summarize as SUM  # noqa: E402

COST = {"empty": 5.0, "ring_reserve_submit": 70.0, "ring_reserve_discard": 45.0, "ring_output": 50.0, "hash_lookup": 25.0,
        "hash_update_delete": 180.0, "counter": 9.0, "percpu_copy": 30.0, "ktime": 40.0}


def text(rounds=7, n=1000, ok=None, ring="ring sent=14000 consumed=14000 ok", drop=None, extra=""):
    L = ["config cpu=2 rounds=%d iters=%d" % (rounds, n)]
    for r in range(-1, rounds):
        for p, c in COST.items():
            if drop == (r, p):
                continue
            good = n if ok is None or ok[0] != (r, p) else ok[1]
            L.append(f"row round={r} prim={p} n={n} ns={round(n * (c + (0 if p == 'empty' else 5.0) + 0.5 * r))} ok={good}")
    return "\n".join(L + ([ring] if ring else [])) + "\n" + extra


class Report(unittest.TestCase):
    def test_the_empty_loop_is_subtracted_round_by_round(self):
        out, rc = SUM.report(text())
        self.assertEqual(rc, 0)
        self.assertIn("7 rounds. The empty loop: 6.5 ns per iteration", out)       # 5 + 0.5 * 3
        self.assertIn("| ring_reserve_submit | 70.0 | 70.0 to 70.0 |", out)        # the drift of 0.5 ns a round cancels
        self.assertIn("| hash_update_delete | 180.0 |", out)
        self.assertIn("| counter | 9.0 |", out)
        self.assertEqual(out.count("\n| "), 1 + len(SUM.PRIMS))                     # the header row and one per primitive

    def test_a_failed_check_stops_the_report(self):
        for t, why in ((text(ok=((2, "hash_lookup"), 999)), "999 of 1000 iterations"),
                       (text(ok=((-1, "ring_output"), 0)), "round -1 ring_output: 0 of 1000"),       # the warm-up counts
                       (text(ring="ring sent=14000 consumed=13999 FAIL"), "handed over 13999"),
                       (text(ring="ring sent=14000 consumed=13999 ok"), "handed over 13999"),
                       (text(ring="ring sent=14000 consumed=14000 FAIL"), "handed over 14000"),
                       (text(ring=""), "did not finish")):
            out, rc = SUM.report(t)
            self.assertEqual(rc, 1)
            self.assertIn(why, out)
            self.assertNotIn("ns per iteration (median)", out)

    def test_malformed_input_is_refused(self):
        for t, why in ((text(drop=(3, "ktime")), "round 3: missing ktime"),
                       (text(drop=(3, "empty")), "round 3: missing empty"),
                       (text(extra="row round=1 prim=counter n=5 ns=5 ok=5\n"), "twice"),
                       (text(extra="row round=1 prim=zzz n=5 ns=5 ok=5\n"), "unknown primitive"),
                       (text(extra="row nonsense\n"), "unparsed row"),
                       (text(extra="ring nonsense\n"), "unparsed ring"),
                       (text(extra="hello\n"), "unknown line"),
                       ("config x\nring sent=0 consumed=0 ok\n", "no timed rounds")):
            with self.assertRaisesRegex(SUM.ParseError, why):
                SUM.report(t)


class ProgStats(unittest.TestCase):
    A = [{"id": 5, "type": "tracing", "name": "file_open_path", "run_time_ns": 1000, "run_cnt": 10},
         {"id": 6, "type": "kprobe", "name": "file_free"},
         {"id": 7, "type": "tracepoint", "name": "exec"}]
    B = [{"id": 5, "type": "tracing", "name": "file_open_path", "run_time_ns": 61000, "run_cnt": 110},
         {"id": 6, "type": "kprobe", "name": "file_free", "run_time_ns": 20000, "run_cnt": 100},
         {"id": 7, "type": "tracepoint", "name": "exec"},
         {"id": 9, "type": "kprobe", "name": "late", "run_time_ns": 50, "run_cnt": 1}]

    def test_delta_and_table(self):
        d = PS.delta(PS.parse_progs(json.dumps(self.A)), PS.parse_progs(json.dumps(self.B)))
        self.assertEqual([(r["name"], r["runs"], r["ns"]) for r in d],
                         [("file_open_path", 100, 60000), ("file_free", 100, 20000), ("late", 1, 50)])   # by time; idle ones left out
        t = PS.table(d, 50)
        self.assertIn("| file_open_path | tracing | 100 | 0.06 | 600.0 | 2.000 | 1200.0 |", t)
        self.assertIn("| file_free | kprobe | 100 | 0.02 | 200.0 | 2.000 | 400.0 |", t)
        self.assertIn("| **all** | | 201 | 0.08 | | 4.020 | 1601.0 |", t)
        self.assertIn("| file_open_path | tracing | 100 | 0.06 | 600.0 |\n", PS.table(d, None) + "\n")

    def test_bad_input(self):
        with self.assertRaisesRegex(PS.StatsError, "not JSON"):
            PS.parse_progs("Error: nope")
        with self.assertRaisesRegex(PS.StatsError, "not a list"):
            PS.parse_progs("{}")
        with self.assertRaisesRegex(PS.StatsError, "without an id"):
            PS.parse_progs('[{"name": "x"}]')
        with self.assertRaisesRegex(PS.StatsError, "went backwards"):
            PS.delta(PS.parse_progs(json.dumps(self.B)), PS.parse_progs(json.dumps(self.A[:1])))


if __name__ == "__main__":
    unittest.main()
