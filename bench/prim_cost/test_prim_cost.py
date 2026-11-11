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


def text(rounds=7, n=1000, ok=None, ring="ring sent=14000 consumed=14000 ok", drop=None, extra="", host=None):
    L = ["config cpu=2 rounds=%d iters=%d" % (rounds, n)]
    for r in range(-1, rounds):
        for p, c in COST.items():
            if drop == (r, p):
                continue
            good = n if ok is None or ok[0] != (r, p) else ok[1]
            L.append(f"row round={r} prim={p} n={n} ns={round(n * (c + (0 if p == 'empty' else 5.0) + 0.5 * r))} ok={good}")
        if host and r in host:      # host: {round: ns per null syscall}
            L.append(f"host round={r} nullsys_n=1000 ns={round(1000 * host[r])}")
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

    def test_host_speed_is_reported_and_judged(self):
        steady = {r: 88.0 + r for r in range(-1, 7)}                              # 88 to 94 in the timed rounds
        out, rc = SUM.report(text(host=steady), 90.0)
        self.assertEqual(rc, 0)
        self.assertIn("Host speed: a null syscall cost 91.0 ns (median of 7 rounds; 88.0 to 94.0).", out)
        self.assertNotIn("Not quotable", out)
        self.assertIn("| ring_reserve_submit | 70.0 |", out)                      # the costs are still reported
        # the warm-up round's host line is not among the judged ones
        self.assertIn("88.0 to 94.0", SUM.report(text(host={**steady, -1: 900.0}), 90.0)[0])
        out, _ = SUM.report(text(host={**steady, 4: 133.0}), 90.0)                # 133 > 1.5 * 88
        self.assertIn("**UNSTEADY: the dearest round is 1.51 times the cheapest (limit 1.5). Not quotable.**", out)
        self.assertNotIn("UNSTEADY", SUM.report(text(host={**steady, 4: 132.0}), 90.0)[0])   # exactly 1.5: steady
        out, _ = SUM.report(text(host={r: 355.0 for r in range(-1, 7)}), 87.5)    # the run of E-0180
        self.assertIn("**SLOW: 4.06 times the reference of 87.5 ns (limit 1.5). Not quotable.**", out)
        self.assertNotIn("UNSTEADY", out)
        self.assertNotIn("SLOW", SUM.report(text(host={r: 135.0 for r in range(-1, 7)}), 90.0)[0])   # exactly 1.5
        out, _ = SUM.report(text(host=steady))
        self.assertIn("No reference was given", out)
        self.assertNotIn("SLOW:", out)
        out, rc = SUM.report(text())                                              # a file from before E-0180
        self.assertEqual(rc, 0)
        self.assertIn("no host line in this run", out)
        self.assertIn("Not quotable", out)

    def test_bad_host_lines(self):
        steady = {r: 90.0 for r in range(-1, 7)}
        for t, why in ((text(host={r: 90.0 for r in range(-1, 7) if r != 3}), "round 3: no host line"),
                       (text(host=steady, extra="host round=2 nullsys_n=1000 ns=90000\n"), "round 2: two host lines"),
                       (text(host=steady, extra="host nonsense\n"), "unparsed host line")):
            with self.assertRaisesRegex(SUM.ParseError, why):
                SUM.report(t)
        for extra in ("host round=9 nullsys_n=1000 ns=0\n", "host round=9 nullsys_n=0 ns=5\n"):
            out, rc = SUM.report(text(host=steady, extra=extra))
            self.assertEqual(rc, 1)
            self.assertIn("round 9: the host line measured nothing", out)

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

    def test_rounds_summary(self):
        r0 = [{"id": 5, "name": "open", "type": "tracing", "runs": 100, "ns": 60000},
              {"id": 6, "name": "free", "type": "kprobe", "runs": 100, "ns": 20000}]
        r1 = [{"id": 5, "name": "open", "type": "tracing", "runs": 100, "ns": 80000},
              {"id": 6, "name": "free", "type": "kprobe", "runs": 100, "ns": 10000},
              {"id": 9, "name": "rare", "type": "kprobe", "runs": 2, "ns": 300000}]
        r2 = [{"id": 5, "name": "open", "type": "tracing", "runs": 100, "ns": 70000},
              {"id": 6, "name": "free", "type": "kprobe", "runs": 100, "ns": 30000}]
        t = PS.summary([r0, r1, r2], 50).split("\n")
        self.assertEqual(t[2], "| rare | kprobe | 1 | 2 | 150000.0 | 150000.0 to 150000.0 | 0.040 | 6000.0 |")   # by median time
        self.assertEqual(t[3], "| open | tracing | 3 | 300 | 700.0 | 600.0 to 800.0 | 2.000 | 1400.0 |")
        self.assertEqual(t[4], "| free | kprobe | 3 | 300 | 200.0 | 100.0 to 300.0 | 2.000 | 400.0 |")
        self.assertEqual(t[5], "| **all** | | 3 | 602 | | | 4.013 | 2000.0 |")     # totals 80000, 390000, 100000: the median
        self.assertEqual(PS.summary([r0], None).split("\n")[2], "| open | tracing | 1 | 100 | 600.0 | 600.0 to 600.0 |")

    def test_host_speed_from_the_command(self):
        out = "workload pid=1\nrow event=nullsys n=1000000 cpu_ns=89100000 wall_ns=90000000\nrow event=same n=5 cpu_ns=9 wall_ns=9"
        self.assertEqual(PS.host_ns(out), 89.1)
        for bad in ("", "row event=same n=5 cpu_ns=9 wall_ns=9", "row event=nullsys n=0 cpu_ns=5 wall_ns=5",
                    "row event=nullsys n=5 cpu_ns=0 wall_ns=5", " row event=nullsys n=5 cpu_ns=5 wall_ns=5"):
            self.assertIsNone(PS.host_ns(bad))
        self.assertEqual(PS.host_of([out, out]), [89.1, 89.1])
        self.assertEqual(PS.host_of(["", ""]), [])                                 # a command without the row
        with self.assertRaisesRegex(PS.StatsError, "round 1: the command printed no null-syscall row"):
            PS.host_of([out, "", out])

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
