# SPDX-License-Identifier: MIT
"""Tests for bench/flow_cost/summarize.py on synthetic flow_cost output with a known answer."""

import math
import random
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import summarize as S  # noqa: E402

FACS = {"session": 1.5, "ts": 1.6, "count": 1.7, "end_rec": 2.0, "ts_rec": 2.1}


def synth(rounds=12, seed=1, check="ok", break_=None, drop=None):
    """Rows whose per-read costs are none * factor, with small paired noise. break_ = (round, arm,
    field, value) puts a wrong value in one row."""
    rnd = random.Random(seed)
    n = 100000
    lines = ["flow_cost: synthetic"]
    if check:
        out = 0 if check == "ok" else 3
        lines.append(f"check reads=2000 flows=2000 outside={out} refused=0 ts_lost=0 create_failed=0 {check}")
    for r in [-1] + list(range(rounds)):
        if r >= 0:
            lines.append(f"nullsys round={r} calls=1000000 total_ns=90000000")
        u = 300.0 * math.exp(rnd.gauss(0, 0.1))
        for arm, f in {"none": 1.0, "none2": math.exp(rnd.gauss(0, 0.001)), **FACS}.items():
            if drop == (r, arm):
                continue
            per = u * f * (math.exp(rnd.gauss(0, 0.0005)) if arm != "none" else 1)
            v = {"hits": 0 if arm in S.UNTRACED else n, "lost": 0, "drained": n if arm in S.RECORDS else 0,
                 "refused": 0, "rmiss": 0}
            if break_ and break_[:2] == (r, arm):
                v[break_[2]] = break_[3]
            lines.append(f"row round={r} event=read arm={arm} n={n} cpu_ns={int(per * n)} wall_ns={int(per * n * 1.01)} "
                         f"hits={v['hits']} lost={v['lost']} drained={v['drained']} refused={v['refused']} "
                         f"rmiss={v['rmiss']} lmiss=0")
    lines.append("flow_cost: ok")
    return "\n".join(lines)


def added(text: str, name: str) -> float:
    m = re.search(rf"\*\*{re.escape(name)}:\*\*.*\n  - added per read (-?[\d,.]+) ns", text)
    assert m, name
    return float(m[1].replace(",", ""))


class Report(unittest.TestCase):
    def test_known_answer(self):
        text, rc = S.report(synth())
        self.assertEqual(rc, 0)
        # the medians of none are ~300 ns; the factors give the added costs
        self.assertAlmostEqual(added(text, "ts against session"), 30, delta=6)
        self.assertAlmostEqual(added(text, "ts_rec against end_rec"), 30, delta=6)
        self.assertAlmostEqual(added(text, "count against ts"), 30, delta=6)      # 1.7 against 1.6 of 300 ns
        self.assertAlmostEqual(added(text, "end_rec against session"), 150, delta=25)
        self.assertAlmostEqual(added(text, "session against none"), 150, delta=25)
        self.assertIn("## cpu time per read (primary; 12 rounds)", text)
        self.assertIn("## wall time per read (secondary; 12 rounds)", text)
        self.assertIn("- 2000 reads, 2000 FLOWs, 0 outside their read, 0 lost, 0 creations failed: ok", text)

    def test_every_book(self):
        for field, value, words in (("hits", 99999, "hits, expected"), ("lost", 1, "lost (no cookie"),
                                    ("refused", 1, "refused 1 FLOW"), ("drained", 5, "FLOW records drained")):
            with self.subTest(field=field):
                text, rc = S.report(synth(break_=(3, "ts_rec", field, value)))
                self.assertEqual(rc, 1)
                self.assertIn(words, text)
                self.assertNotIn("## cpu time", text)          # no timings over a broken book
        text, rc = S.report(synth(break_=(3, "none", "hits", 4)))
        self.assertEqual(rc, 1)
        text, rc = S.report(synth(break_=(3, "session", "drained", 1)))   # a record from a record-less arm
        self.assertEqual(rc, 1)

    def test_check_pass(self):
        text, rc = S.report(synth(check="FAIL"))
        self.assertEqual(rc, 1)
        self.assertIn("3 outside their read", text)
        ok = "check reads=2000 flows=2000 outside=0 refused=0 ts_lost=0 create_failed=0 ok"
        for line in (ok.replace("outside=0", "outside=1"), ok.replace("flows=2000", "flows=1999"),
                     ok.replace("ts_lost=0", "ts_lost=2"), ok.replace(" ok", " FAIL")):
            with self.subTest(line=line):            # the numbers and the harness's verdict each count
                _, rc = S.report(synth(check=None) + "\n" + line)
                self.assertEqual(rc, 1)
        self.assertEqual(S.report(synth(check=None) + "\n" + ok)[1], 0)
        text, rc = S.report(synth(check=None))
        self.assertEqual(rc, 1)
        self.assertIn("no check line", text)

    def test_skips_reported(self):
        text, _ = S.report(synth(break_=(2, "ts", "rmiss", 7)))
        self.assertIn("| ts | 7 | 0 |", text)

    def test_parse_errors(self):
        with self.assertRaises(S.ParseError):
            S.report(synth().replace("arm=ts ", "arm=tz ", 1))
        with self.assertRaises(S.ParseError):
            S.report(synth() + "\nrow round=1 garbage")
        with self.assertRaises(S.ParseError):
            S.report(synth(drop=(4, "ts")))
        with self.assertRaises(S.ParseError):
            S.report("\n".join(x for x in synth().splitlines() if not x.startswith("nullsys")))
        with self.assertRaises(S.ParseError):
            S.report(synth() + "\ncheck reads=1")

    def test_main(self):
        self.assertEqual(S.main(["x"]), 2)


if __name__ == "__main__":
    unittest.main()
