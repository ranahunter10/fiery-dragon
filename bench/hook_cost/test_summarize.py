# SPDX-License-Identifier: MIT
"""Tests for summarize.py on synthetic hook_cost output with a known answer."""

import math
import random
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import summarize as S  # noqa: E402


def synth(rounds=12, tp=1.0, btf=1.0, spine=1.0, seed=1, bad_hits=False, drop=None):
    """Rows whose per-event costs are none * factor, with small paired noise."""
    rnd = random.Random(seed)
    lines = ["hook_cost: synthetic"]
    for r in [-1] + list(range(rounds)):
        if r >= 0:
            lines.append(f"nullsys round={r} calls=1000000 total_ns=90000000")
        for ev, n, base in (("rename", 200000, 120.0), ("exec", 300, 400000.0)):
            u = base * math.exp(rnd.gauss(0, 0.1))
            facs = {"none": 1.0, "none2": math.exp(rnd.gauss(0, 0.001)), "tp": tp, "btf": btf}
            if ev == "exec":
                facs["spine"] = spine
            for arm, f in facs.items():
                if drop == (r, ev, arm):
                    continue
                per = u * f * (math.exp(rnd.gauss(0, 0.0005)) if arm not in ("none",) else 1)
                hits = 0 if arm in ("none", "none2") else n
                if bad_hits and (r, ev, arm) == (3, "rename", "tp"):
                    hits -= 1
                lines.append(f"row round={r} event={ev} arm={arm} n={n} cpu_ns={int(per * n)} "
                             f"wall_ns={int(per * n * 1.01)} hits={hits}")
    return "\n".join(lines) + "\n"


def overhead(section: str, name: str) -> float:
    m = re.search(re.escape(f"**{name}:** overhead ") + r"([+-]\d+\.\d+) %", section)
    if not m:
        raise AssertionError(f"no quoted overhead for {name!r} in:\n{section}")
    return float(m[1])


class SummarizeTest(unittest.TestCase):
    def test_known_effects(self):
        text, rc = S.report(synth(tp=1.25, btf=1.10, spine=1.02))
        self.assertEqual(rc, 0)
        sec = text.split("## rename, cpu time")[1].split("##")[0]
        self.assertAlmostEqual(overhead(sec, "tp against none"), 25.0, delta=0.2)
        self.assertAlmostEqual(overhead(sec, "btf against none"), 10.0, delta=0.2)
        self.assertAlmostEqual(overhead(sec, "tp against btf (the ADR-0020 question)"), 13.64, delta=0.2)  # 1.25/1.10
        self.assertIn("null syscalls", sec)
        added = float(re.search(r"tp against none:.*?\n  - added per event ([\d.]+) ns", sec, re.S)[1])
        self.assertAlmostEqual(added, 0.25 * 120, delta=6)                # per event, not per arm
        exec_sec = text.split("## exec, cpu time")[1].split("##")[0]
        self.assertAlmostEqual(overhead(exec_sec, "spine EXEC (shipped) against none"), 2.0, delta=0.2)

    def test_no_effect_not_resolved(self):
        text, rc = S.report(synth())
        self.assertEqual(rc, 0)
        self.assertIn("tp against btf (the ADR-0020 question):** not resolved on this host", text)

    def test_books_that_do_not_close_fail(self):
        text, rc = S.report(synth(bad_hits=True))
        self.assertEqual(rc, 1)
        self.assertIn("round 3 rename/tp: 199999 hits, expected 200000", text)

    def test_warmup_rows_are_checked_not_used(self):
        rows, _, bad = S.parse(synth(rounds=3))
        self.assertNotIn(("rename", -1), rows)
        self.assertEqual(bad, [])

    def test_missing_arm_is_an_error(self):
        with self.assertRaises(S.ParseError):
            S.report(synth(drop=(2, "exec", "btf")))

    def test_unparsed_row_is_an_error(self):
        with self.assertRaises(S.ParseError):
            S.parse("row round=0 event=rename arm=tp n=10 cpu_ns=x wall_ns=1 hits=10\n")

    def test_main_exit_codes(self, ):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ok, bad = Path(d, "ok.txt"), Path(d, "bad.txt")
            ok.write_text(synth())
            bad.write_text(synth(bad_hits=True))
            self.assertEqual(S.main(["s", str(ok)]), 0)
            self.assertEqual(S.main(["s", str(bad)]), 1)
            self.assertEqual(S.main(["s"]), 2)


if __name__ == "__main__":
    unittest.main()
