# SPDX-License-Identifier: MIT
"""Tests for summarize.py on synthetic rw_hook_cost output with a known answer."""

import math
import random
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import summarize as S  # noqa: E402

FACS = {"fentry": 1.1, "fexit": 1.2, "kpm": 1.3, "pair": 1.8, "session": 1.5}


def synth(rounds=12, facs=None, seed=1, bad_hits=None, orphan=None, drop=None, coexist="ok", rmiss=0,
          arms=None):
    """Rows whose per-read costs are none * factor, with small paired noise."""
    facs = dict(FACS if facs is None else facs)
    rnd = random.Random(seed)
    n = 100000
    lines = ["rw_hook_cost: synthetic"]
    if coexist:
        got = 500 if coexist == "ok" else 499
        lines.append(f"coexist function=security_file_open opens=500 session={got} fentry=500 {coexist}")
    for r in [-1] + list(range(rounds)):
        if r >= 0:
            lines.append(f"nullsys round={r} calls=1000000 total_ns=90000000")
        u = 300.0 * math.exp(rnd.gauss(0, 0.1))
        all_facs = {"none": 1.0, "none2": math.exp(rnd.gauss(0, 0.001)), **facs}
        for arm, f in all_facs.items():
            if arms is not None and arm not in arms:
                continue
            if drop == (r, arm):
                continue
            per = u * f * (math.exp(rnd.gauss(0, 0.0005)) if arm != "none" else 1)
            hits = 0 if arm in ("none", "none2") else n
            if bad_hits == (r, arm):
                hits -= 1
            orph = 1 if orphan == (r, arm) else 0
            rm = rmiss if arm == "fexit" else 0
            lines.append(f"row round={r} event=read arm={arm} n={n} cpu_ns={int(per * n)} "
                         f"wall_ns={int(per * n * 1.01)} hits={hits} orphan={orph} rmiss={rm} lmiss=0")
    return "\n".join(lines) + "\n"


def overhead(section: str, name: str) -> float:
    m = re.search(re.escape(f"**{name}:** overhead ") + r"([+-]\d+\.\d+) %", section)
    if not m:
        raise AssertionError(f"no quoted overhead for {name!r} in:\n{section}")
    return float(m[1])


class SummarizeTest(unittest.TestCase):
    def test_known_effects(self):
        text, rc = S.report(synth())
        self.assertEqual(rc, 0)
        sec = text.split("## cpu time per read")[1].split("##")[0]
        self.assertAlmostEqual(overhead(sec, "fexit against none"), 20.0, delta=0.3)
        self.assertAlmostEqual(overhead(sec, "session against none"), 50.0, delta=0.3)
        self.assertAlmostEqual(overhead(sec, "session against pair"), (1.5 / 1.8 - 1) * 100, delta=0.3)
        self.assertAlmostEqual(overhead(sec, "session against fexit"), 25.0, delta=0.3)
        added = float(re.search(r"session against none:.*?\n  - added per read ([\d.]+) ns", sec, re.S)[1])
        self.assertAlmostEqual(added, 0.5 * 300, delta=20)               # per read, not per arm
        self.assertIn("security_file_open: 500 opens, session 500, fentry 500: ok", text)

    def test_no_effect_not_resolved(self):
        text, rc = S.report(synth(facs={a: 1.0 for a in FACS}))
        self.assertEqual(rc, 0)
        sec = text.split("## cpu time per read")[1].split("##")[0]
        self.assertIn("**session against none:** not resolved", sec)

    def test_warmup_not_timed(self):
        text, _ = S.report(synth(rounds=12))
        self.assertIn("(primary; 12 rounds)", text)

    def test_floor_carried_onto_second_arm(self):
        # session and pair cost the same: the verdict must be "not resolved" against an A/A floor
        # near zero (the floor carried onto pair), not against none2/pair (about -44 %)
        text, _ = S.report(synth(facs={**FACS, "session": 1.8}))
        sec = text.split("## cpu time per read")[1].split("##")[0]
        m = re.search(r"\*\*session against pair:\*\* not resolved on this host "
                      r"\(A/A interval ([+-][\d.]+) % to ([+-][\d.]+) %\)", sec)
        self.assertIsNotNone(m, sec)
        self.assertLess(abs(float(m[1])), 1.0)
        self.assertLess(abs(float(m[2])), 1.0)

    def test_books(self):
        for kw, frag in ((dict(bad_hits=(3, "session")), "round 3 session: 99999 hits"),
                         (dict(orphan=(2, "pair")), "round 2 pair: 1 returns without their entry"),
                         (dict(coexist="FAIL"), "coexist on security_file_open"),
                         (dict(bad_hits=(-1, "kpm")), "round -1 kpm")):
            text, rc = S.report(synth(**kw))
            self.assertEqual(rc, 1, kw)
            self.assertIn(frag, text)

    def test_arm_that_did_not_run(self):
        # what the harness prints when an arm fails to attach: no time, no hits
        text = re.sub(r"arm=pair n=100000 cpu_ns=\d+ wall_ns=\d+ hits=\d+",
                      "arm=pair n=100000 cpu_ns=0 wall_ns=0 hits=0", synth())
        out, rc = S.report(text)
        self.assertEqual(rc, 1)
        self.assertIn("round 0 pair: no time measured", out)
        self.assertNotIn("## cpu time per read", out)

    def test_skip_counters_summed(self):
        text, _ = S.report(synth(rmiss=2, rounds=5))
        self.assertIn("| fexit | 12 | 0 |", text)                      # 6 rows (warm-up included) x 2

    def test_no_trampoline_run(self):
        text, rc = S.report(synth(coexist=None, arms=("none", "none2", "kpm", "pair", "session"),
                                  facs={"kpm": 1.3, "pair": 1.8, "session": 1.5}))
        self.assertEqual(rc, 0)
        self.assertNotIn("fexit against none", text)
        self.assertIn("session against pair", text)
        self.assertIn("- not run", text)

    def test_missing_arm_and_garbage(self):
        with self.assertRaises(S.ParseError):
            S.report(synth(drop=(4, "pair")))
        with self.assertRaises(S.ParseError):
            S.report("row round=0 event=read arm=none n=x\nnullsys round=0 calls=1 total_ns=1\n")
        with self.assertRaises(S.ParseError):
            S.report("row round=0 event=read arm=bogus n=1 cpu_ns=1 wall_ns=1 hits=0 orphan=0 rmiss=0 lmiss=0\n")


if __name__ == "__main__":
    unittest.main()
