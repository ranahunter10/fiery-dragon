# SPDX-License-Identifier: MIT
"""Tests for the open_sections report (bench/open_sections/summarize.py)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import summarize as OS  # noqa: E402

COST = {"empty": 15, "open_all": 600, "open_claim": 30, "open_hdr": 40, "open_facts": 30, "open_obj": 40,
        "open_file": 35, "open_dpath": 300, "open_output": 50, "sess_entry": 120, "sess_file": 60,
        "sess_return": 30, "free_all": 250, "free_lookup": 30, "free_ring": 60, "free_delete": 60}


def single(rounds=5, n=1000, host=90.0, drop=None, samples=None, books="ok", extra=""):
    L = [f"config mode=single rounds={rounds} n={n} ncpu=3 dir=/var/tmp/x"]
    for r in range(-1, rounds):
        for s, c in COST.items():
            if drop == (r, s):
                continue
            k = n if samples is None or samples[0] != (r, s) else samples[1]
            L.append(f"row round={r} sec={s} n={k} ns={k * (c + r)}")
        if drop != (r, "host"):
            L.append(f"host round={r} nullsys_n=100000 ns={round(100000 * host)}")
    return "\n".join(L + ([f"books {books} open=1 close=1 other=0"] if books else [])) + "\n" + extra


def contend(missing=0, fentry=2400100, opens=2400000, lost=0, books="ok"):
    return (f"config mode=contend workers=12 n=200000 ncpu=3 dir=/var/tmp/x\n"
            f"contend workers=12 n=200000 opens={opens} fentry_run={fentry} session_entry={fentry + missing} "
            f"session_no_inode=0 missing={missing} open_emitted={fentry} open_lost={lost} missing_lost=0 "
            f"close_emitted=2400200 close_lost=0 rmiss_path={missing} rmiss_session=0 rmiss_free=0 "
            f"lmiss_session=0 lmiss_free=0\nbooks {books} open=1 close=1 other=0\n")


class Single(unittest.TestCase):
    def test_sections_medians_and_net(self):
        out, rc = OS.report(single(), 89.1)
        self.assertEqual(rc, 0)
        self.assertIn("Host speed: a null syscall cost 90.0 ns (median of 5 rounds; 90.0 to 90.0).", out)
        self.assertIn("| open_dpath | 1.000 | 302.0 | 300.0 to 304.0 | 285.0 |", out)   # rounds 0-4: +0..+4
        self.assertIn("| empty | 1.000 | 17.0 | 15.0 to 19.0 |  |", out)
        self.assertIn("- open_all: 602.0 ns, of which its 7 timed sections 539.0; the rest, 63.0 ns,", out)
        self.assertIn("- free_all: 252.0 ns, of which its 3 timed sections 156.0; the rest, 96.0 ns,", out)
        self.assertNotIn("round=-1", out)

    def test_a_slow_host_is_not_quotable(self):
        out, rc = OS.report(single(host=365.0), 89.1)
        self.assertEqual(rc, 0)
        self.assertIn("**SLOW: 4.10 times", out)

    def test_failed_checks_stop_the_report(self):
        for t, why in ((single(samples=((2, "open_all"), 999)), "round 2: open_all has 999 samples for 1000 opens"),
                       (single(samples=((-1, "free_all"), 7)), "round -1: free_all has 7 samples"),
                       (single(books="FAIL"), "the books did not close"),
                       (single(books=None), "the run did not finish")):
            out, rc = OS.report(t)
            self.assertEqual(rc, 1)
            self.assertIn(why, out)
            self.assertNotIn("ns per sample", out)

    def test_a_section_without_samples_is_shown_empty(self):
        out, rc = OS.report(single(samples=((3, "open_claim"), 0)).replace("sec=open_claim n=1000", "sec=open_claim n=0"))
        self.assertEqual(rc, 0)
        self.assertIn("| open_claim | 0 | | | |", out)
        self.assertNotIn("- open_all:", out)

    def test_malformed_input_is_refused(self):
        for t, why in ((single(drop=(1, "open_dpath")), "round 1: missing open_dpath"),
                       (single(drop=(1, "host")), "round 1: no host line"),
                       (single(extra="row round=1 sec=empty n=1 ns=1\n"), "twice"),
                       (single(extra="row round=1 sec=zzz n=1 ns=1\n"), "unknown section"),
                       (single(extra="host round=1 nullsys_n=1 ns=1\n"), "two host lines"),
                       (single(extra="hello\n"), "unknown line"),
                       (single(extra=contend().split("\n")[1] + "\n"), "a contend line in a single run"),
                       ("books ok open=0 close=0 other=0\n", "no config line"),
                       ("config mode=single rounds=1 n=1 ncpu=1 dir=/x\nbooks ok open=0 close=0 other=0\n", "no timed rounds")):
            with self.assertRaisesRegex(OS.ParseError, why):
                OS.report(t)


class Contend(unittest.TestCase):
    def test_skips_are_counted_against_every_open_seen(self):
        out, rc = OS.report(contend(missing=24))
        self.assertEqual(rc, 0)
        self.assertIn("**Path program skipped: 24 opens** (OPEN written with PATH_MISSING), 1.00e-05 of 2,400,124.", out)
        self.assertNotIn("rule of three", out)
        self.assertIn("recursion_misses path 24", out)

    def test_none_skipped_gives_an_upper_bound(self):
        out, rc = OS.report(contend())
        self.assertEqual(rc, 0)
        self.assertIn("**Path program skipped: 0 opens**", out)
        self.assertIn("None skipped: below 1.25e-06 at 95 % (rule of three).", out)

    def test_failed_checks(self):
        out, rc = OS.report(contend(fentry=2399990, missing=5))
        self.assertEqual(rc, 1)
        self.assertIn("fewer opens seen (2399990 path runs + 5 skipped) than the workers made (2400000)", out)
        out, rc = OS.report(contend(books="FAIL"))
        self.assertEqual(rc, 1)
        self.assertNotIn("skipped:", out)
        self.assertEqual(OS.report(contend(fentry=2399995, missing=5))[1], 0)   # exactly the workers' opens

    def test_shape(self):
        with self.assertRaisesRegex(OS.ParseError, "needs one contend line"):
            OS.report("config mode=contend workers=1 n=1 ncpu=1 dir=/x\nbooks ok open=0 close=0 other=0\n")
        with self.assertRaisesRegex(OS.ParseError, "unparsed contend"):
            OS.report("config mode=contend workers=1 n=1 ncpu=1 dir=/x\ncontend workers=1\n")


if __name__ == "__main__":
    unittest.main()
