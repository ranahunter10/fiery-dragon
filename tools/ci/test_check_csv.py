# SPDX-License-Identifier: MIT
"""Tests for check_csv.py: each kind of problem is found, and a well-formed file passes."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_csv  # noqa: E402

LOG_HEAD = "id,date,area,entry,evidence,grade,ref\n"
PAP_HEAD = ("id,type,short_name,title,authors,venue_year,link,used_for,key_claims_used,"
            "read_depth,verified,verified_how,verified_date,notes\n")
PAP_ROW = "R-{n:03d},paper,s,t,a,v,l,u,k,full text,{v},how,2026-11-12,\n"


def write(text: str) -> Path:
    d = Path(tempfile.mkdtemp())
    p = d / "x.csv"
    p.write_text(text)
    return p


class TestLog(unittest.TestCase):
    def run_log(self, body: str) -> list[str]:
        return check_csv.check(write(LOG_HEAD + body), r"E-\d{4}")

    def test_good(self):
        self.assertEqual(self.run_log('E-0001,2026-11-12,a,"x, with ""quotes""\nand a newline",e,MEAS,#1\n'
                                      "E-0002,2026-11-12,a,x,e,MEAS (helper: INF),#2\n"), [])

    def test_short_row(self):
        (p,) = self.run_log("E-0001,2026-11-12,a,x,e,MEAS\n")
        self.assertIn("6 fields, header has 7", p)

    def test_bad_grade_and_date(self):
        ps = self.run_log("E-0001,12-11-2026,a,x,e,GUESS,#1\n")
        self.assertEqual(len(ps), 2)
        self.assertTrue(any("grade 'GUESS'" in p for p in ps))
        self.assertTrue(any("date '12-11-2026'" in p for p in ps))

    def test_order_and_repeat(self):
        ps = self.run_log("E-0002,2026-11-12,a,x,e,MEAS,#1\nE-0001,2026-11-12,a,x,e,MEAS,#1\n"
                          "E-0002,2026-11-12,a,x,e,MEAS,#1\n")
        self.assertTrue(any("E-0001 comes after E-0002" in p for p in ps))
        self.assertTrue(any("E-0002 repeated" in p for p in ps))

    def test_id_form(self):
        (p,) = self.run_log("E-1,2026-11-12,a,x,e,MEAS,#1\n")
        self.assertIn("not of the form", p)


class TestPapers(unittest.TestCase):
    def test_good_and_bad_verified(self):
        good = write(PAP_HEAD + PAP_ROW.format(n=1, v="yes") + PAP_ROW.format(n=2, v="partly"))
        self.assertEqual(check_csv.check(good, r"R-\d{3}"), [])
        bad = write(PAP_HEAD + PAP_ROW.format(n=1, v="maybe"))
        (p,) = check_csv.check(bad, r"R-\d{3}")
        self.assertIn("verified 'maybe'", p)

    def test_the_old_shape(self):
        # the shape R-032 and its neighbours had: verified_how and verified_date in one field
        bad = write(PAP_HEAD + "R-032,blog,s,t,a,v,l,u,k,full text,yes,WebFetch 2026-11-06,\n")
        (p,) = check_csv.check(bad, r"R-\d{3}")
        self.assertIn("13 fields, header has 14", p)


class TestRepo(unittest.TestCase):
    def test_the_repository_passes(self):
        root = Path(__file__).resolve().parents[2]
        self.assertEqual(check_csv.main(root), 0)


if __name__ == "__main__":
    unittest.main()
