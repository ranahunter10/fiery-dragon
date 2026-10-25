# SPDX-License-Identifier: MIT
"""Tests for wheels.py, with no network. Run: python3 -m unittest -v bench/probes/p11_wheels/test_wheels.py"""

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wheels as W  # noqa: E402

TAGS = W.emulated_tags("3.14.4", 42)
RANK = {t: i for i, t in enumerate(TAGS)}


def whl(name, req=None, yanked=False):
    return {"filename": name, "packagetype": "bdist_wheel", "requires_python": req, "yanked": yanked}


def sdist(name):
    return {"filename": name, "packagetype": "sdist", "requires_python": None, "yanked": False}


def pypi(latest, releases):
    return {"info": {"version": latest}, "last_serial": 7, "releases": releases}


class TagsTest(unittest.TestCase):
    def test_most_preferred_first_and_bounds(self):
        names = [str(t) for t in TAGS]
        self.assertEqual(names[0], "cp314-cp314-manylinux_2_42_x86_64")
        self.assertIn("cp312-abi3-manylinux_2_28_x86_64", names)       # stable ABI from an older Python
        self.assertIn("cp314-cp314-manylinux2014_x86_64", names)       # legacy alias of 2_17
        self.assertIn("py3-none-any", names)
        self.assertNotIn("cp314-cp314-manylinux_2_43_x86_64", names)   # newer glibc than the target
        self.assertNotIn("cp313-cp313-manylinux_2_28_x86_64", names)   # another CPython's ABI
        self.assertNotIn("cp314-cp314t-manylinux_2_28_x86_64", names)  # free-threaded build


class ClassifyTest(unittest.TestCase):
    def c(self, f):
        return W.classify_file(f, RANK, "3.14.4")

    def test_each_skip_reason(self):
        self.assertEqual(self.c(whl("a-1-cp314-cp314-manylinux_2_28_x86_64.whl", yanked=True))[0], "yanked")
        self.assertEqual(self.c(sdist("a-1.tar.gz"))[0], "not_wheel")
        self.assertEqual(self.c(whl("not-a-wheel-name.whl"))[0], "bad_filename")
        self.assertEqual(self.c(whl("a-1-py3-none-any.whl", req=">=3.9,<3.14"))[0], "requires_python")
        self.assertEqual(self.c(whl("a-1-py3-none-any.whl", req=">=3.9,<=3.14"))[0], "requires_python")  # 3.14.4 > 3.14
        self.assertEqual(self.c(whl("a-1-cp313-cp313-manylinux_2_28_x86_64.whl"))[0], "no_matching_tag")
        self.assertEqual(self.c(whl("a-1-cp314-cp314-win_amd64.whl"))[0], "no_matching_tag")

    def test_ok_returns_rank(self):
        reason, r = self.c(whl("a-1-cp314-cp314-manylinux_2_28_x86_64.whl", req=">=3.10"))
        self.assertEqual(reason, "ok")
        self.assertEqual(r, RANK[next(t for t in TAGS if str(t) == "cp314-cp314-manylinux_2_28_x86_64")])

    def test_compressed_tag_set_matches_on_any_member(self):
        reason, _ = self.c(whl("a-1-cp314-cp314-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"))
        self.assertEqual(reason, "ok")


class AssessTest(unittest.TestCase):
    def a(self, data):
        return W.assess("pkg", data, TAGS, "3.14.4")

    def test_latest_binary_prefers_specific_over_generic(self):
        r = self.a(pypi("2.0", {"2.0": [whl("pkg-2.0-py3-none-any.whl"),
                                        whl("pkg-2.0-cp314-cp314-manylinux_2_28_x86_64.whl"),
                                        whl("pkg-2.0-cp313-cp313-manylinux_2_28_x86_64.whl"),
                                        sdist("pkg-2.0.tar.gz")]}))
        self.assertEqual(r["verdict"], "binary (latest)")
        self.assertEqual(r["latest_best_wheel"], "pkg-2.0-cp314-cp314-manylinux_2_28_x86_64.whl")
        self.assertEqual(r["latest_files"], 4)
        self.assertEqual(r["latest_skipped"]["no_matching_tag"], 1)
        self.assertEqual(r["latest_skipped"]["not_wheel"], 1)
        self.assertTrue(r["latest_has_sdist"])

    def test_latest_source_only_falls_back_to_older_binary(self):
        r = self.a(pypi("2.0", {"2.0": [sdist("pkg-2.0.tar.gz"), whl("pkg-2.0-cp313-cp313-manylinux_2_28_x86_64.whl")],
                                "1.9": [whl("pkg-1.9-cp314-cp314-manylinux_2_28_x86_64.whl")],
                                "1.8": [whl("pkg-1.8-cp314-cp314-manylinux_2_28_x86_64.whl")]}))
        self.assertEqual(r["verdict"], "binary only up to 1.9")
        self.assertIsNone(r["latest_best_wheel"])
        self.assertEqual(r["newest_installable_wheel"], "pkg-1.9-cp314-cp314-manylinux_2_28_x86_64.whl")

    def test_version_order_is_semantic_not_lexical(self):
        r = self.a(pypi("3.0", {"3.0": [sdist("pkg-3.0.tar.gz")],
                                "2.10": [whl("pkg-2.10-py3-none-any.whl")],
                                "2.9": [whl("pkg-2.9-py3-none-any.whl")]}))
        self.assertEqual(r["newest_installable"], "2.10")

    def test_prerelease_newer_than_latest_is_ignored(self):
        r = self.a(pypi("1.0", {"1.0": [sdist("pkg-1.0.tar.gz")],
                                "1.1rc1": [whl("pkg-1.1rc1-py3-none-any.whl")]}))
        self.assertEqual(r["verdict"], "no installable wheel")

    def test_yanked_only_is_not_installable(self):
        r = self.a(pypi("1.0", {"1.0": [whl("pkg-1.0-py3-none-any.whl", yanked=True)]}))
        self.assertEqual(r["verdict"], "no installable wheel")
        self.assertEqual(r["latest_skipped"]["yanked"], 1)


class MainTest(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = W.main(argv)
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_argument_errors(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_main(["--python", "3.14.4", "--out", d + "/x"])[0], 2)
            self.assertEqual(self.run_main(["--python", "3.14", "--glibc", "42", "--out", d + "/x"])[0], 2)
            self.assertEqual(self.run_main(["--extra-index-url", "u", "--out", d + "/x"])[0], 2)

    def test_old_pip_refuses_resolve(self):
        # fetch and resolve are mocked so that a broken guard fails here at once instead of downloading
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(W, "pip_major", return_value=(24, "24.0")), \
                mock.patch.object(W, "fetch", side_effect=OSError("must not fetch")), \
                mock.patch.object(W, "resolve") as res:
            code, _, err = self.run_main(["--resolve", "--out", d + "/x"])
        self.assertEqual(code, 2)
        self.assertIn("555 MB", err)
        res.assert_not_called()

    def test_fetch_error_is_a_row_and_a_failing_exit(self):
        good = pypi("1.0", {"1.0": [whl("pkg-1.0-py3-none-any.whl")]})

        def fake(pkg):
            if pkg == "bad":
                raise OSError("no route")
            return good, {"bytes": 1, "sha256": "x"}

        with tempfile.TemporaryDirectory() as d, mock.patch.object(W, "fetch", side_effect=fake):
            code, out, _ = self.run_main(["good", "bad", "--python", "3.14.4", "--glibc", "42", "--out", d + "/x"])
            self.assertTrue((Path(d) / "x" / "results.json").exists())
        self.assertEqual(code, 2)
        self.assertIn("| bad | ? | **ERROR** OSError: no route", out)
        self.assertIn("| good | 1.0 | binary (latest) |", out)


if __name__ == "__main__":
    unittest.main()
