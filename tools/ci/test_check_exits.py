# SPDX-License-Identifier: MIT
"""Tests for tools/ci/check_exits.py (ADR-0019 G2.2)."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_exits  # noqa: E402


def run(src: str) -> tuple[list[str], list[str]]:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.c"
        p.write_text(src)
        return check_exits.scan([p])


class CheckExits(unittest.TestCase):
    def test_each_forbidden_call(self):
        for call in ("exit(1);", "_exit(1);", "_Exit(1);", "quick_exit(1);", "abort();", "exit (1);"):
            bad, ok = run(f"void f(void)\n{{\n\t{call}\n}}\n")
            self.assertEqual((len(bad), len(ok)), (1, 0), call)
            self.assertIn(":3:", bad[0])

    def test_marked_site_allowed(self):
        bad, ok = run("void f(void) { _exit(3); /* exit-ok: test child */ }\n")
        self.assertEqual((bad, len(ok)), ([], 1))

    def test_marker_needs_a_reason(self):
        bad, _ = run("void f(void) { exit(3); /* exit-ok: */ }\n")
        self.assertEqual(len(bad), 1)

    def test_marker_on_another_line_does_not_count(self):
        bad, _ = run("/* exit-ok: elsewhere */\nvoid f(void) { exit(3); }\n")
        self.assertEqual(len(bad), 1)

    def test_names_that_only_contain_exit(self):
        bad, ok = run("void f(void) { on_exit(g, 0); p15_exit_name(1); atexit(g); s.exit_code = 1; my_abort_count++; }\n")
        self.assertEqual((bad, ok), ([], []))

    def test_comments_and_strings_ignored(self):
        src = ('/* calls exit(1) on error,\n   and abort() never */\n'
               'void f(void) { puts("exit(1)"); char c = \'(\'; } // exit(2)\n')
        self.assertEqual(run(src), ([], []))

    def test_lexer_edges_do_not_hide_calls(self):
        cases = {
            "a quote char literal does not open a string": "void f(void) { char q = '\"'; exit(1); }\n",
            "an escaped quote does not close a string": 'void f(void) { puts("\\""); exit(1); }\n',
            "a line comment ends at the newline": "// note\nvoid f(void) { exit(1); }\n",
            "a block comment's closing slash is not code": "int f(void) { int a = 4 /* half *// 2; exit(a); }\n",
        }
        for what, src in cases.items():
            bad, _ = run(src)
            self.assertEqual(len(bad), 1, what)

    def test_code_after_block_comment_still_checked(self):
        bad, _ = run("void f(void) { /* x */ exit(1); }\n")
        self.assertEqual(len(bad), 1)

    def test_line_numbers_survive_multiline_comments(self):
        bad, _ = run("/*\n\n*/\nvoid f(void) { abort(); }\n")
        self.assertIn(":4:", bad[0])

    def test_main_exit_status(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.c").write_text("int main(void) { return 0; }\n")
            self.assertEqual(check_exits.main([d]), 0)
            (Path(d) / "b.h").write_text("static inline void die(void) { exit(1); }\n")
            self.assertEqual(check_exits.main([d]), 1)
            self.assertEqual(check_exits.main([str(Path(d) / "none")]), 2)


if __name__ == "__main__":
    unittest.main()
