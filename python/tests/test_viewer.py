# SPDX-License-Identifier: MIT
"""p15.graph.viewer: the story document read back from story.py's text report (the VM evidence of
2026-11-14), the format's checks, and the page. Needs no DuckDB; test_rules.py checks that a live
graph's document (story.doc) and its text read back agree."""

import contextlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

from p15.graph import viewer as V  # noqa: E402

EV = ROOT / "docs/evidence/vm/2026-11-14-demo"
PAGE = ROOT / "docs/demo/storybook-2026-11-14.html"
TITLE = "The demo attack, 14 November 2026"


def report() -> str:
    return (EV / "attack-path.txt").read_text(encoding="utf-8")


def rules() -> str:
    return (EV / "rules.txt").read_text(encoding="utf-8")


def embedded(page: str) -> dict:
    m = re.search(r'<script type="application/json" id="story-data">(.*?)</script>', page, re.S)
    return json.loads(m.group(1))


class EvidenceTest(unittest.TestCase):
    """The recorded demo run: the document holds what the report says, no more and no less."""

    @classmethod
    def setUpClass(cls):
        cls.d = V.from_text(report(), rules())

    def test_counts_match_the_report(self):
        d = self.d
        self.assertEqual(d["counts"], {"shown": 41, "reached": 210, "hidden_noise": 0, "hidden_old": 169})
        self.assertEqual(len(d["nodes"]), 41)
        self.assertEqual((len(d["why"]), len(d["edges"]), len(d["pairs"])), (6, 59, 4))
        self.assertEqual(sum(1 for n in d["nodes"] if n["kind"] == "proc"), 16)   # "the processes, in full"

    def test_start_and_its_command(self):
        st = {n["id"]: n for n in self.d["nodes"]}[self.d["start"]]
        self.assertEqual(st["short"], "proc 7352 sh")
        self.assertIn("nc -w1 127.0.0.1 4444", st["cmd"])
        self.assertEqual(self.d["ancestors"][0], "sudo(7253)")
        self.assertEqual(self.d["ancestors"][-1], "systemd(1)")

    def test_cause_chain_runs_back_to_the_request(self):
        chain = [(w["op"], w["src"]) for w in self.d["why"]]
        self.assertEqual(chain[:4], [("CLONE", "proc 7320 python"), ("RECV", "sock 127.0.0.1:8080 -> 127.0.0.1:57084"),
                                     ("TCP", "sock 127.0.0.1:57084 -> 127.0.0.1:8080"), ("SEND", "proc 7351 curl")])
        self.assertEqual(self.d["why"][0]["dst"], self.d["start"])
        self.assertIsNone(self.d["why"][2]["t"])          # a pairing keeps no time
        for a, b in zip(self.d["why"], self.d["why"][1:]):
            self.assertEqual(b["dst"], a["src"])           # each step's cause is the next step's subject

    def test_an_edge_keeps_its_count_and_bytes(self):
        k = [e for e in self.d["edges"] if e["op"] == "WRITE" and e["dst"] == "file /tmp/.k"]
        self.assertEqual(len(k), 1)
        self.assertEqual((k[0]["src"], k[0]["count"], k[0]["bytes"], k[0]["t"]), ("proc 7355 curl", 1486, 11807104, 1.044))

    def test_alerts_on_the_path_name_their_process(self):
        on = [(a["rule"], a["node"]) for a in self.d["alerts"] if a["on_path"]]
        self.assertEqual(on, [("R4", "proc 7352 sh"), ("R1", "proc 7358 .k"), ("R1", "proc 7363 3 [kworker]"),
                              ("R2", "proc 7363 3 [kworker]"), ("R1", "proc 7364 4 [upd]"), ("R3", "proc 7364 4 [upd]")])

    def test_the_seventh_alert_is_off_the_path(self):
        off = [a for a in self.d["alerts"] if not a["on_path"]]
        self.assertEqual([(a["rule"], a["key"]) for a in off], [("R4", "p:7344:1023144936962")])

    def test_without_rules_only_the_path_alerts(self):
        d = V.from_text(report())
        self.assertEqual(len(d["alerts"]), 6)
        self.assertTrue(all(a["on_path"] for a in d["alerts"]))

    def test_committed_page_is_current(self):
        """docs/demo/storybook-2026-11-14.html is this module's output for the evidence: regenerate it
        with the command in docs/demo/README.md when the template or the parser changes."""
        src = {"kind": "text", "file": "attack-path.txt", "sha256": V.sha256(EV / "attack-path.txt"),
               "rules": {"file": "rules.txt", "sha256": V.sha256(EV / "rules.txt")},
               "manifest": (EV / "manifest.txt").read_text(encoding="utf-8").splitlines()}
        d = V.from_text(report(), rules(), src)
        d["title"] = TITLE
        self.assertEqual(PAGE.read_text(encoding="utf-8"), V.render(d))


class StrictTest(unittest.TestCase):
    """A report the parser does not recognise is an error naming the line, never a shorter story."""

    def lines(self):
        return report().splitlines()

    def assertFailsAt(self, text, line, rules_text=None):
        with self.assertRaises(V.StoryError) as cm:
            V.from_text(text, rules_text)
        self.assertIn(f"line {line}:", str(cm.exception))

    def test_a_strange_line_inside_the_edges(self):
        L = self.lines()
        i = L.index("what it led to, in order (time from the start node's first moment):") + 3
        L.insert(i, "    +0.004s  something else entirely")
        self.assertFailsAt("\n".join(L), i + 1)

    def test_a_missing_section(self):
        L = self.lines()
        i = L.index("the processes, in full:")
        self.assertFailsAt("\n".join(L[:i]), i)      # the report ends where the section should start

    def test_text_after_the_report(self):
        self.assertFailsAt(report() + "\nTraceback (most recent call last):\n", len(self.lines()) + 2)

    def test_cut_short_anywhere(self):
        """A report cut off after any line parses or fails with StoryError, never another exception."""
        L, ok = self.lines(), 0
        for k in range(len(L) + 1):
            try:
                V.from_text("\n".join(L[:k]) + "\n")
                ok += 1
            except V.StoryError:
                pass
        self.assertEqual(ok, 3)   # only the whole report: with its HTML line, without it, without its blank line too

    def test_story_py_trailers_are_known(self):
        V.from_text(report() + "story: /var/tmp/x.json\nstorybook: /var/tmp/x.html\n")

    def test_an_edge_after_the_pairings(self):
        L = self.lines()
        i = max(n for n, x in enumerate(L) if "==TCP==" in x) + 1
        L.insert(i, "    +1.200s  proc 7352 sh  --CLONE-->  proc 7353 getent")
        self.assertFailsAt("\n".join(L), i + 1)

    def test_a_process_no_edge_names(self):
        L = self.lines()
        i = L.index("the processes, in full:") + 1
        L.insert(i, "  proc 1 init (/sbin/init)")
        self.assertFailsAt("\n".join(L), i + 1)

    def test_an_alert_whose_process_is_not_on_the_path(self):
        t = report().replace("ran it as pid 7358", "ran it as pid 9999", 1)
        with self.assertRaisesRegex(V.StoryError, "pid 9999, which is 0 nodes"):
            V.from_text(t)

    def test_rules_output_must_hold_every_path_alert(self):
        r = "\n".join(x for x in rules().splitlines() if not (x.startswith("  +") and "R3 deleted-exec" in x))
        with self.assertRaisesRegex(V.StoryError, "does not list"):
            V.from_text(report(), r)

    def test_rules_output_with_a_strange_line(self):
        with self.assertRaisesRegex(V.StoryError, "rules line 3"):
            V.from_text(report(), rules().replace("  +   6.551s", "  ?   6.551s"))


class ValidateTest(unittest.TestCase):
    def doc(self):
        return V.from_text(report())

    def test_each_check(self):
        cases = {
            "schema": lambda d: d.update(schema="p15.story/0"),
            "is not a node": lambda d: d["edges"][0].update(dst="proc 1 nobody"),
            "not in time order": lambda d: d["edges"].reverse(),
            "counts.shown": lambda d: d["counts"].update(shown=40),
            "twice": lambda d: d["nodes"].append(dict(d["nodes"][0])),
            "missing 'pairs'": lambda d: d.pop("pairs"),
            "start": lambda d: d.update(start="proc 1 nobody"),
        }
        for want, spoil in cases.items():
            with self.subTest(want):
                d = self.doc()
                spoil(d)
                with self.assertRaisesRegex(V.StoryError, re.escape(want)):
                    V.validate(d)


class PageTest(unittest.TestCase):
    def test_the_document_round_trips_through_the_page(self):
        d = V.from_text(report(), rules())
        self.assertEqual(embedded(V.render(d)), d)

    def test_a_label_cannot_close_the_script(self):
        d = V.from_text(report())
        evil = "file /tmp/</script><script>alert(1)</script>&"
        old = d["edges"][-1]["dst"]
        for n in d["nodes"]:
            if n["id"] == old:
                n["label"] = n["short"] = evil
        page = V.render(d)
        self.assertNotIn("<script>alert(1)", page)
        self.assertEqual(page.count("</script>"), V.TEMPLATE.read_text(encoding="utf-8").count("</script>"))
        self.assertEqual(embedded(page), d)

    def test_the_template_has_one_slot(self):
        d = V.from_text(report())
        for tpl in ("<html></html>", f"{V.SLOT}{V.SLOT}"):
            with self.assertRaisesRegex(V.StoryError, "data slots"):
                V.render(d, tpl)

    def test_the_page_fetches_nothing(self):
        tpl = V.TEMPLATE.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"""(src|href)\s*=\s*["']?(https?:)?//""", tpl))
        self.assertNotIn("@import", tpl)
        self.assertNotIn("fetch(", tpl)


class CliTest(unittest.TestCase):
    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = V.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_from_text_writes_the_page_and_the_document(self):
        with tempfile.TemporaryDirectory() as t:
            page, js = Path(t) / "p.html", Path(t) / "s.json"
            rc, out, _ = self.run_main("--from-text", str(EV / "attack-path.txt"), "--rules", str(EV / "rules.txt"),
                                       "-o", str(page), "--json", str(js))
            self.assertEqual(rc, 0)
            self.assertIn("41 nodes, 59 edges, 6 alerts on the path", out)
            d = json.loads(js.read_text())
            self.assertEqual(d["source"]["sha256"], V.sha256(EV / "attack-path.txt"))
            self.assertEqual(embedded(page.read_text()), d)
            page2 = Path(t) / "p2.html"                      # the document written is a valid input
            self.assertEqual(self.run_main(str(js), "-o", str(page2))[0], 0)
            self.assertEqual(page2.read_text(), page.read_text())

    def test_errors(self):
        with tempfile.TemporaryDirectory() as t:
            bad = Path(t) / "bad.txt"
            bad.write_text("not a report\n")
            self.assertEqual(self.run_main("--from-text", str(Path(t) / "none.txt"), "-o", str(Path(t) / "x"))[0], 2)
            rc, _, err = self.run_main("--from-text", str(bad), "-o", str(Path(t) / "x.html"))
            self.assertEqual(rc, 1)
            self.assertIn("line 1:", err)
            self.assertFalse((Path(t) / "x.html").exists())
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                V.main(["-o", str(Path(t) / "x.html")])


class ShortTest(unittest.TestCase):
    def test_short_labels(self):
        self.assertEqual(V.short("proc 7 nc (nc -w1 x)"), "proc 7 nc")
        self.assertEqual(V.short("proc 422 3 (kworker)"), "proc 422 3 [kworker]")
        self.assertEqual(V.short("file /tmp/x"), "file /tmp/x")

    def test_node_kinds(self):
        self.assertEqual(V.node("1", "sock a:1 -> b:2")["kind"], "sock")
        with self.assertRaises(V.StoryError):
            V.node("1", "pipe 3")


if __name__ == "__main__":
    unittest.main()
