# SPDX-License-Identifier: MIT
"""Tests for the process tree (proctree.py), the port query (net.py) and p15-trace's two
reports (trace.py, report_html.py), on the synthetic run of scenario.py, whose story is known.

    python3 -m unittest -v python/tests/test_trace.py
"""

import contextlib
import io
import re
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scenario as S  # noqa: E402
from p15w_build import R, batch, header, meta_for, rec, write_run  # noqa: E402

from p15 import net as N  # noqa: E402
from p15 import proctree as P  # noqa: E402
from p15 import report_html as H  # noqa: E402
from p15 import trace as T  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.dir = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def ctx(self, **kw):
        return T.load(S.build(self.dir / "run", **kw))


class Tree(Base):
    def test_story(self):
        t = self.ctx().tree
        srv, c1, nc = t.procs[S.SRV], t.procs[S.C1], t.procs[S.NC]
        self.assertEqual((srv.parent, srv.name, srv.cmdline), (S.BASH, "python3", "python3 -m http.server 18077"))
        self.assertEqual(sorted(t.procs[S.BASH].children), sorted([S.SRV, S.C1, S.C2]))
        self.assertEqual([p.pid for p in t.lineage(S.NC)], [640, 630, 600, 500])
        self.assertEqual((c1.exit_code, c1.exit_text()), (0, "exited 0"))
        self.assertEqual(nc.exit_text(), "exited 1")
        self.assertEqual(srv.exit_text(), "still running at the end of the run")
        self.assertTrue(t.procs[S.BASH].origin.startswith("started before the capture"))
        self.assertEqual(srv.images[0].exe, (8, 1, 1600))
        self.assertEqual((t.counts["pre_existing"], t.counts["fork_missing"], t.counts["exit_twice"]), (1, 0, 0))
        self.assertFalse(any(p.in_gap for p in t.procs.values()))

    def test_signal_exit_text(self):
        p = P.Proc((1, 1), exit_ns=5, exit_code=9)
        self.assertEqual(p.exit_text(), "killed by signal 9")
        p.exit_code = 0x80 | 11
        self.assertEqual(p.exit_text(), "killed by signal 11 (core dumped)")

    def test_gap_marks_processes_alive_then(self):
        t = self.ctx(gap=True).tree
        self.assertEqual(len(t.gaps), 1)
        self.assertEqual(t.gaps[0].lost, 3, "2 ring losses + 1 kernel skip (GAP v2)")
        self.assertTrue(t.procs[S.NC].in_gap)
        self.assertTrue(t.procs[S.SRV].in_gap)             # still running: alive in every window
        self.assertFalse(t.procs[S.C1].in_gap)             # exited before the window

    def test_identity_checks_count(self):
        recs = [S.fork(10, S.BASH, (7, 5)), S.fork(11, S.BASH, (7, 5)), S.ex(20, (7, 5)), S.ex(21, (7, 5)),
                S.fork(12, S.BASH, (8, 6), kind=2),
                rec("EXIT", h_ts_ns=13, h_tgid=7, h_start_ns=5, group_dead=0)]
        d = write_run(self.dir / "r2", [header(0, meta_for()) + batch(0, 0, recs)])
        from p15 import wal as W
        t = P.build(W.read_run(d).ring_records(0), run_start_ns=1)
        self.assertEqual((t.counts["fork_twice"], t.counts["exit_twice"], t.counts["fork_thread"],
                          t.counts["exit_thread"]), (1, 1, 1, 1))
        self.assertNotIn((8, 6), t.procs, "a thread is not a process")

    def test_missing_fork_vs_pre_existing(self):
        t = P.build([], run_start_ns=100)
        late, early = t.get((9, 500)), t.get((9, 50))
        self.assertEqual(t.counts["placeholder"], 2)
        self.assertEqual(late.origin, "no spine record in the run")
        t2 = P.build([R.decode(memoryview(S.ex(600, (9, 500))), 0, 0, 0),
                      R.decode(memoryview(S.ex(600, (9, 50))), 0, 0, 1)], run_start_ns=100)
        self.assertTrue(t2.procs[(9, 500)].origin.startswith("started during the run"))
        self.assertTrue(t2.procs[(9, 50)].origin.startswith("started before"))
        self.assertEqual((t2.counts["fork_missing"], t2.counts["pre_existing"]), (1, 1))
        self.assertIsNotNone(early)


class Port(Base):
    def test_18077(self):
        ctx = self.ctx()
        r = N.port_report(ctx.events, 18077)
        self.assertEqual([lst.cookie for lst in r.listeners], [9001])
        self.assertEqual(r.listeners[0].endpoint, "127.0.0.1:18077")
        self.assertEqual([c.accept.cookie for c in r.accepted], [9003, 9005, 9006])
        self.assertTrue(all(c.listener is r.listeners[0] for c in r.accepted), "joined by cookie")
        self.assertEqual([c.connect.proc if c.connect else None for c in r.accepted], [S.C1, S.C2, None])
        self.assertEqual([c.match for c in r.accepted], ["isn", "isn", ""])
        self.assertEqual([e.proc for e in r.outbound], [S.C1, S.C2])
        self.assertEqual((r.refused, r.binds, r.other), ([], [], []))
        self.assertEqual(r.procs, {S.SRV, S.C1, S.C2})
        self.assertEqual((r.counts["client_by_isn"], r.counts["client_by_endpoints"], r.counts["client_not_found"]),
                         (2, 0, 1))
        self.assertEqual((r.counts["isn_mismatch"], r.counts["tcp_without_isn"]), (0, 0))
        self.assertEqual(len(r.events), 7)

    def test_4444_refused(self):
        r = N.port_report(self.ctx().events, 4444)
        self.assertEqual((r.listeners, r.accepted, r.outbound), ([], [], []))
        self.assertEqual([(e.proc, e.ret, e.ret_text()) for e in r.refused], [(S.NC, -111, "ECONNREFUSED (-111)")])

    def test_unknown_port(self):
        r = N.port_report(self.ctx().events, 9)
        self.assertEqual(r.events, [])

    def test_in_progress_is_not_a_failure(self):
        e = N.event(R.decode(memoryview(S.net(5, S.C1, "CONNECT", 1, "127.0.0.1:1", "127.0.0.1:80", ret=-115)), 0, 1, 0))
        self.assertTrue(e.ok)
        self.assertEqual(e.ret_text(), "in progress (non-blocking)")
        r = N.port_report([e], 80)
        self.assertEqual((len(r.outbound), len(r.refused)), (1, 0))

    def test_isn_join_rules(self):
        """ADR-0022: the client ISN joins exactly, beats time, and sets a different connection aside."""
        def ev(t, p, op, ck, lo, re_="0.0.0.0:0", peer=0, isn=None):
            return N.event(R.decode(memoryview(S.net(t, p, op, ck, lo, re_, peer=peer, isn=isn)), 0, 1, t))
        t0 = 10 ** 9
        lst = [ev(1, S.SRV, "LISTEN", 1, "127.0.0.1:80")]

        def acc(isn):
            return ev(t0, S.SRV, "ACCEPT", 9, "127.0.0.1:80", "127.0.0.1:5000", peer=1, isn=isn)

        def con(dt, proc, ck, isn):
            return ev(t0 + dt, proc, "CONNECT", ck, "127.0.0.1:5000", "127.0.0.1:80", isn=isn)
        # a reused port: the nearer connect is the other connection; the ISN picks the right one
        r = N.port_report(lst + [con(10, S.C1, 2, 7), con(1000, S.C2, 3, 5), acc(5)], 80)
        c = r.accepted[0]
        self.assertEqual((c.connect.proc, c.match), (S.C2, "isn"))
        self.assertEqual((r.counts["client_by_isn"], r.counts["isn_mismatch"], r.counts["client_by_endpoints"]), (1, 1, 0))
        # only a different connection on those endpoints: not joined, and counted
        r = N.port_report(lst + [con(10, S.C1, 2, 7), acc(5)], 80)
        self.assertIsNone(r.accepted[0].connect)
        self.assertEqual((r.counts["client_not_found"], r.counts["isn_mismatch"]), (1, 1))
        # either side without an ISN: the window's inference, labelled as such, and the record counted
        for why, a_isn, c_isn in (("connect has none", 5, None), ("accept has none", None, 5)):
            with self.subTest(why):
                r = N.port_report(lst + [con(10, S.C1, 2, c_isn), acc(a_isn)], 80)
                self.assertEqual((r.accepted[0].connect.proc, r.accepted[0].match), (S.C1, "endpoints"))
                self.assertEqual((r.counts["client_by_endpoints"], r.counts["tcp_without_isn"]), (1, 1))
        # 0 is an ISN like any other
        r = N.port_report(lst + [con(10, S.C1, 2, 0), acc(0)], 80)
        self.assertEqual(r.accepted[0].match, "isn")
        # the ISN doesn't widen the window: an equal ISN 6 s away is outside it
        r = N.port_report(lst + [con(6 * 10 ** 9, S.C1, 2, 5), acc(5)], 80)
        self.assertIsNone(r.accepted[0].connect)

    def test_endpoint_join_rules(self):
        def ev(t, p, op, ck, lo, re_="0.0.0.0:0", peer=0, ret=0, netns=None, isn=None):
            raw = S.net(t, p, op, ck, lo, re_, ret=ret, peer=peer, isn=isn)
            e = N.event(R.decode(memoryview(raw), 0, 1, t))
            if netns is not None:
                e.netns = netns
            return e
        w = N.JOIN_WINDOW_NS
        t0 = 2 * w                        # the accept's time, so a connect a full window before it is > 0
        lst = [ev(1, S.SRV, "LISTEN", 1, "127.0.0.1:80")]
        acc = ev(t0, S.SRV, "ACCEPT", 9, "127.0.0.1:80", "127.0.0.1:5000", peer=1)
        cases = {   # each one is inside the window but for the window cases, so only its own rule rejects it
            "more than the window after": [ev(t0 + w + 1, S.C1, "CONNECT", 2, "127.0.0.1:5000", "127.0.0.1:80")],
            "more than the window before": [ev(t0 - w - 1, S.C1, "CONNECT", 2, "127.0.0.1:5000", "127.0.0.1:80")],
            "failed": [ev(t0 - 10, S.C1, "CONNECT", 2, "127.0.0.1:5000", "127.0.0.1:80", ret=-111)],
            "other netns": [ev(t0 - 10, S.C1, "CONNECT", 2, "127.0.0.1:5000", "127.0.0.1:80", netns=7)],
            "other target": [ev(t0 - 10, S.C1, "CONNECT", 2, "127.0.0.1:5000", "127.0.0.1:81")],
        }
        for why, conn in cases.items():
            with self.subTest(why):
                r = N.port_report(lst + conn + [acc], 80)
                self.assertIsNone(r.accepted[0].connect)
                self.assertEqual(r.counts["client_not_found"], 1)
        # E-0092: on the VM the accept returned 12 us before its own connect. Both edges of the window count.
        for why, dt, after in (("12 us after (as on the VM)", 12_185, 1), ("the window's edge after", w, 1),
                               ("the window's edge before", -w, 0), ("at the same time", 0, 0)):
            with self.subTest(why):
                r = N.port_report(lst + [ev(t0 + dt, S.C1, "CONNECT", 2, "127.0.0.1:5000", "127.0.0.1:80"), acc], 80)
                self.assertEqual(r.accepted[0].connect.proc, S.C1)
                self.assertEqual((r.counts["client_by_endpoints"], r.counts["connect_after_accept"]), (1, after))
        # Two candidates: the one nearest in time wins, on whichever side it is.
        for why, near, far, winner in (("nearer before", -30, 40, S.C1), ("nearer after", -40, 30, S.C2),
                                       ("both before", -40, -10, S.C2), ("both after", 10, 40, S.C1)):
            with self.subTest(why):
                two = [ev(t0 + near, S.C1, "CONNECT", 2, "127.0.0.1:5000", "127.0.0.1:80"),
                       ev(t0 + far, S.C2, "CONNECT", 3, "127.0.0.1:5000", "127.0.0.1:80")]
                r = N.port_report(lst + two + [acc], 80)
                self.assertEqual(r.accepted[0].connect.proc, winner)
                self.assertEqual(r.counts["endpoint_ambiguous"], 1)
                self.assertEqual(r.counts["connect_after_accept"], int(r.accepted[0].connect.ts_ns > t0))

    def test_accept_whose_listener_is_not_in_the_run(self):
        acc = N.event(R.decode(memoryview(S.net(5, S.SRV, "ACCEPT", 9, "127.0.0.1:80", "10.1.1.1:3", peer=77)), 0, 1, 0))
        r = N.port_report([acc], 80)
        self.assertEqual((len(r.accepted), r.accepted[0].listener, r.counts["accept_no_listener"]), (1, None, 1))

    def test_udp_bind_and_failed_bind(self):
        b = N.event(R.decode(memoryview(S.net(5, S.SRV, "BIND", 3, "0.0.0.0:53", proto=17)), 0, 1, 0))
        f = N.event(R.decode(memoryview(S.net(6, S.C1, "BIND", 4, "0.0.0.0:53", ret=-98)), 0, 1, 1))
        r = N.port_report([b, f], 53)
        self.assertEqual(([e.cookie for e in r.binds], r.listeners), ([3, 4], []))
        self.assertEqual(f.ret_text(), "EADDRINUSE (-98)")


class TextReport(Base):
    def report(self, port, **kw):
        ctx = self.ctx(**kw)
        return T.text_report(ctx, N.port_report(ctx.events, port))

    def test_18077(self):
        out = self.report(18077)
        self.assertIn("capture RUNNING, accounting invariant closed, exit 0 (stop requested)", out)
        self.assertIn("127.0.0.1:18077 tcp  cookie 9001  listening from 10:00:01.000 (t+1.000s)  by python3 (600) ← "
                      "pid 500 [started before the capture]", out)
        self.assertIn("client: curl (610) ← pid 500 [started before the capture]  (exact, by TCP sequence number", out)
        self.assertIn("10.0.0.7:52000 -> 127.0.0.1:18077", out)
        self.assertIn("client: not on this host", out)
        self.assertIn("pid 610     curl http://127.0.0.1:18077/", out)
        self.assertIn("exited 0 at t+3.050s", out)

    def test_4444(self):
        out = self.report(4444)
        self.assertRegex(out, r"127\.0\.0\.1:0 -> 127\.0\.0\.1:4444 tcp  ECONNREFUSED \(-111\) +by nc \(640\) ← sh \(630\) "
                              r"← python3 \(600\) ← pid 500")

    def test_trust_lines(self):
        self.assertIn("NETWORK CAPTURE WAS OFF", self.report(18077, net_on=False))
        self.assertIn("network capture was off, so this says nothing", self.report(18077, net_on=False))
        self.assertIn("no END record", self.report(18077, end=False))
        out = self.report(4444, gap=True)
        self.assertIn("1 GAP window(s), 3 spine records lost", out)
        self.assertIn("alive during a GAP window", out)

    def test_kernel_skips(self):
        self.assertIn("kernel-skipped events: none", self.report(18077))
        self.assertIn("KERNEL-SKIPPED EVENTS: fork 0, exec 3, exit 0, rename 0, network 0", self.report(18077, skipped=3))
        self.assertIn("predates ADR-0020", self.report(18077, stats_v1=True))

    def test_wall_clock_uses_the_nearest_anchor(self):
        ctx = self.ctx()
        ctx.anchors.append((S.START + 4 * S.S, S.WALL + 4 * S.S + 7_000_000))   # a later anchor, 7 ms off
        ctx.anchors.sort()
        self.assertEqual(ctx.wall(S.START + 3 * S.S), "10:00:03.000")
        self.assertEqual(ctx.wall(S.START + 4 * S.S), "10:00:04.007")


class Html(Base):
    def page(self, port, **kw):
        ctx = self.ctx(**kw)
        return H.render(ctx, N.port_report(ctx.events, port))

    def test_self_contained_and_well_formed(self):
        for port in (18077, 4444, 9):
            with self.subTest(port=port):
                doc = self.page(port)
                self.assertTrue(doc.startswith("<!doctype html>"))
                self.assertIsNone(re.search(r"""(src|href)\s*=\s*["']?(https?:)?//""", doc), "nothing from elsewhere")
                self.assertNotIn("<script", doc)
                Checker().check(doc)

    def test_content(self):
        doc = self.page(18077)
        self.assertIn("python3 600 listened here. 3 connections were accepted, 2 of them from a process on this host.", doc)
        self.assertIn("child of pid 500", doc)
        self.assertEqual(doc.count('<td class="op ACCEPT">'), 3)
        self.assertIn("9003 ← 9001", doc)
        self.assertIn('stroke="var(--remote)"', doc)
        self.assertIn("Nothing in this run names this port.", self.page(9))
        self.assertIn('stroke-dasharray="6 5"', self.page(4444), "a failed connect is dashed")

    def test_escapes_what_the_run_says(self):
        d = S.build(self.dir / "run")
        ctx = T.load(d)
        ctx.tree.procs[S.SRV].images[-1].argv = ["<script>alert(1)</script>"]
        doc = H.render(ctx, N.port_report(ctx.events, 18077))
        self.assertNotIn("<script>alert", doc)
        self.assertIn("&lt;script&gt;", doc)

    def test_trust_colour(self):
        self.assertIn("--state:var(--connect)", self.page(18077))
        self.assertIn("--state:var(--refused)", self.page(18077, net_on=False))
        self.assertIn("--state:var(--refused)", self.page(18077, end=False))
        self.assertIn("--state:var(--listen)", self.page(18077, gap=True))


class Checker(HTMLParser):
    """Every element that isn't void is closed, in order."""
    VOID = {"meta", "br", "path", "rect", "circle", "line", "img", "input", "link"}

    def check(self, doc):
        self.stack = []
        self.feed(doc)
        self.close()
        assert not self.stack, f"unclosed: {self.stack}"

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        pass

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        assert self.stack and self.stack[-1] == tag, f"</{tag}> closes {self.stack[-1:]}"
        self.stack.pop()


class Cli(Base):
    def test_main(self):
        d = S.build(self.dir / "run")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(T.main(["--port", "18077", str(d), "--html", str(self.dir / "r.html")]), 0)
        self.assertIn("p15-trace: port 18077", out.getvalue())
        self.assertTrue((self.dir / "r.html").read_text().startswith("<!doctype html>"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(T.main(["--port", "1", str(self.dir)]), 1)
            with self.assertRaises(SystemExit):
                T.main(["--port", "0", str(d)])
        self.assertIn("cannot read", err.getvalue())

    def test_not_a_p15d_run(self):
        d = write_run(self.dir / "bare", [header(0, meta_for())])
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(T.main(["--port", "1", str(d)]), 1)
        self.assertIn("not a p15d run", err.getvalue())


if __name__ == "__main__":
    unittest.main()
