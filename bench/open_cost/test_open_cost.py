# SPDX-License-Identifier: MIT
"""Tests for the open-cost driver and its report (bench/open_cost/run.py, summarize.py)."""

import contextlib
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "python" / "tests"))
sys.path.insert(0, str(HERE.parents[1] / "python"))

import numpy as np  # noqa: E402
import run as RUN  # noqa: E402
import summarize as SUM  # noqa: E402
from p15w_build import R, batch, header, meta_for, rec, write_run  # noqa: E402

PID = 4242
T0 = 10 ** 9


def facts() -> bytes:
    a = np.zeros(1, R.gen.PARTS["OBJFACTS"])
    a["seen"] = 1
    return a.tobytes()


def opn(i, path, pid=PID, fflags=0, with_facts=False):
    var = {"path": path}
    if with_facts:
        var["facts"] = facts()
        fflags |= R.gen.FF_OBJ_NEW
    return rec("OPEN", var=var, h_ts_ns=T0 + i, h_tgid=pid, h_tid=pid, h_start_ns=5, fid=100 + i, obj=7, fflags=fflags,
               f_mode=1)


def cls(i, pid=PID):
    """The CLOSE of the open made just before it (opn(i - 1))."""
    return rec("CLOSE", h_ts_ns=T0 + i, h_tgid=pid, h_tid=pid, h_start_ns=5, fid=100 + i - 1, obj=7)


def wal(d: Path, bulk, *, end=True, state=0, invariant=1, lost=0) -> Path:
    daemon = [rec("FILE_STATS", h_ts_ns=T0 + 900, open_lost=lost)]
    if end:
        daemon.append(rec("END", var={"reason": b"stop requested"}, h_ts_ns=T0 + 901, run_state=state, invariant=invariant))
    seg = header(0, meta_for()) + batch(1, 0, bulk) + batch(2, 0, daemon)
    return write_run(d, [seg])


class Books(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.d)

    def books(self, bulk, expected, **kw):
        return RUN.capture_books(wal(self.d / "run", bulk, **kw), PID, Path("/data/oc"), expected)

    def test_every_open_and_close_found(self):
        bulk = [opn(0, b"/data/oc/same", with_facts=True), cls(1), opn(2, b"/data/oc/d/0"), cls(3),
                opn(4, b"/usr/lib/libc.so.6"), cls(5),                       # the workload's own, not under DIR
                opn(6, b"/data/oc/same", pid=77), cls(7, pid=77),            # another process
                opn(8, b"/data/ocX/same")]                                   # a path that only starts alike
        b = self.books(bulk, 2)
        self.assertEqual((b["opens"], b["closes"], b["facts"], b["other_opens"], b["path_missing"], b["ok"]),
                         (2, 2, 1, 1, 0, 1))
        self.assertEqual(b["open_bytes"], len(bulk[0]) + len(bulk[2]))
        self.assertEqual(b["close_bytes"], len(bulk[1]) + len(bulk[3]))

    def test_what_makes_the_books_fail(self):
        good = [opn(0, b"/data/oc/same"), cls(1), opn(2, b"/data/oc/d/0"), cls(3)]
        self.assertEqual(self.books(good, 2)["ok"], 1)
        for name, bulk, expected, kw in (
                ("an open is missing", good[2:], 2, {}),
                ("more opens than made", good, 1, {}),
                ("a close is missing", good[:3], 2, {}),
                ("no END", good, 2, {"end": False}),
                ("run state", good, 2, {"state": 1}),
                ("invariant", good, 2, {"invariant": 0}),
                ("lost to the ring", good, 2, {"lost": 1})):
            shutil.rmtree(self.d / "run")
            self.assertEqual(self.books(bulk, expected, **kw)["ok"], 0, name)

    def test_a_path_missing_record_may_stand_for_an_open(self):
        bulk = [opn(0, b"/data/oc/same"), cls(1), opn(2, b"", fflags=R.gen.FF_PATH_MISSING), cls(3)]
        b = self.books(bulk, 2)
        self.assertEqual((b["opens"], b["path_missing"], b["closes"], b["ok"]), (1, 1, 1, 1))
        shutil.rmtree(self.d / "run")
        self.assertEqual(self.books(bulk, 3)["ok"], 0)        # two short, one PATH_MISSING

    def test_an_unreadable_wal_is_an_error(self):
        (self.d / "empty").mkdir()
        with self.assertRaises(RUN.RunError):
            RUN.capture_books(self.d / "empty", PID, Path("/data/oc"), 1)
        with self.assertRaises(RUN.RunError):
            RUN.capture_books(self.d / "absent", PID, Path("/data/oc"), 1)


class Driver(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_rotation_gives_every_arm_every_position(self):
        orders = [RUN.rotation(r) for r in range(-1, 5)]
        self.assertEqual(orders[1:4], [("none", "p15d", "none2"), ("p15d", "none2", "none"), ("none2", "none", "p15d")])
        self.assertEqual(orders[0], orders[3])
        self.assertTrue(all(sorted(o) == sorted(RUN.ARMS) for o in orders))

    def test_without_the_reader_it_stops_before_any_arm(self):
        import builtins
        from unittest import mock
        real = builtins.__import__

        def no_wal(name, *args, **kw):
            if name == "p15" and args and args[2] and "wal" in args[2]:
                raise ImportError("No module named 'google_crc32c'")
            return real(name, *args, **kw)
        err = io.StringIO()
        with mock.patch("builtins.__import__", no_wal), mock.patch.object(RUN, "make_files") as mk, \
                contextlib.redirect_stderr(err):
            code = RUN.main(["--p15d", "x", "--workload", "y", "--dir", str(self.d)])
        self.assertEqual(code, 2)
        mk.assert_not_called()
        self.assertIn("P15_PYTHON", err.getvalue())

    def test_agent_switches_sums_threads(self):
        for tid, v, nv in ((10, 50, 7), (11, 3, 1)):
            t = self.d / "10" / "task" / str(tid)
            t.mkdir(parents=True)
            (t / "status").write_text(f"Name:\tp15d\nvoluntary_ctxt_switches:\t{v}\nnonvoluntary_ctxt_switches:\t{nv}\n")
        (self.d / "10" / "task" / "12").mkdir()                 # a thread that exited: no file
        self.assertEqual(RUN.agent_switches(10, self.d), 61)

    def test_agent_cpu_sums_threads(self):
        for tid, ns in ((10, 500), (11, 70)):
            t = self.d / "10" / "task" / str(tid)
            t.mkdir(parents=True)
            (t / "schedstat").write_text(f"{ns} 3 4\n")
        (self.d / "10" / "task" / "12").mkdir()                 # a thread that exited: no file
        self.assertEqual(RUN.agent_cpu_ns(10, self.d), 570)
        (self.d / "20" / "task").mkdir(parents=True)
        with self.assertRaises(RUN.RunError):
            RUN.agent_cpu_ns(20, self.d)

    def stub(self, body: str) -> Path:
        p = self.d / "stub"
        p.write_text("#!/usr/bin/env python3\n" + body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
        return p

    def test_workload_output_is_checked(self):
        ok = self.stub("print('workload pid=9 cpu=0')\nfor e in 'abc': print(f'row event={e} n=1 cpu_ns=1 wall_ns=1')\n")
        self.assertEqual(RUN.workload(ok, self.d, 1, 1, 0), (9, [f"row event={e} n=1 cpu_ns=1 wall_ns=1" for e in "abc"]))
        with self.assertRaisesRegex(RUN.RunError, "exit 3"):
            RUN.workload(self.stub("import sys\nsys.exit(3)\n"), self.d, 1, 1, None)
        with self.assertRaisesRegex(RUN.RunError, "not understood"):
            RUN.workload(self.stub("print('workload pid=9')\nprint('row event=a n=1 cpu_ns=1 wall_ns=1')\n"), self.d, 1, 1, None)

    def test_a_traced_arm_end_to_end_with_stubs(self):
        """A stub p15d that writes a WAL naming the stub workload's pid: the capture line is ok, the
        WAL is removed; with a WAL that lacks the opens it is FAIL and the log is kept."""
        work, data = self.d / "work", self.d / "data"
        work.mkdir()
        RUN.make_files(data, 3)
        self.assertEqual(sorted(p.name for p in (data / "d").iterdir()), ["0", "1", "2"])
        for n_opens, code, verdict in ((4, 0, "ok"), (3, 0, "FAIL"), (4, 3, "FAIL")):
            bulk = []
            for i in range(n_opens):
                bulk += [opn(2 * i, str(data).encode() + b"/same"), cls(2 * i + 1)]
            src = wal(self.d / f"src{n_opens}-{code}", bulk)
            p15d = self.stub(
                "import shutil, signal, sys, time\n"
                f"shutil.copytree({str(src)!r}, sys.argv[2] + '/run1')\n"
                "sys.stderr.write('p15d level=info code=start\\n'); sys.stderr.flush()\n"
                f"signal.signal(signal.SIGTERM, lambda *a: sys.exit({code}))\n"
                "time.sleep(60)\n")
            wl = self.d / "wl"
            wl.write_text("#!/usr/bin/env python3\n"
                          f"print('workload pid={PID} cpu=0')\n"
                          "for e in ('nullsys', 'same', 'distinct'): print(f'row event={e} n=2 cpu_ns=10 wall_ns=20')\n")
            wl.chmod(0o755)
            a = SimpleNamespace(p15d=p15d, p15d_arg=[], workload=wl, dir=data, same=1, distinct=3, cpu=None, settle=0.0,
                                idle=0.05, keep=False)
            rows, cap = RUN.traced_arm(a, work, 0)
            self.assertEqual(len(rows), 3)
            self.assertTrue(cap.endswith(verdict), cap)
            self.assertIn(f"capture round=0 pid={PID} expected=4 opens={n_opens} path_missing=0 closes={n_opens}", cap)
            self.assertIn(f"exit={code}", cap)
            self.assertFalse((work / "wal-0").exists())
            self.assertEqual((work / "p15d-0.log").exists(), verdict == "FAIL")
            SUM.CAP.match(cap).groups()                       # the report can read the line

    def test_perf_samples_p15d_over_the_workload_only(self):
        """--perf starts perf record on p15d's pid before the workload and stops it with SIGINT."""
        log = self.d / "perf.log"
        fake = self.stub("import signal, sys, time\n"
                         f"open({str(log)!r}, 'w').write(' '.join(sys.argv[1:]))\n"
                         f"signal.signal(signal.SIGINT, lambda *a: (open({str(log)!r}, 'a').write(' SIGINT'), sys.exit(0)))\n"
                         "time.sleep(60)\n")
        a = SimpleNamespace(perf=self.d / "prof", perf_bin=str(fake))
        pr = RUN.perf_start(a, 4321, 7)
        self.assertIsNone(pr.poll())
        RUN.perf_stop(pr)
        self.assertEqual(pr.returncode, 0)
        args = log.read_text()
        self.assertIn(f"record -q -F 1999 --call-graph dwarf,16384 -p 4321 -o {self.d / 'prof' / 'perf-7.data'}", args)
        self.assertTrue(args.endswith(" SIGINT"))
        self.assertIsNone(RUN.perf_start(SimpleNamespace(perf=None), 1, 0))
        RUN.perf_stop(None)
        with self.assertRaisesRegex(RUN.RunError, "perf exited 1"):
            RUN.perf_start(SimpleNamespace(perf=self.d / "prof", perf_bin=str(self.stub("import sys; sys.exit(1)\n"))), 1, 0)

    def test_p15d_that_dies_or_never_starts(self):
        log = self.d / "log"
        log.write_text("p15d level=error code=load\n")
        p = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(70)"])
        p.wait()
        with self.assertRaisesRegex(RUN.RunError, "exited 70"):
            RUN.wait_started(log, p, 5)
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
        try:
            with self.assertRaisesRegex(RUN.RunError, "did not start"):
                RUN.wait_started(log, p, 0.2)
        finally:
            p.kill()
            p.wait()

    @unittest.skipUnless(shutil.which("cc"), "no C compiler")
    def test_the_real_workload(self):
        exe = self.d / "open_cost"
        subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", str(HERE / "open_cost.c"), "-o", str(exe)], check=True)
        RUN.make_files(self.d / "data", 5)
        pid, rows = RUN.workload(exe, self.d / "data", 7, 5, 0)
        self.assertGreater(pid, 0)
        got = [SUM.ROW.match("row round=0 arm=none " + r[4:]).groups()[2:4] for r in rows]
        self.assertEqual(got, [("nullsys", "1000000"), ("same", "7"), ("distinct", "5")])
        os.unlink(self.d / "data" / "d" / "4")
        with self.assertRaisesRegex(RUN.RunError, "exit 1"):
            RUN.workload(exe, self.d / "data", 7, 5, 0)
        with self.assertRaisesRegex(RUN.RunError, "exit 2"):
            RUN.workload(exe, self.d / "data", -1, 5, 0)


def run_text(rounds=12, add_same=150.0, add_distinct=400.0, noise=0.0, agent_per_op=200, cap_tail="ok", drop=None,
             missing=0):
    """A synthetic run: untraced same 1000 ns and distinct 1500 ns per op, null 130 ns; p15d adds
    the given ns; with noise, a deterministic pattern that differs per arm and round."""
    L = ["config kernel=test cpus=3 rounds=%d same=1000 distinct=100 settle=1 idle=1 p15d_args=-" % rounds]
    for r in range(-1, rounds):
        for k, arm in enumerate(("none", "p15d", "none2")):
            t = arm == "p15d"
            wob = 1 + noise * (((r + 2) * (7919 + 104729 * k)) % 11 - 5) / 5      # each arm its own noise
            aa = 1.002 if arm == "none2" else 1.0
            for ev, n, base, add in (("nullsys", 1000000, 130.0, 0.0), ("same", 1000, 1000.0, add_same),
                                     ("distinct", 100, 1500.0, add_distinct)):
                if drop == (r, arm, ev):
                    continue
                cpu = round(n * (base * wob * aa + (add if t else 0)))
                L.append(f"row round={r} arm={arm} event={ev} n={n} cpu_ns={cpu} wall_ns={cpu + 1000}")
            if t:
                L.append(f"capture round={r} pid={100 + r} expected=1100 opens={1100 - missing} path_missing={missing} closes=1100 facts=101 "
                         f"open_bytes={(1100 - missing) * 96} close_bytes={1100 * 56} other_opens=3 lost=0 end=1 state=0 invariant=1 "
                         f"stops=0 exit=0 idle_cpu_ns=2000000 idle_wall_ns=1000000000 "
                         f"agent_cpu_ns={1100 * agent_per_op + 500000} agent_wall_ns=250000000 {cap_tail}")
    return "\n".join(L) + "\n"


class Report(unittest.TestCase):
    def test_switches_are_reported_when_the_run_has_them(self):
        text, rc = SUM.report(run_text())
        self.assertEqual(rc, 0)
        self.assertNotIn("thread switches", text)                # an older run: no line, no error
        new = run_text().replace(" ok\n", " idle_switches=40 agent_switches=550 ok\n")
        text, rc = SUM.report(new)
        self.assertEqual(rc, 0)
        self.assertIn("p15d's thread switches: 500.0 per 1,000 open+close in the window (median), 40.0 per second idle", text)
        with self.assertRaisesRegex(SUM.ParseError, "other fields"):
            SUM.report(run_text().replace(" ok\n", " surprise=1 ok\n"))

    def test_a_profiling_run_gives_no_timing(self):
        text, rc = SUM.report(run_text().replace("p15d_args=-", "p15d_args=- perf=/tmp/prof", 1))
        self.assertEqual(rc, 1)
        self.assertIn("no timing is reported", text)
        self.assertNotIn("median per open+close", text)
        self.assertIn("bytes per open+close", text)              # the books are still shown

    def test_numbers(self):
        text, rc = SUM.report(run_text())
        self.assertEqual(rc, 0)
        self.assertIn("12 rounds. Null syscall (getppid) without capture, median: 130.0 ns", text)
        self.assertIn("| none | 1,000.0 ns |", text)
        self.assertIn("| p15d | 1,150.0 ns |", text)
        self.assertIn("added per open+close 150.0 ns", text)          # same, cpu
        self.assertIn("1.15 null syscalls", text)
        self.assertIn("added per open+close 400.0 ns", text)          # distinct
        self.assertIn("records per open+close: 2.000; bytes per open+close in the WAL: 152.0 (OPEN 96.0, CLOSE 56.0)", text)
        self.assertIn("opens carrying the object's facts: 9.2%", text)
        self.assertIn("p15d idle: 2.00 ms of CPU per second", text)
        # gross: (1100*200 + 500000) / 1100 = 654.5; net of the idle rate (2 ms/s over 0.25 s = 500000 ns): 200.0
        self.assertIn("654.5 ns of CPU in the window (mean), 200.0 ns after the idle rate is taken off (median 200.0 ns)", text)
        # net agent / untraced open CPU = 1100*200 / (1000*1000 + 100*1500) = 19.1 %
        self.assertIn("agent overhead of the opens", text)
        self.assertIn("mean 19.1%, median 19.1%, range 19.1% to 19.1%", text)
        # gross agent / whole workload CPU = 720000 / (130e6 + 1.15e6) = 0.5 %
        self.assertIn("null syscalls included): mean 0.5%, median 0.5%", text)
        self.assertIn("overhead +15.0", text.replace("15.00", "15.0"))

    def test_path_missing_records_are_records(self):
        text, rc = SUM.report(run_text(missing=100))
        self.assertEqual(rc, 0)
        self.assertIn("OPEN records with their path 12,000; PATH_MISSING records of the workload 1,200", text)
        self.assertIn("records per open+close: 2.000; bytes per open+close in the WAL: 143.3 (OPEN 96.0, CLOSE 56.0)", text)

    def test_an_effect_inside_the_noise_is_not_quoted(self):
        text, rc = SUM.report(run_text(add_same=0.5, add_distinct=0.5, noise=0.05))
        self.assertEqual(rc, 0)
        self.assertIn("not resolved on this host", text)

    def test_books_that_fail_stop_the_timings(self):
        text, rc = SUM.report(run_text(cap_tail="FAIL"))
        self.assertEqual(rc, 1)
        self.assertIn("Books that did not close: no timing is reported", text)
        self.assertNotIn("median per open+close", text)
        text, rc = SUM.report(run_text() + "error round=3 arm=p15d p15d did not start in 120 s\n")
        self.assertEqual(rc, 1)
        text, rc = SUM.report("config x\nerror round=-1 arm=p15d p15d exited 69 before it started\n")
        self.assertEqual(rc, 1)                                     # an early failure is shown, not "no rounds"
        self.assertIn("p15d exited 69", text)

    def test_malformed_input_is_refused(self):
        for bad, why in ((run_text(drop=(3, "none2", "same")), "round 3: missing none2/same"),
                         (run_text() + "row round=1 arm=none event=same n=5 cpu_ns=5 wall_ns=5\n", "twice"),
                         (run_text() + "row round=1 arm=zzz event=same n=5 cpu_ns=5 wall_ns=5\n", "unknown arm"),
                         (run_text() + "row garbage\n", "unparsed row"),
                         (run_text() + "capture round=1 pid=1 ok\n", "other fields"),
                         (run_text() + "hello\n", "unknown line"),
                         (run_text().replace("capture round=5 ", "capture round=55 "), "round 5: no capture line"),
                         ("config x\n", "no timed rounds")):
            with self.assertRaisesRegex(SUM.ParseError, why):
                SUM.report(bad)

    def test_main(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "ok.txt").write_text(run_text())
            (d / "bad.txt").write_text("hello\n")
            run = lambda *a: subprocess.run([sys.executable, str(HERE / "summarize.py"), *a], capture_output=True, text=True)
            self.assertEqual(run(str(d / "ok.txt")).returncode, 0)
            self.assertEqual(run(str(d / "bad.txt")).returncode, 1)
            self.assertEqual(run().returncode, 2)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
