# SPDX-License-Identifier: MIT
"""Tests for run.py and workloads/. Run: python3 -m unittest -v bench/census/test_run.py

These cover selection, planning, the workload scripts' syntax, the file-churn
workload, and the report. The end-to-end run (bpftrace + workloads) needs root
and a kernel; it was dry-run in the dev container and is proven on the VM.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run as R  # noqa: E402
from workloads import filechurn, knownops  # noqa: E402


class SelectionTest(unittest.TestCase):
    def test_group_light_expands_in_registry_order(self):
        self.assertEqual([w.name for w in R.select("light")],
                         ["idle", "exec-storm", "file-churn", "super-producer", "xfer", "io-uring"])
        self.assertEqual([w.name for w in R.select("check")], ["known-ops"])

    def test_names_and_groups_mix_without_duplicates(self):
        self.assertEqual([w.name for w in R.select("xfer, idle ,light")][:2], ["xfer", "idle"])
        self.assertEqual(len(R.select("xfer,idle,light")), len(R.GROUPS["light"]))

    def test_unknown_name_is_an_error(self):
        with self.assertRaisesRegex(R.RunError, "unknown workload 'nope'"):
            R.select("idle,nope")

    def test_empty_selection_is_an_error(self):
        with self.assertRaises(R.RunError):
            R.select(" , ")

    def test_cli_rejects_unknown_workload(self):
        with self.assertRaises(SystemExit):
            with open(os.devnull, "w") as null, _redirect_stderr(null):
                R.main(["--workloads", "nope", "--dry-run"])


class RegistryTest(unittest.TestCase):
    def test_names_unique_and_groups_known(self):
        names = [w.name for w in R.WORKLOADS]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(w.group in R.GROUPS for w in R.WORKLOADS))

    def test_every_script_is_valid_bash(self):
        for w in R.WORKLOADS:
            with self.subTest(w.name):
                r = subprocess.run(["bash", "-n", "-c", w.script], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_every_script_stops_itself(self):
        # The runner only kills a workload past duration + grace; each script must honour $DURATION.
        for w in R.WORKLOADS:
            with self.subTest(w.name):
                self.assertIn("DURATION", w.script)

    def test_every_workload_declares_its_tools(self):
        for w in R.WORKLOADS:
            with self.subTest(w.name):
                self.assertTrue(w.needs)


class PlanTest(unittest.TestCase):
    def test_missing_tools_mark_skip(self):
        fake_which = lambda t: None if t == "fio" else f"/usr/bin/{t}"
        steps = dict((w.name, miss) for w, miss in R.plan(R.select("light"), which=fake_which))
        self.assertEqual(steps["io-uring"], ["fio"])
        self.assertEqual(steps["idle"], [])

    def test_meminfo_parse(self):
        text = "MemTotal:        8220244 kB\nMemFree:  100 kB\n"
        self.assertEqual(R.meminfo_kb(text, "MemTotal"), 8220244)
        self.assertIsNone(R.meminfo_kb(text, "SwapTotal"))


class ClassifyTest(unittest.TestCase):
    GOOD_S = {"complete": True, "lost_events": 0}
    GOOD_W = {"exit_code": 0, "killed_after_grace": False}

    def test_ok_only_when_everything_is_clean(self):
        self.assertEqual(R.classify(True, self.GOOD_S, self.GOOD_W), "ok")

    def test_each_problem_fails_the_run(self):
        cases = {
            "bpftrace did not stop cleanly": (False, self.GOOD_S, self.GOOD_W),
            "census output incomplete": (True, {**self.GOOD_S, "complete": False}, self.GOOD_W),
            "bpftrace lost 3 events": (True, {**self.GOOD_S, "lost_events": 3}, self.GOOD_W),
            "workload exit 1": (True, self.GOOD_S, {**self.GOOD_W, "exit_code": 1}),
            "workload overran and was killed": (True, self.GOOD_S, {"exit_code": -9, "killed_after_grace": True}),
        }
        for reason, args in cases.items():
            with self.subTest(reason):
                st = R.classify(*args)
                self.assertTrue(st.startswith("FAILED"), st)
                self.assertIn(reason, st)

    def test_problems_are_all_listed(self):
        st = R.classify(False, {"complete": False, "lost_events": 1}, {"exit_code": 2, "killed_after_grace": False})
        self.assertEqual(st.count(";"), 3)


class PreflightTest(unittest.TestCase):
    def test_probe_targets_from_real_census(self):
        with open(os.path.join(os.path.dirname(R.__file__), "census.bt")) as f:
            funcs, tps = R.probe_targets(f.read())
        for fn in ("vfs_read", "vfs_unlink", "vfs_mkdir", "notify_change", "__sys_connect_file",
                   "do_accept", "security_mmap_file", "memfd_alloc_file", "__x64_sys_ptrace"):
            self.assertIn(fn, funcs)
        for tp in ("sock/sock_send_length", "io_uring/io_uring_complete", "task/task_rename", "raw_syscalls/sys_enter"):
            self.assertIn(tp, tps)
        self.assertFalse(any(t.startswith("syscalls/") for t in tps), "sys_enter_* tracepoints are silent on 7.0 (E-0022)")

    def test_missing_targets(self):
        with tempfile.TemporaryDirectory() as ev:
            os.makedirs(os.path.join(ev, "sock", "sock_send_length"))
            missing = R.missing_targets({"vfs_read", "gone", "inlined"}, {"sock/sock_send_length", "x/y"},
                                        btf_funcs={"vfs_read", "inlined"}, ftrace_funcs={"vfs_read"},
                                        events_dir=__import__("pathlib").Path(ev))
        self.assertEqual(missing, ["gone (not in BTF)", "inlined (not traceable)", "tracepoint x/y"])

    def test_unverifiable_sources_do_not_report_missing(self):
        self.assertEqual(R.missing_targets({"anything"}, set(), None, None, __import__("pathlib").Path("/nonexistent")), [])


class SelfCheckTest(unittest.TestCase):
    def test_expectations_take_last_json_line(self):
        log = 'noise\n{"expect": {"mkdir": 1}}\n{"other": 1}\n{"expect": {"mkdir": 5, "unlink": 15}}\n'
        self.assertEqual(R.expectations(log), {"mkdir": 5, "unlink": 15})

    def test_no_expectations(self):
        self.assertIsNone(R.expectations('{"filechurn": {}}\nplain text\n'))

    def test_shortfalls_only_below_expectation(self):
        summary = {"rows": [{"class": "mkdir", "total": 50}, {"class": "unlink", "total": 149},
                            {"class": "chmod", "total": 99}]}
        self.assertEqual(R.shortfalls({"mkdir": 50, "unlink": 150, "chmod": 50, "memfd": 1}, summary),
                         ["memfd 0 < 1", "unlink 149 < 150"])

    def test_classify_fails_on_missed_hooks(self):
        st = R.classify(True, {"complete": True, "lost_events": 0}, {"exit_code": 0, "killed_after_grace": False},
                        ["memfd 0 < 50"])
        self.assertEqual(st, "FAILED (hook missed events: memfd 0 < 50)")

    def test_knownops_counts_what_it_does(self):
        with tempfile.TemporaryDirectory() as tmp:
            exp = knownops.run(os.path.join(tmp, "ko"), k=3)
        for cls in ("mkdir", "rmdir", "chmod", "chown", "truncate", "link", "symlink", "rename_file",
                    "connect", "accept", "connect_fail", "mmap_shared_w", "memfd", "ptrace", "process_vm_writev"):
            self.assertEqual(exp[cls], 3, cls)
        self.assertEqual(exp["unlink"], 9)
        self.assertEqual((exp["bind"], exp["listen"]), (1, 1))
        self.assertIn(exp["io_uring_setup"], (0, 3))   # 0 where io_uring is disabled by sysctl
        self.assertIn(exp["mprotect_exec"], (0, 3))    # 0 under a W^X policy


class ReportTest(unittest.TestCase):
    CONDS = {"utc_start": "2026-10-25T00:00:00+00:00", "kernel": "7.0.0-38-generic", "bpftrace": "bpftrace v0.25.0",
             "git_commit": "0123456789abcdef", "git_dirty": False, "probe_sha256": "ab" * 32, "cpus": 4,
             "mem_total_kb": 8000000, "hypervisor_vendor": "KVM", "virt": "oracle", "swap_before": "none",
             "swapoff_during_runs": True, "duration_s": 60, "workload_user": "ashu", "snapshot": "01-toolchain",
             "host_note": "test"}

    def test_index_lists_ok_skipped_and_failed(self):
        summary = {"emitted_records_mean_per_s": 1234.0, "emitted_records_p99_per_s": 5000.0,
                   "emitted_records_max_per_s": 6000.0, "log_bytes_p99_per_s": 320000.0, "verdict": "WITHIN BUDGET"}
        md = R.render_index(self.CONDS, [
            {"name": "idle", "status": "ok", "summary": summary},
            {"name": "io-uring", "status": "SKIPPED (missing fio)"},
            {"name": "xfer", "status": "FAILED (workload exit 1)", "summary": summary},
        ])
        self.assertIn("| idle | ok | 1,234 | 5,000 | 6,000 | 0.32 | WITHIN BUDGET |", md)
        self.assertIn("| io-uring | SKIPPED (missing fio) |", md)
        self.assertIn("| xfer | FAILED (workload exit 1) |", md)
        self.assertIn("kernel 7.0.0-38-generic", md)
        self.assertNotIn("(dirty)", md)


class FileChurnTest(unittest.TestCase):
    def test_short_run_does_all_operations_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, "churn")
            stats = filechurn.churn(d, duration=0.3, files=20, min_size=100, max_size=5000, seed=1)
            self.assertGreaterEqual(stats["create"], 20)
            for op in ("read", "append", "delete"):
                self.assertGreater(stats[op], 0, op)
            self.assertGreater(stats["bytes_read"], 0)
            self.assertFalse(os.path.exists(d))

    def test_cli_prints_json_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run([sys.executable, filechurn.__file__, "--dir", os.path.join(tmp, "c"),
                                "--duration", "0.2", "--files", "5"], capture_output=True, text=True, check=True)
            out = json.loads(r.stdout)
            self.assertEqual(out["params"]["files"], 5)
            self.assertIn("create", out["filechurn"])


class _redirect_stderr:
    def __init__(self, f):
        self.f = f
    def __enter__(self):
        self.old, sys.stderr = sys.stderr, self.f
    def __exit__(self, *a):
        sys.stderr = self.old


if __name__ == "__main__":
    unittest.main()
