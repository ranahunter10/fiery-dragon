#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Drive the open-cost measurement (STATE decision 22a.4; ADR-0018 rule 2): the same workload
(open_cost.c) with p15d capturing and without it, paired by round.

    sudo python3 bench/open_cost/run.py --p15d build/p15d --workload build/open_cost \
         --dir /var/tmp/p15-open-cost --rounds 20 > open_cost.txt

Arms per round, in an order rotated each round, after one untimed warm-up round (round -1):
  none, none2   no p15d: the untraced arm and its A/A control
  p15d          p15d started for the arm (default options: spine, NET, file identity), given
                SETTLE seconds for its opening snapshot, then IDLE seconds in which only its own
                CPU time is read (what it burns with nothing asked of it), then the workload;
                then stopped, and its WAL read
What a traced arm must show (its "capture" line; summarize.py refuses timings otherwise):
  - p15d exited 0 with run state 0 and its invariant holding, and END is in the WAL;
  - every open the workload made is an OPEN record of its pid under DIR, or is among that pid's
    PATH_MISSING records; every such open file has its CLOSE; nothing was lost to the ring.
It also reports, from the WAL and /proc: the bytes those records take, the opens other processes
made meanwhile, and p15d's CPU time (all threads, /proc/<pid>/task/*/schedstat) over the idle
window and over the workload.

The workload pins itself to one CPU; p15d's threads are left where the scheduler puts them, as in
real use. Output: "config", "row" and "capture" lines on stdout; summarize.py makes the report.

With --perf DIR, each traced arm also samples p15d with `perf record` (DWARF call graphs) over the
workload's window only, into DIR/perf-ROUND.data, for `perf report`. Sampling costs p15d CPU, so
a run with --perf profiles where p15d's time goes and is not an overhead measurement: its config
line says perf=DIR and summarize.py refuses to time it.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))

ARMS = ("none", "p15d", "none2")
START_TIMEOUT_S = 120
STOP_TIMEOUT_S = 120


class RunError(Exception):
    pass


def rotation(rnd: int) -> tuple[str, ...]:
    """The arm order of a round: rotated by one each round, so every arm takes every position."""
    k = rnd % len(ARMS)
    return ARMS[k:] + ARMS[:k]


def agent_cpu_ns(pid: int, proc: Path = Path("/proc")) -> int:
    """On-CPU time of every thread of `pid`, in ns (schedstat's first field; needs schedstats,
    which Ubuntu's kernels have). A thread that exits between the listing and the read is skipped:
    its time is then missing from the sum, so the caller reads this while p15d's threads all live."""
    total = 0
    tasks = list((proc / str(pid) / "task").iterdir())
    if not tasks:
        raise RunError(f"pid {pid} has no threads")
    for t in tasks:
        try:
            total += int((t / "schedstat").read_text().split()[0])
        except FileNotFoundError:
            continue
    return total


def make_files(d: Path, distinct: int) -> None:
    """The files the workload opens. Made once, before any arm: creating them is not measured."""
    (d / "d").mkdir(parents=True, exist_ok=True)
    (d / "same").write_bytes(b"x")
    for i in range(distinct):
        p = d / "d" / str(i)
        if not p.exists():
            p.write_bytes(b"x")
    os.sync()


def workload(binary: Path, d: Path, same: int, distinct: int, cpu: int | None) -> tuple[int, list[str]]:
    """Run the workload; return its pid and its row lines."""
    cmd = [str(binary), str(d), str(same), str(distinct)] + ([str(cpu)] if cpu is not None else [])
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RunError(f"workload exit {r.returncode}: {r.stderr.strip()}")
    lines = r.stdout.splitlines()
    head = dict(kv.split("=") for kv in lines[0].split()[1:]) if lines and lines[0].startswith("workload ") else {}
    rows = [ln for ln in lines if ln.startswith("row ")]
    if "pid" not in head or len(rows) != 3:
        raise RunError(f"workload output not understood: {r.stdout!r}")
    return int(head["pid"]), rows


def agent_switches(pid: int, proc: Path = Path("/proc")) -> int:
    """Context switches of every thread of `pid`, voluntary and not (/proc/PID/task/*/status). p15d's
    profile spent about a third of its samples switching threads (E-0215); this counts them."""
    total = 0
    for t in (proc / str(pid) / "task").iterdir():
        try:
            for line in (t / "status").read_text().splitlines():
                if line.startswith(("voluntary_ctxt_switches:", "nonvoluntary_ctxt_switches:")):
                    total += int(line.split()[1])
        except FileNotFoundError:
            continue
    return total


def capture_books(run_dir: Path, pid: int, d: Path, expected: int) -> dict:
    """What the WAL holds about the workload's opens. Raises RunError if the run cannot be read."""
    from p15 import records as R
    from p15 import wal as W
    try:
        run = W.read_run(run_dir)
        bulk = list(run.ring_records(1))
        daemon = list(run.ring_records(2))
    except (W.RunError, W.HeaderError, R.RecordError, OSError) as e:
        raise RunError(f"WAL {run_dir}: {e}") from e
    prefix = str(d).encode() + b"/"
    fids: set[int] = set()
    out = dict(opens=0, open_bytes=0, facts=0, path_missing=0, closes=0, close_bytes=0, other_opens=0)
    for r in bulk:
        if r.name == "OPEN":
            if r.h["tgid"] != pid:
                out["other_opens"] += 1
            elif r.f["fflags"] & R.gen.FF_PATH_MISSING:
                out["path_missing"] += 1
            elif r.var["path"].startswith(prefix):
                out["opens"] += 1
                out["open_bytes"] += r.h["len"]
                out["facts"] += r.var["facts"] is not None
                fids.add(r.f["fid"])
    for r in bulk:
        if r.name == "CLOSE" and r.f["fid"] in fids:
            out["closes"] += 1
            out["close_bytes"] += r.h["len"]
    last = {r.name: r for r in daemon}
    fs, end = last.get("FILE_STATS"), last.get("END")
    out["lost"] = sum(fs.f[k] for k in ("open_lost", "close_lost", "missing_lost", "verdict_lost", "backing_lost")) \
        if fs else -1
    out["end"] = 0 if end is None else 1
    out["state"] = end.f["run_state"] if end else -1
    out["invariant"] = end.f["invariant"] if end else -1
    out["stops"] = len(run.stops)
    short = expected - out["opens"]
    out["ok"] = int(end is not None and out["state"] == 0 and out["invariant"] == 1 and out["lost"] == 0 and
                    out["stops"] == 0 and 0 <= short <= out["path_missing"] and out["closes"] == out["opens"])
    return out


def wait_started(log: Path, proc: subprocess.Popen, timeout_s: float) -> None:
    """Wait for p15d's code=start line: its programs are loaded and its self-tests passed."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout_s:
        if "code=start" in log.read_text(errors="replace"):
            return
        if proc.poll() is not None:
            raise RunError(f"p15d exited {proc.returncode} before it started: {log.read_text(errors='replace')[-400:]}")
        time.sleep(0.05)
    raise RunError(f"p15d did not start in {timeout_s} s")


def perf_start(a, pid: int, rnd: int) -> subprocess.Popen | None:
    """`perf record` on p15d's threads (DWARF call graphs: p15d and libbpf keep no frame pointers),
    or None without --perf. Raises RunError if perf exits at once (not installed, not allowed)."""
    if getattr(a, "perf", None) is None:
        return None
    a.perf.mkdir(parents=True, exist_ok=True)
    out = a.perf / f"perf-{rnd}.data"
    cmd = [getattr(a, "perf_bin", "perf"), "record", "-q", "-F", "1999", "--call-graph", "dwarf,16384",
           "-p", str(pid), "-o", str(out)]
    pr = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(0.3)                           # perf attaches before the workload starts
    if pr.poll() is not None:
        raise RunError(f"perf exited {pr.returncode}: {pr.stderr.read().decode(errors='replace')[-300:]}")
    return pr


def perf_stop(pr: subprocess.Popen | None) -> None:
    """Stop `perf record` (SIGINT writes its file) and wait for it."""
    if pr is None:
        return
    pr.send_signal(signal.SIGINT)
    try:
        pr.wait(STOP_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        pr.kill()
        pr.wait()


def traced_arm(a, work: Path, rnd: int) -> tuple[list[str], str]:
    """Start p15d, run the workload under it, stop it, read its WAL. Returns the workload's rows
    and the capture line."""
    wal = work / f"wal-{rnd}"
    log = work / f"p15d-{rnd}.log"
    shutil.rmtree(wal, ignore_errors=True)
    with open(log, "wb") as lf:
        p = subprocess.Popen([str(a.p15d), "--wal-dir", str(wal)] + a.p15d_arg, stdout=lf, stderr=lf)
    try:
        wait_started(log, p, START_TIMEOUT_S)
        time.sleep(a.settle)
        c0, t0, s0 = agent_cpu_ns(p.pid), time.monotonic_ns(), agent_switches(p.pid)
        time.sleep(a.idle)
        c1, t1, s1 = agent_cpu_ns(p.pid), time.monotonic_ns(), agent_switches(p.pid)
        prof = perf_start(a, p.pid, rnd)
        try:
            pid, rows = workload(a.workload, a.dir, a.same, a.distinct, a.cpu)
            time.sleep(0.2)                      # the drain's last poll of what the workload wrote
            c2, t2, s2 = agent_cpu_ns(p.pid), time.monotonic_ns(), agent_switches(p.pid)
        finally:
            perf_stop(prof)
    finally:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
        try:
            code = p.wait(STOP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            code = -9
    runs = sorted(x for x in wal.iterdir() if x.is_dir()) if wal.is_dir() else []
    if len(runs) != 1:
        raise RunError(f"round {rnd}: expected one run directory under {wal}, found {len(runs)}")
    b = capture_books(runs[0], pid, a.dir, a.same + a.distinct)
    if code != 0:
        b["ok"] = 0
    line = (f"capture round={rnd} pid={pid} expected={a.same + a.distinct} " +
            " ".join(f"{k}={b[k]}" for k in ("opens", "path_missing", "closes", "facts", "open_bytes", "close_bytes",
                                             "other_opens", "lost", "end", "state", "invariant", "stops")) +
            f" exit={code} idle_cpu_ns={c1 - c0} idle_wall_ns={t1 - t0} agent_cpu_ns={c2 - c1} agent_wall_ns={t2 - t1}"
            f" idle_switches={s1 - s0} agent_switches={s2 - s1}"
            f" {'ok' if b['ok'] else 'FAIL'}")
    if not a.keep:
        shutil.rmtree(wal, ignore_errors=True)
        if b["ok"]:
            log.unlink(missing_ok=True)
    return rows, line


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--p15d", type=Path, required=True)
    ap.add_argument("--workload", type=Path, required=True)
    ap.add_argument("--dir", type=Path, required=True, help="where the workload's files live (a real filesystem, not tmpfs)")
    ap.add_argument("--work", type=Path, help="where WALs and logs go (default: DIR/work)")
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--same", type=int, default=200000)
    ap.add_argument("--distinct", type=int, default=20000)
    ap.add_argument("--cpu", type=int)
    ap.add_argument("--settle", type=float, default=1.0)
    ap.add_argument("--idle", type=float, default=1.0)
    ap.add_argument("--keep", action="store_true", help="keep every WAL and log")
    ap.add_argument("--p15d-arg", action="append", default=[], help="an extra p15d argument (repeatable)")
    ap.add_argument("--perf", type=Path, metavar="DIR", help="profile p15d with perf record into DIR (not a timing run)")
    ap.add_argument("--perf-bin", default="perf", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.rounds < 1 or a.same < 1 or a.distinct < 1:
        ap.error("rounds, same and distinct must be at least 1")
    try:                                   # the books need p15's reader: fail now, not after the first arms
        from p15 import wal as _  # noqa: F401
    except ImportError as e:
        print(f"open_cost: p15's WAL reader cannot be imported ({e}); run with the project's Python, "
              "e.g. make bench-open-cost P15_PYTHON=~/p15venv/bin/python", file=sys.stderr)
        return 2
    work = a.work or a.dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    make_files(a.dir, a.distinct)
    print(f"config kernel={os.uname().release} cpus={os.cpu_count()} rounds={a.rounds} same={a.same} "
          f"distinct={a.distinct} settle={a.settle} idle={a.idle} p15d_args={' '.join(a.p15d_arg) or '-'}"
          + (f" perf={a.perf}" if a.perf else ""), flush=True)
    failed = 0
    for rnd in range(-1, a.rounds):
        for arm in rotation(rnd):
            try:
                if arm == "p15d":
                    rows, cap = traced_arm(a, work, rnd)
                    print(cap)
                    failed += cap.endswith("FAIL")
                else:
                    _, rows = workload(a.workload, a.dir, a.same, a.distinct, a.cpu)
            except RunError as e:
                print(f"error round={rnd} arm={arm} {e}", flush=True)
                return 1
            for r in rows:
                print(f"row round={rnd} arm={arm} {r[4:]}")
            sys.stdout.flush()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
