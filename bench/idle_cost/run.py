#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Drive the idle-cost measurement (gate 3 of STATE decision 28): p15d's own CPU per second on a host
that asks nothing of it, under several settings, compared at the same background load.

    sudo ~/p15venv/bin/python bench/idle_cost/run.py --p15d build/p15d --work /var/tmp/p15-idle \
         --arm max10=--poll-max-ms=10 --arm max200=--poll-max-ms=200 --rounds 5 > idle_cost.txt

Per round, each arm in an order rotated each round (so drift of the host spreads over every arm):
p15d is started with the arm's options (comma-separated, "=" for a space), given SETTLE seconds
after its start line (the opening snapshot), then each of its threads' on-CPU time
(/proc/<pid>/task/*/schedstat, by thread name) is read at the start and end of a WINDOW-second
window; then it is stopped and its WAL read for what arrived meanwhile: the records of each ring
whose timestamps fall in the window (the background load), and, from the STATS records in it, the
drain's polls (the sum of the poll-gap histogram) per second.
Lines: "config", then per arm and round "thread" lines and one "run" line. A run counts only if
p15d exited 0 with END state 0 and its invariant holding; otherwise its run line says FAIL.
"""

from __future__ import annotations

import argparse
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))

START_TIMEOUT_S = 120
STOP_TIMEOUT_S = 120
POLL_FIELDS = ("poll_gap_le_100us", "poll_gap_le_1ms", "poll_gap_le_10ms", "poll_gap_le_100ms", "poll_gap_le_1s",
               "poll_gap_gt_1s")


class RunError(Exception):
    pass


def arm_args(spec: str) -> tuple[str, list[str]]:
    """'name=--a=1,--b' -> ('name', ['--a', '1', '--b'])."""
    name, _, rest = spec.partition("=")
    if not name or not name.isidentifier():
        raise RunError(f"bad arm {spec!r}: NAME=OPTIONS")
    out: list[str] = []
    for o in filter(None, rest.split(",")):
        out += o.split("=", 1)
    return name, out


def rotation(names: list[str], rnd: int) -> list[str]:
    k = rnd % len(names)
    return names[k:] + names[:k]


def threads_cpu(pid: int, proc: Path = Path("/proc")) -> dict[str, int]:
    """On-CPU ns of each thread of pid, keyed 'comm/tid' (schedstat's first field)."""
    out = {}
    for t in (proc / str(pid) / "task").iterdir():
        try:
            out[f"{(t / 'comm').read_text().strip()}/{t.name}"] = int((t / "schedstat").read_text().split()[0])
        except (FileNotFoundError, ProcessLookupError):
            continue
    return out


def boot_ns() -> int:
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def window_books(run_dir: Path, w0: int, w1: int) -> dict:
    """What the WAL says about the window [w0, w1] (boot ns)."""
    from p15 import records as R
    from p15 import wal as W
    try:
        run = W.read_run(run_dir)
        load = {k: sum(1 for r in run.ring_records(k) if w0 <= r.h["ts_ns"] <= w1) for k in (0, 1)}
        daemon = list(run.ring_records(2))
    except (W.RunError, W.HeaderError, R.RecordError, OSError) as e:
        raise RunError(f"WAL {run_dir}: {e}") from e
    stats = [r for r in daemon if r.name == "STATS" and w0 <= r.h["ts_ns"] <= w1]
    end = next((r for r in daemon if r.name == "END"), None)
    polls = -1.0
    if len(stats) >= 2:
        n = sum(stats[-1].f[k] - stats[0].f[k] for k in POLL_FIELDS)
        polls = n / ((stats[-1].h["ts_ns"] - stats[0].h["ts_ns"]) / 1e9)
    ok = end is not None and end.f["run_state"] == 0 and end.f["invariant"] == 1 and polls >= 0
    return {"spine": load[0], "bulk": load[1], "polls_per_s": polls, "end": int(end is not None),
            "state": end.f["run_state"] if end else -1, "invariant": end.f["invariant"] if end else -1, "ok": ok}


def wait_started(log: Path, proc: subprocess.Popen, timeout_s: float) -> None:
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout_s:
        if "code=start" in log.read_text(errors="replace"):
            return
        if proc.poll() is not None:
            raise RunError(f"p15d exited {proc.returncode} before it started: {log.read_text(errors='replace')[-400:]}")
        time.sleep(0.05)
    raise RunError(f"p15d did not start in {timeout_s} s")


def one(a, name: str, opts: list[str], rnd: int) -> list[str]:
    wal = a.work / f"wal-{name}-{rnd}"
    log = a.work / f"p15d-{name}-{rnd}.log"
    shutil.rmtree(wal, ignore_errors=True)
    with open(log, "wb") as lf:
        p = subprocess.Popen([str(a.p15d), "--wal-dir", str(wal)] + opts, stdout=lf, stderr=lf)
    try:
        wait_started(log, p, START_TIMEOUT_S)
        time.sleep(a.settle)
        c0, w0 = threads_cpu(p.pid), boot_ns()
        time.sleep(a.window)
        c1, w1 = threads_cpu(p.pid), boot_ns()
        time.sleep(1.5)                     # a STATS after the window's end, so the window has two
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
        raise RunError(f"{name} round {rnd}: expected one run directory under {wal}, found {len(runs)}")
    b = window_books(runs[0], w0, w1)
    ok = b["ok"] and code == 0
    lines = [f"thread arm={name} round={rnd} name={k.split('/')[0]} cpu_ns={c1[k] - c0[k]}" for k in sorted(c1) if k in c0]
    total = sum(c1[k] - c0[k] for k in c1 if k in c0)
    lines.append(f"run arm={name} round={rnd} window_ns={w1 - w0} cpu_ns={total} spine={b['spine']} bulk={b['bulk']} "
                 f"polls_per_s={b['polls_per_s']:.1f} exit={code} end={b['end']} state={b['state']} "
                 f"invariant={b['invariant']} {'ok' if ok else 'FAIL'}")
    if not a.keep:
        shutil.rmtree(wal, ignore_errors=True)
        if ok:
            log.unlink(missing_ok=True)
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--p15d", type=Path, required=True)
    ap.add_argument("--work", type=Path, required=True, help="where WALs and logs go")
    ap.add_argument("--arm", action="append", required=True, help="NAME=OPTIONS, e.g. max200=--poll-max-ms=200")
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--settle", type=float, default=5.0)
    ap.add_argument("--window", type=float, default=20.0)
    ap.add_argument("--keep", action="store_true", help="keep every WAL and log")
    a = ap.parse_args(argv)
    try:
        arms = dict(arm_args(s) for s in a.arm)
        if len(arms) != len(a.arm) or a.rounds < 1 or a.window < 5:
            raise RunError("arm names must differ; --rounds >= 1; --window >= 5")
        a.work.mkdir(parents=True, exist_ok=True)
        print(f"config rounds={a.rounds} settle={a.settle} window={a.window} arms="
              + ";".join(f"{k}:{' '.join(v) or '-'}" for k, v in arms.items()), flush=True)
        for rnd in range(a.rounds):
            for name in rotation(list(arms), rnd):
                for line in one(a, name, arms[name], rnd):
                    print(line, flush=True)
    except RunError as e:
        print(f"run_error {e}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
