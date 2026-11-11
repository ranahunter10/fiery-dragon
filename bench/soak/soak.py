#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The soak (gate 4 of STATE decision 28): p15d under real programs for a long run, sampled as it
goes, then every operation the workload logged checked against the WAL and the graph of the run.

    sudo ~/p15venv/bin/python bench/soak/soak.py --p15d build/p15d --work /var/tmp/p15-soak \
         --duration 3600 > build/soak.txt

1. p15d starts with its defaults and a Prometheus text file; after SETTLE s, bench/soak/workload.py
   runs for DURATION s.
2. Every SAMPLE s, a "sample" line: p15d's CPU per second since the last sample (all threads, and the
   drain and writer threads), its resident memory, the WAL's bytes, and from the text file the run
   state, spine and network events, queue-full and GAP counts and the longest poll gap.
3. p15d is stopped; an "end" line: its exit code, END's state and invariant.
4. "truth" lines: per step kind, the items the workload logged and how many the WAL holds, with
   up to 5 missing ones; then "file_stats" from the last FILE_STATS (the walk's counters included).
5. The graph of the run (python -m p15.graph): its output as "graph_out" lines and its exit code,
   then "graph_truth" lines: the dropper chain of every compiled program, the http connections
   paired by ISN, and every memfd execution.
The WAL is kept (WORK/wal) unless --clean; the graph file is WORK/graph.duckdb.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))

import check as C  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
START_TIMEOUT_S = 180
STOP_TIMEOUT_S = 300
PROM = ("p15_run_state", "p15_spine_events_total:drained", "p15_spine_events_total:kernel_skipped",
        "p15_net_events_total:written", "p15_net_events_total:kernel_skipped", "p15_queue_full_total",
        "p15_gap_records_total", "p15_poll_gap_max_seconds")


class SoakError(Exception):
    pass


def prom(path: Path) -> dict[str, float]:
    """The wanted metrics from p15d's text file: 'name value', or 'name{...,cause="c",...} value' summed
    over the other labels as 'name:c'."""
    out = dict.fromkeys(PROM, 0.0)
    try:
        text = path.read_text()
    except OSError:
        return out
    for line in text.splitlines():
        if not line or line[0] == "#" or " " not in line:
            continue
        key, _, val = line.rpartition(" ")
        name, _, labels = key.partition("{")
        cause = next((x.split("=", 1)[1].strip('"') for x in labels.rstrip("}").split(",") if x.startswith("cause=")), None)
        k = f"{name}:{cause}" if cause else name
        if k in out:
            try:
                out[k] += float(val)
            except ValueError:
                pass
    return out


def threads(pid: int) -> dict[str, int]:
    out = {}
    for t in Path(f"/proc/{pid}/task").iterdir():
        try:
            name = (t / "comm").read_text().strip()
            out[name] = out.get(name, 0) + int((t / "schedstat").read_text().split()[0])
        except (FileNotFoundError, ProcessLookupError):
            continue
    return out


def rss_kb(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return -1


def du(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def wait_started(log: Path, proc: subprocess.Popen) -> None:
    t0 = time.monotonic()
    while time.monotonic() - t0 < START_TIMEOUT_S:
        if "code=start" in log.read_text(errors="replace"):
            return
        if proc.poll() is not None:
            raise SoakError(f"p15d exited {proc.returncode} before it started: {log.read_text(errors='replace')[-400:]}")
        time.sleep(0.1)
    raise SoakError("p15d did not start")


def emit(line: str) -> None:
    print(line, flush=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--p15d", type=Path, required=True)
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--duration", type=float, default=3600)
    ap.add_argument("--sample", type=float, default=60)
    ap.add_argument("--settle", type=float, default=10)
    ap.add_argument("--pause", type=float, default=1.0, help="the workload's pause between steps")
    ap.add_argument("--p15d-arg", action="append", default=[], help="an extra p15d option (repeat)")
    ap.add_argument("--clean", action="store_true", help="delete the WAL after the checks")
    a = ap.parse_args(argv)
    work = a.work.resolve()
    shutil.rmtree(work, ignore_errors=True)
    (work / "wal").mkdir(parents=True)
    textfile, log, truth_log = work / "p15d.prom", work / "p15d.log", work / "truth.jsonl"
    emit(f"config duration={a.duration:g} sample={a.sample:g} settle={a.settle:g} pause={a.pause:g} "
         f"p15d_args={','.join(a.p15d_arg) or '-'} ncpu={os.cpu_count()}")
    with open(log, "wb") as lf:
        p = subprocess.Popen([str(a.p15d), "--wal-dir", str(work / "wal"), "--textfile", str(textfile)] + a.p15d_arg,
                             stdout=lf, stderr=lf)
    wl = None
    try:
        wait_started(log, p)
        time.sleep(a.settle)
        wl = subprocess.Popen([sys.executable, str(ROOT / "bench/soak/workload.py"), "--work", str(work / "w"),
                               "--duration", str(a.duration), "--log", str(truth_log), "--pause", str(a.pause)],
                              stdout=subprocess.DEVNULL, stderr=open(work / "workload.err", "wb"))
        t_start = time.monotonic()
        prev, prev_t = threads(p.pid), time.monotonic()
        while True:
            done = wl.poll() is not None
            time.sleep(0 if done else min(a.sample, max(0.0, a.sample - (time.monotonic() - prev_t))))
            if p.poll() is not None:
                raise SoakError(f"p15d exited {p.returncode} during the soak")
            now, now_t = threads(p.pid), time.monotonic()
            dt = now_t - prev_t
            if dt > 0.5:
                d = {k: now.get(k, 0) - prev.get(k, 0) for k in now}
                m = prom(textfile)
                emit(f"sample t={now_t - t_start:.0f} cpu_ms_per_s={sum(d.values()) / dt / 1e6:.3f} "
                     f"drain_ms_per_s={d.get('p15d', 0) / dt / 1e6:.3f} writer_ms_per_s={d.get('p15d-writer', 0) / dt / 1e6:.3f} "
                     f"rss_kb={rss_kb(p.pid)} wal_bytes={du(work / 'wal')} state={int(m['p15_run_state'])} "
                     f"spine_drained={int(m['p15_spine_events_total:drained'])} "
                     f"spine_skipped={int(m['p15_spine_events_total:kernel_skipped'])} "
                     f"net_written={int(m['p15_net_events_total:written'])} "
                     f"net_skipped={int(m['p15_net_events_total:kernel_skipped'])} "
                     f"queue_full={int(m['p15_queue_full_total'])} gaps={int(m['p15_gap_records_total'])} "
                     f"poll_gap_max_s={m['p15_poll_gap_max_seconds']:.3f}")
                prev, prev_t = now, now_t
            if done:
                break
        emit(f"workload exit={wl.returncode}")
        time.sleep(3)
    except SoakError as e:
        emit(f"soak_error {e}")
    finally:
        if wl is not None and wl.poll() is None:
            wl.terminate()
            wl.wait(60)
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
        try:
            code = p.wait(STOP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            p.kill()
            code = p.wait()
    return finish(work, code, truth_log, a.clean)


def finish(work: Path, code: int, truth_log: Path, clean: bool) -> int:
    from p15 import records as R
    from p15 import wal as W
    runs = sorted(x for x in (work / "wal").iterdir() if x.is_dir())
    if len(runs) != 1:
        emit(f"soak_error expected one run directory, found {len(runs)}")
        return 1
    run_dir = runs[0]
    truth = C.Truth.load(truth_log) if truth_log.exists() else C.Truth([])
    last = {}
    errors: list = []
    t0 = time.monotonic()
    try:
        run = W.read_run(run_dir)
        n = 0
        for ring in (0, 1, 2):
            for r in run.ring_records(ring, errors):
                n += 1
                truth.see(r)
                if ring == 2:
                    last[r.name] = r
    except (W.RunError, W.HeaderError, R.RecordError, OSError) as e:
        emit(f"soak_error WAL {run_dir}: {e}")
        return 1
    end = last.get("END")
    emit(f"end exit={code} end={int(end is not None)} state={end.f['run_state'] if end else -1} "
         f"invariant={end.f['invariant'] if end else -1} records={n} read_errors={len(errors)} "
         f"stops={len(run.stops)} read_s={time.monotonic() - t0:.0f}")
    for kind, o in sorted(truth.results().items()):
        emit(f"truth step={kind} steps={o['steps']} expected={o['expected']} found={o['found']}")
        for m in o["missing"]:
            emit(f"truth_missing {m}")
    for s in truth.failed:
        emit(f"step_failed {s['step']}-{s['i']} {s.get('error', '')}")
    fs = last.get("FILE_STATS")
    if fs is not None:
        emit("file_stats " + " ".join(f"{k}={fs.f[k]}" for k in (
            "open_emitted", "missing_emitted", "walked", "walk_raced", "walk_truncated", "walk_unnamed", "open_lost",
            "missing_lost", "close_lost", "fentry_missed", "kprobe_missed", "files_live_max", "objs_live_max")
            if k in fs.f))
    db = work / "graph.duckdb"
    t0 = time.monotonic()
    g = subprocess.run([sys.executable, "-m", "p15.graph", str(run_dir), str(db)], capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=str(ROOT / "python")))
    for line in (g.stdout + g.stderr).splitlines():
        emit(f"graph_out {line}")
    emit(f"graph rc={g.returncode} build_s={time.monotonic() - t0:.0f} bytes={db.stat().st_size if db.exists() else 0}")
    if db.exists():
        for name, (got, want) in C.graph_check(db, truth).items():
            emit(f"graph_truth {name} found={got} expected={want}")
    if clean:
        shutil.rmtree(work / "wal", ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
