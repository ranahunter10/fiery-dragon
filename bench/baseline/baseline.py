#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed-work baselines: how fast is this machine, how stable is it, and what does tracing cost?

For each round, run every job (jobs.py) untraced and under a probe (default:
the census probe). The order is counterbalanced: odd rounds run untraced
first, even rounds traced first, so warm-up effects cancel instead of looking
like overhead. Then report, per job and configuration:

    n, mean, standard deviation, CV % (the drift indicator), min, max
    and the tracing overhead (slowdown %, comparing means).

This is phase-0 probe P12 (untraced baselines) and the instrument for the
Hyper-V on/off experiment (E-0029, E-0036). Must run as root (bpftrace); jobs
run as the invoking user.

    sudo python3 bench/baseline/baseline.py --label hyperv-on-A1 --rounds 3 \\
        --host-note "Hyper-V on, plugged in, Best performance"
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "census"))
import run as R  # noqa: E402  (census runner: workload launching, probe start/stop, conditions)
sys.path.insert(0, str(HERE))
import jobs as J  # noqa: E402

JOB_TIMEOUT_S = 600   # a job that takes longer than this is broken; run_workload kills it
UNSTABLE_CV_PCT = 10.0  # above this spread, a mean (and any slowdown built on it) is not quotable


def round_order(round_no: int, traced: bool) -> list[str]:
    """Counterbalanced configuration order: odd rounds untraced first, even rounds traced first."""
    if not traced:
        return ["none"]
    return ["none", "traced"] if round_no % 2 == 1 else ["traced", "none"]


def parse_job_line(log_text: str) -> dict | None:
    for line in reversed(log_text.strip().splitlines()):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "job" in obj and "value" in obj:
            return obj
    return None


def aggregate(results: list[dict]) -> list[dict]:
    """Per (job, config): n, mean, sd, cv %, min, max; plus tracing slowdown % per job."""
    rows = []
    jobs = sorted({r["job"] for r in results}, key=list(J.JOBS).index)
    for job in jobs:
        unit, better, _ = J.JOBS[job]
        means = {}
        for cfg in ("none", "traced"):
            vals = [r["value"] for r in results if r["job"] == job and r["config"] == cfg and r["value"] is not None]
            if not vals:
                continue
            mean = statistics.fmean(vals)
            sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
            means[cfg] = mean
            rows.append({"job": job, "config": cfg, "unit": unit, "better": better, "n": len(vals),
                         "mean": mean, "sd": sd, "cv_pct": 100 * sd / mean if mean else 0.0,
                         "min": min(vals), "max": max(vals)})
        if "none" in means and "traced" in means and means["none"] and means["traced"]:
            # slowdown: >0 means tracing made the job slower, whatever the unit's direction
            slow = (means["traced"] / means["none"] - 1) if better == "lower" else (means["none"] / means["traced"] - 1)
            for row in rows:
                if row["job"] == job:
                    row["tracing_slowdown_pct"] = 100 * slow
    return rows


def render(conds: dict, rows: list[dict], label: str) -> str:
    out = [f"# Baseline: {label}", "",
           f"- UTC start {conds['utc_start']}; kernel {conds['kernel']}; {conds['bpftrace']}; "
           f"git {conds['git_commit'][:12]}{' (dirty)' if conds['git_dirty'] else ''}",
           f"- {conds['cpus']} CPUs, {conds['mem_total_kb']} kB; hypervisor seen by guest: {conds['hypervisor_vendor']} "
           f"({conds['virt']}); swap before: {conds['swap_before']}",
           f"- host note: {conds['host_note']}; snapshot: {conds['snapshot']}", "",
           "| job | config | n | mean | sd | CV % | min | max | tracing slowdown |",
           "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    unstable_jobs = {r["job"] for r in rows if r["cv_pct"] > UNSTABLE_CV_PCT}
    for r in rows:
        slow = ""
        if "tracing_slowdown_pct" in r and r["config"] == "traced":
            slow = f"{r['tracing_slowdown_pct']:+.0f} %" + (" ⚠ not quotable" if r["job"] in unstable_jobs else "")
        cv = f"{r['cv_pct']:.1f}" + (" ⚠" if r["cv_pct"] > UNSTABLE_CV_PCT else "")
        out.append(f"| {r['job']} | {r['config']} | {r['n']} | {r['mean']:.2f} {r['unit']} | {r['sd']:.2f} | "
                   f"{cv} | {r['min']:.2f} | {r['max']:.2f} | {slow} |")
    out += ["", f"CV % = standard deviation / mean over rounds: the drift indicator. ⚠ marks CV > {UNSTABLE_CV_PCT:.0f} %: "
            "that mean, and any slowdown computed from it, is not quotable. Slowdown > 0 means tracing made the job slower.", ""]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--label", required=True, help="name of this configuration, e.g. hyperv-on-A1")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--jobs", default=",".join(J.JOBS), help="comma-separated subset of: " + ", ".join(J.JOBS))
    ap.add_argument("--probe", type=Path, default=HERE.parent / "census" / "census.bt", help="probe for the traced config")
    ap.add_argument("--untraced-only", action="store_true")
    ap.add_argument("--bpftrace", default="bpftrace")
    ap.add_argument("--snapshot", default="unrecorded")
    ap.add_argument("--host-note", default="unrecorded", help="Hyper-V state, power mode, other load (the guest cannot see these)")
    ap.add_argument("--no-swapoff", dest="swapoff", action="store_false")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    jobs = [j.strip() for j in args.jobs.split(",") if j.strip()]
    unknown = [j for j in jobs if j not in J.JOBS]
    if unknown or not jobs:
        ap.error(f"unknown jobs: {unknown}; known: {', '.join(J.JOBS)}")
    traced = not args.untraced_only
    if args.dry_run:
        for rnd in range(1, args.rounds + 1):
            print(f"round {rnd}: " + "  then  ".join(f"[{c}] {', '.join(jobs)}" for c in round_order(rnd, traced)))
        return 0
    if os.geteuid() != 0:
        ap.error("must run as root (bpftrace); use sudo")

    user = R.workload_user()
    out = args.out or Path("/var/tmp/fd-baseline") / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + args.label)
    out.mkdir(parents=True, exist_ok=False)
    cond_args = argparse.Namespace(bpftrace=args.bpftrace, probe=args.probe, swapoff=args.swapoff, drop_caches=False,
                                   duration=0, snapshot=args.snapshot, host_note=args.host_note,
                                   disk_mbps=0.0, headroom=0.0)
    conds = R.conditions(cond_args, user)
    conds.update({"label": args.label, "rounds": args.rounds, "jobs": jobs, "traced": traced})
    (out / "conditions.json").write_text(json.dumps(conds, indent=2) + "\n")

    work = out / "work"
    work.mkdir()
    if user:
        shutil.chown(work, user=user)
    swap_was_on = conds["swap_before"] != "none"
    results: list[dict] = []
    try:
        if args.swapoff and swap_was_on:
            subprocess.run(["swapoff", "-a"], check=True)
        for rnd in range(1, args.rounds + 1):
            for cfg in round_order(rnd, traced):
                probe_proc = None
                if cfg == "traced":
                    probe_proc = R.start_census(args.bpftrace, args.probe, out / f"r{rnd}-probe.jsonl", out / f"r{rnd}-probe.err")
                try:
                    for job in jobs:
                        w = R.Workload(job, "baseline", J.JOBS[job][2], ("python3",),
                                       f'python3 "$HERE/../baseline/jobs.py" {job} --work "$WORK"')
                        log = out / f"r{rnd}-{cfg}-{job}.log"
                        res = R.run_workload(w, JOB_TIMEOUT_S, work, log, user)
                        parsed = parse_job_line(log.read_text(errors="replace"))
                        value = parsed["value"] if parsed and res["exit_code"] == 0 else None
                        skipped = parsed.get("skipped") if parsed and res["exit_code"] == 0 else None
                        results.append({"round": rnd, "config": cfg, "job": job, "value": value, "skipped": skipped,
                                        "exit_code": res["exit_code"], "killed": res["killed_after_grace"]})
                        status = (f"SKIPPED ({skipped})" if skipped else
                                  f"FAILED (see {log.name})" if value is None else f"{value:.2f} {J.JOBS[job][0]}")
                        print(f"[baseline] round {rnd} {cfg:6s} {job:13s} {status}", flush=True)
                finally:
                    if probe_proc is not None:
                        R.stop_census(probe_proc)
    finally:
        if args.swapoff and swap_was_on:
            subprocess.run(["swapon", "-a"], check=False)
        rows = aggregate(results)
        (out / "results.json").write_text(json.dumps({"results": results, "summary": rows}, indent=2) + "\n")
        report = render(conds, rows, args.label)
        (out / "index.md").write_text(report)
        print("\n" + report + f"\nResults in {out}")
    return 0 if all(r["value"] is not None or r["skipped"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
