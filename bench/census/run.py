#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the event-rate census over a set of workloads and collect the evidence.

For each workload:
  1. start census.bt (bpftrace -f json) and wait until it reports it is attached;
  2. run the workload for a fixed duration, as the invoking (non-root) user;
  3. stop the census with SIGINT, so its END block prints the final totals;
  4. summarize the run (summarize.py) into <name>.md and <name>.json.

Everything that could change a number goes into conditions.json: kernel,
bpftrace version, probe hash, git commit, swap state, CPUs, memory, load, and
the operator's notes on host power mode and Hyper-V. A workload whose tools
are missing is SKIPPED and listed, never silently left out.

Usage (on the VM):
    sudo python3 bench/census/run.py --workloads light --duration 60 \\
        --snapshot 01-toolchain --host-note "plugged in, Best performance, Hyper-V on"
    python3 bench/census/run.py --list
    python3 bench/census/run.py --workloads light --dry-run
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import pwd
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import summarize as S  # noqa: E402

ATTACH_TIMEOUT_S = 90      # fexit attach of ~20 probes takes a few seconds; leave room
STOP_TIMEOUT_S = 30
SAFETY_GRACE_S = 30        # workloads stop themselves; the runner kills them only past duration + grace
SETTLE_S = 3               # quiet gap between workloads


@dataclass(frozen=True)
class Workload:
    name: str
    group: str
    summary: str
    needs: tuple[str, ...]   # executables that must be on PATH
    script: str              # bash; env: DURATION (s), WORK (scratch dir), HERE (bench/census)
    reference: str = ""      # published workload it approximates, if any


# Each script stops by itself after $DURATION seconds.
WORKLOADS: tuple[Workload, ...] = (
    Workload("idle", "light", "Nothing runs: the background floor of the VM.",
             ("sleep",), 'sleep "$DURATION"'),
    Workload("exec-storm", "light", "Execute /bin/echo in a tight loop.",
             ("bash",),
             'end=$((SECONDS+DURATION)); while [ "$SECONDS" -lt "$end" ]; do /bin/echo x >/dev/null; done',
             reference="Houssel et al. shbm (50,000 echo execs), time-bounded here"),
    Workload("file-churn", "light", "PostMark-style create/append/read/delete of 500 small files.",
             ("python3",),
             'python3 "$HERE/workloads/filechurn.py" --dir "$WORK/churn" --duration "$DURATION"',
             reference="PostMark-shaped (Houssel et al. used PostMark); parameters are ours"),
    Workload("super-producer", "light", "Five concurrent `find /usr` loops: a syscall flood.",
             ("bash", "find"),
             'for i in 1 2 3 4 5; do ( end=$((SECONDS+DURATION)); '
             'while [ "$SECONDS" -lt "$end" ]; do find /usr >/dev/null 2>&1; done ) & done; wait',
             reference="Mao, Ujcich & Ma super-producer (find over /usr, 5 threads)"),
    Workload("xfer", "light", "In-kernel copies: cp (copy_file_range), cat (splice), sendfile.",
             ("bash", "cp", "cat", "python3", "dd"),
             'dd if=/dev/urandom of="$WORK/src" bs=1M count=64 status=none; '
             'end=$((SECONDS+DURATION)); while [ "$SECONDS" -lt "$end" ]; do '
             'cp "$WORK/src" "$WORK/dst"; cat "$WORK/src" >/dev/null; '
             'python3 -c "import os,sys; i=os.open(sys.argv[1],os.O_RDONLY); o=os.open(sys.argv[2],os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o644); '
             'n=os.fstat(i).st_size; s=0\nwhile s<n: s+=os.sendfile(o,i,s,n-s)" "$WORK/src" "$WORK/dst2"; '
             'done; rm -f "$WORK/src" "$WORK/dst" "$WORK/dst2"'),
    Workload("io-uring", "light", "fio random read/write through io_uring on a 256 MiB file.",
             ("fio",),
             'fio --name=uring --ioengine=io_uring --rw=randrw --bs=4k --size=256M --iodepth=16 '
             '--directory="$WORK" --time_based --runtime="$DURATION" --output-format=terse >/dev/null'),
    Workload("known-ops", "check", "Exact numbers of every META, NET and capability operation; verified against the census.",
             ("python3",),
             'python3 "$HERE/workloads/knownops.py" --dir "$WORK/ko" --k 50 --duration "$DURATION"',
             reference="self-test: census count must be >= what succeeded in userspace"),
)

GROUPS = {g: [w.name for w in WORKLOADS if w.group == g] for g in ("light", "check")}
GROUPS["all"] = [w.name for w in WORKLOADS]


class RunError(RuntimeError):
    pass


def select(spec: str) -> list[Workload]:
    """'light', 'all', or comma-separated names; order kept, duplicates removed."""
    by_name = {w.name: w for w in WORKLOADS}
    names: list[str] = []
    for item in (s.strip() for s in spec.split(",") if s.strip()):
        expanded = GROUPS.get(item, [item])
        for n in expanded:
            if n not in by_name:
                raise RunError(f"unknown workload {n!r}; known: {', '.join(by_name)}; groups: {', '.join(GROUPS)}")
            if n not in names:
                names.append(n)
    if not names:
        raise RunError("no workloads selected")
    return [by_name[n] for n in names]


def missing_tools(w: Workload, which: Callable[[str], str | None] = shutil.which) -> list[str]:
    return [t for t in w.needs if which(t) is None]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def meminfo_kb(text: str, key: str) -> int | None:
    for line in text.splitlines():
        if line.startswith(key + ":"):
            return int(line.split()[1])
    return None


def sh(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return (r.stdout or r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"<error: {e}>"


def workload_user() -> str | None:
    """Run workloads as the human who called sudo, not as root."""
    user = os.environ.get("SUDO_USER")
    return user if os.geteuid() == 0 and user and user != "root" else None


def conditions(args: argparse.Namespace, user: str | None) -> dict:
    meminfo = Path("/proc/meminfo").read_text()
    lscpu = sh(["lscpu"])
    return {
        "utc_start": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "kernel": platform.release(),
        "bpftrace": sh([args.bpftrace, "--version"]),
        "probe": str(args.probe), "probe_sha256": sha256(args.probe),
        "summarize_sha256": sha256(HERE / "summarize.py"),
        "runner_sha256": sha256(Path(__file__).resolve()),
        "git_commit": sh(["git", "-C", str(HERE), "rev-parse", "HEAD"]),
        "git_dirty": bool(sh(["git", "-C", str(HERE), "status", "--porcelain"])),
        "python": platform.python_version(),
        "cpus": os.cpu_count(),
        "mem_total_kb": meminfo_kb(meminfo, "MemTotal"),
        "hypervisor_vendor": next((l.split(":", 1)[1].strip() for l in lscpu.splitlines()
                                   if l.startswith("Hypervisor vendor")), None),
        "virt": sh(["systemd-detect-virt"]),
        "swap_before": sh(["swapon", "--show", "--noheadings"]) or "none",
        "swapoff_during_runs": args.swapoff,
        "drop_caches_before_each": args.drop_caches,
        "loadavg_before": Path("/proc/loadavg").read_text().strip(),
        "io_uring_disabled": (Path("/proc/sys/kernel/io_uring_disabled").read_text().strip()
                              if Path("/proc/sys/kernel/io_uring_disabled").exists() else "n/a"),
        "disk_mbps_budget_input": args.disk_mbps, "headroom": args.headroom,
        "duration_s": args.duration,
        "workload_user": user or "root",
        "snapshot": args.snapshot,
        "host_note": args.host_note,
    }


PROBE_RE = re.compile(r"^(fexit|fentry):vmlinux:([A-Za-z0-9_]+)|^tracepoint:([a-z0-9_]+):([a-z0-9_]+)", re.M)


def probe_targets(probe_text: str) -> tuple[set[str], set[str]]:
    """Kernel functions and tracepoints a bpftrace script attaches to."""
    funcs, tps = set(), set()
    for m in PROBE_RE.finditer(probe_text):
        if m.group(2):
            funcs.add(m.group(2))
        else:
            tps.add(f"{m.group(3)}/{m.group(4)}")
    return funcs, tps


def missing_targets(funcs: set[str], tps: set[str], btf_funcs: set[str] | None,
                    ftrace_funcs: set[str] | None, events_dir: Path) -> list[str]:
    """What the probe needs but this kernel does not offer. None for a set means unverifiable."""
    missing = []
    for f in sorted(funcs):
        if btf_funcs is not None and f not in btf_funcs:
            missing.append(f"{f} (not in BTF)")
        elif ftrace_funcs is not None and f not in ftrace_funcs:
            missing.append(f"{f} (not traceable)")
    missing += [f"tracepoint {t}" for t in sorted(tps) if not (events_dir / t).is_dir()]
    return missing


def kernel_symbols() -> tuple[set[str] | None, set[str] | None]:
    btf = None
    if shutil.which("bpftool"):
        out = sh(["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "raw"])
        btf = set(re.findall(r"FUNC '([A-Za-z0-9_]+)'", out)) or None
    try:
        text = Path("/sys/kernel/tracing/available_filter_functions").read_text()
        ftrace = {line.split()[0] for line in text.splitlines() if line}
    except OSError:
        ftrace = None
    return btf, ftrace


def start_census(bpftrace: str, probe: Path, raw: Path, err: Path) -> subprocess.Popen:
    out_f, err_f = open(raw, "w"), open(err, "w")
    p = subprocess.Popen([bpftrace, "-f", "json", str(probe)], stdout=out_f, stderr=err_f)
    out_f.close(); err_f.close()
    deadline = time.monotonic() + ATTACH_TIMEOUT_S
    while time.monotonic() < deadline:
        if p.poll() is not None:
            raise RunError(f"bpftrace exited ({p.returncode}) before attaching; see {err}")
        if S.START_RE.search(raw.read_text(errors="replace")):
            return p
        time.sleep(0.2)
    stop_census(p)
    raise RunError(f"census did not attach within {ATTACH_TIMEOUT_S} s; see {err}")


def stop_census(p: subprocess.Popen) -> bool:
    """SIGINT so END prints the totals. True if it stopped cleanly."""
    if p.poll() is not None:
        return p.returncode == 0
    p.send_signal(signal.SIGINT)
    try:
        return p.wait(timeout=STOP_TIMEOUT_S) == 0
    except subprocess.TimeoutExpired:
        p.kill(); p.wait()
        return False


def run_workload(w: Workload, duration: int, work: Path, log: Path, user: str | None) -> dict:
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
           "DURATION": str(duration), "WORK": str(work), "HERE": str(HERE),
           "HOME": pwd.getpwnam(user).pw_dir if user else "/root"}
    cmd = ["bash", "-c", w.script]
    if user:
        cmd = ["runuser", "-u", user, "--", "env", *[f"{k}={v}" for k, v in env.items()], *cmd]
    t0 = time.monotonic()
    with open(log, "w") as lf:
        p = subprocess.Popen(cmd, env=env, stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            rc = p.wait(timeout=duration + SAFETY_GRACE_S)
            killed = False
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            rc, killed = p.wait(), True
    return {"exit_code": rc, "killed_after_grace": killed, "elapsed_s": round(time.monotonic() - t0, 2)}


def expectations(log_text: str) -> dict[str, int] | None:
    """The {"expect": {...}} a self-checking workload prints as its last JSON line, or None."""
    for line in reversed(log_text.strip().splitlines()):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("expect"), dict):
            return {str(k): int(v) for k, v in obj["expect"].items()}
    return None


def shortfalls(expect: dict[str, int], summary: dict) -> list[str]:
    """Classes the census counted fewer times than the workload provably did them."""
    got = {r["class"]: r["total"] for r in summary["rows"]}
    return [f"{cls} {got.get(cls, 0)} < {n}" for cls, n in sorted(expect.items()) if got.get(cls, 0) < n]


def classify(clean_stop: bool, summary: dict, workload: dict, missed: list[str] | None = None) -> str:
    """'ok' only if the census stopped cleanly, is complete, lost nothing, the workload ran
    normally, and every expected count was reached."""
    problems = []
    if not clean_stop:
        problems.append("bpftrace did not stop cleanly")
    if not summary["complete"]:
        problems.append("census output incomplete")
    if summary["lost_events"]:
        problems.append(f"bpftrace lost {summary['lost_events']} events")
    if workload["killed_after_grace"]:
        problems.append("workload overran and was killed")
    elif workload["exit_code"] != 0:
        problems.append(f"workload exit {workload['exit_code']}")
    if missed:
        problems.append("hook missed events: " + ", ".join(missed))
    return "ok" if not problems else "FAILED (" + "; ".join(problems) + ")"


def render_index(conds: dict, results: list[dict]) -> str:
    out = ["# Census run", "",
           f"- UTC start: {conds['utc_start']}; kernel {conds['kernel']}; {conds['bpftrace']}",
           f"- git {conds['git_commit'][:12]}{' (dirty)' if conds['git_dirty'] else ''}; "
           f"probe sha256 {conds['probe_sha256'][:12]}",
           f"- {conds['cpus']} CPUs, {conds['mem_total_kb']} kB RAM; hypervisor {conds['hypervisor_vendor']} ({conds['virt']}); "
           f"swap before: {conds['swap_before']}; swapoff during runs: {conds['swapoff_during_runs']}",
           f"- duration per workload: {conds['duration_s']} s; workloads run as: {conds['workload_user']}; "
           f"snapshot: {conds['snapshot']}; host: {conds['host_note']}", "",
           "| workload | status | records/s mean | p99 | max | log MB/s p99 | verdict |",
           "|---|---|---:|---:|---:|---:|---|"]
    for r in results:
        s = r.get("summary")
        if s:
            out.append(f"| {r['name']} | {r['status']} | {s['emitted_records_mean_per_s']:,.0f} | "
                       f"{s['emitted_records_p99_per_s']:,.0f} | {s['emitted_records_max_per_s']:,.0f} | "
                       f"{s['log_bytes_p99_per_s']/1e6:.2f} | {s['verdict']} |")
        else:
            out.append(f"| {r['name']} | {r['status']} | | | | | |")
    checked = [r for r in results if "expect" in r]
    for r in checked:
        got = {row["class"]: row["total"] for row in r["summary"]["rows"]}
        out += ["", f"**Self-check `{r['name']}`** (census count must be >= operations that succeeded):", "",
                "| class | expected | counted | |", "|---|---:|---:|---|"]
        out += [f"| {c} | {n} | {got.get(c, 0)} | {'✅' if got.get(c, 0) >= n else '❌ MISSED'} |"
                for c, n in sorted(r["expect"].items())]
    out += ["", "Per-workload detail: `<workload>.md`. Raw: `<workload>.jsonl`. Conditions: `conditions.json`.", ""]
    return "\n".join(out)


def plan(selected: list[Workload], which: Callable[[str], str | None] = shutil.which) -> list[tuple[Workload, list[str]]]:
    return [(w, missing_tools(w, which)) for w in selected]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--workloads", default="light", help="group (light, all) or comma-separated names")
    ap.add_argument("--duration", type=int, default=60, help="seconds per workload (default 60; >= 60 for a meaningful p99)")
    ap.add_argument("--out", type=Path, default=None, help="output dir (default /var/tmp/fd-census/<UTC time>)")
    ap.add_argument("--probe", type=Path, default=HERE / "census.bt")
    ap.add_argument("--bpftrace", default="bpftrace")
    ap.add_argument("--disk-mbps", type=float, default=63.7,
                    help="sustained disk MB/s for the budget (default: P5 minimum, docs/evidence/phase0/05-p5-disk.txt)")
    ap.add_argument("--headroom", type=float, default=3.0, help="budget headroom factor (default 3)")
    ap.add_argument("--snapshot", default="unrecorded", help="VM snapshot the run is based on")
    ap.add_argument("--host-note", default="unrecorded", help="host power mode, Hyper-V state, other load")
    ap.add_argument("--no-swapoff", dest="swapoff", action="store_false", help="leave swap on (default: off while measuring)")
    ap.add_argument("--drop-caches", action="store_true", help="drop page cache before each workload")
    ap.add_argument("--skip-attach-check", action="store_true", help="run even if the pre-flight finds missing hooks")
    ap.add_argument("--keep-work", action="store_true", help="keep scratch directories")
    ap.add_argument("--list", action="store_true", help="list workloads and exit")
    ap.add_argument("--dry-run", action="store_true", help="show the plan and missing tools; run nothing")
    args = ap.parse_args(argv)

    if args.list:
        for w in WORKLOADS:
            print(f"{w.name:15s} [{w.group}] {w.summary}" + (f"  (~ {w.reference})" if w.reference else ""))
        return 0
    try:
        selected = select(args.workloads)
    except RunError as e:
        ap.error(str(e))
    steps = plan(selected)
    if args.dry_run:
        for w, miss in steps:
            print(f"{'SKIP' if miss else 'RUN '} {w.name:15s} {args.duration:>4d} s" +
                  (f"  missing: {', '.join(miss)}" if miss else ""))
        return 0

    if os.geteuid() != 0:
        ap.error("must run as root (bpftrace); use sudo")
    if shutil.which(args.bpftrace) is None:
        ap.error(f"bpftrace not found: {args.bpftrace}")
    funcs, tps = probe_targets(args.probe.read_text())
    btf, ftrace = kernel_symbols()
    missing = missing_targets(funcs, tps, btf, ftrace, Path("/sys/kernel/tracing/events"))
    print(f"[census] attach pre-flight: {len(funcs)} functions, {len(tps)} tracepoints; "
          f"BTF {'checked' if btf is not None else 'UNVERIFIABLE'}, "
          f"ftrace {'checked' if ftrace is not None else 'UNVERIFIABLE'}; missing: {missing or 'none'}", flush=True)
    if missing and not args.skip_attach_check:
        ap.error("probe needs what this kernel lacks: " + "; ".join(missing))
    user = workload_user()
    out = args.out or Path("/var/tmp/fd-census") / dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True, exist_ok=False)
    conds = conditions(args, user)
    (out / "conditions.json").write_text(json.dumps(conds, indent=2) + "\n")

    swap_was_on = conds["swap_before"] != "none"
    results: list[dict] = []
    try:
        if args.swapoff and swap_was_on:
            subprocess.run(["swapoff", "-a"], check=True)
        for w, miss in steps:
            r: dict = {"name": w.name}
            results.append(r)
            if miss:
                r["status"] = f"SKIPPED (missing {', '.join(miss)})"
                print(f"[census] {w.name}: {r['status']}", flush=True)
                continue
            work = out / "work" / w.name
            work.mkdir(parents=True)
            if user:
                shutil.chown(work, user=user)
                shutil.chown(work.parent, user=user)
            if args.drop_caches:
                subprocess.run(["sync"], check=True)
                Path("/proc/sys/vm/drop_caches").write_text("3\n")
            time.sleep(SETTLE_S)
            print(f"[census] {w.name}: attaching probe...", flush=True)
            raw, err = out / f"{w.name}.jsonl", out / f"{w.name}.bpftrace.err"
            try:
                p = start_census(args.bpftrace, args.probe, raw, err)
            except RunError as e:
                r["status"] = f"FAILED ({e})"
                print(f"[census] {w.name}: {r['status']}", flush=True)
                continue
            print(f"[census] {w.name}: running {args.duration} s...", flush=True)
            try:
                r["workload"] = run_workload(w, args.duration, work, out / f"{w.name}.workload.log", user)
            finally:
                clean_stop = stop_census(p)
            census = S.parse(raw.read_text().splitlines())
            s = S.summarize(census, label=w.name, disk_mbps=args.disk_mbps, headroom=args.headroom,
                            sizes=dict(S.DEFAULT_SIZE_OVERRIDES), default_size=S.DEFAULT_RECORD_BYTES)
            (out / f"{w.name}.md").write_text(S.to_markdown(s))
            (out / f"{w.name}.json").write_text(json.dumps(s, indent=2) + "\n")
            r["summary"] = s
            expect = expectations((out / f"{w.name}.workload.log").read_text(errors="replace"))
            if expect is not None:
                r["expect"] = expect
                r["missed"] = shortfalls(expect, s)
            r["status"] = classify(clean_stop, s, r["workload"], r.get("missed"))
            print(f"[census] {w.name}: {r['status']}; {s['emitted_records_mean_per_s']:,.0f} records/s mean, "
                  f"p99 {s['emitted_records_p99_per_s']:,.0f}", flush=True)
            if not args.keep_work:
                shutil.rmtree(work, ignore_errors=True)
    finally:
        if args.swapoff and swap_was_on:
            subprocess.run(["swapon", "-a"], check=False)
        index = render_index(conds, results)
        (out / "index.md").write_text(index)
        (out / "results.json").write_text(json.dumps(
            [{k: v for k, v in r.items() if k != "summary"} for r in results], indent=2) + "\n")
        print("\n" + index + f"\nResults in {out}")
    return 0 if all(r["status"] == "ok" or r["status"].startswith("SKIPPED") for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
