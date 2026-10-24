#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed-work jobs that time themselves. Each prints one JSON line:
    {"job": NAME, "value": X, "unit": "s" | "ops/s" | "MB/s", "better": "lower" | "higher"}

Used by baseline.py to compare configurations: untraced vs traced, and host
settings such as Hyper-V on/off. A job measures only its own work, so process
start-up (sudo, runuser) is never part of the number.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "census"))
from workloads import filechurn  # noqa: E402

JOBS = {
    "find-serial":   ("s", "lower", "find /usr three times in sequence"),
    "find-parallel": ("s", "lower", "five concurrent find /usr (the census super-producer shape)"),
    "exec":          ("s", "lower", "2,000 executions of /bin/true from a bash loop"),
    "churn":         ("ops/s", "higher", "10 s of PostMark-style small-file churn (workloads/filechurn.py)"),
    "disk":          ("MB/s", "higher", "20 s sequential 1 MiB direct writes with fio (P5 test A)"),
}


def _find(n_parallel: int, repeats: int) -> float:
    t = time.monotonic()
    for _ in range(repeats):
        ps = [subprocess.Popen(["find", "/usr"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
              for _ in range(n_parallel)]
        for p in ps:
            p.wait()
    return time.monotonic() - t


def run_job(name: str, work: str) -> float | None:
    """Run one job; return its value, or None if a tool it needs is missing."""
    if name == "find-serial":
        return _find(1, 3)
    if name == "find-parallel":
        return _find(5, 1)
    if name == "exec":
        t = time.monotonic()
        subprocess.run(["bash", "-c", "for i in $(seq 2000); do /bin/true; done"], check=True)
        return time.monotonic() - t
    if name == "churn":
        stats = filechurn.churn(os.path.join(work, "churn"), duration=10.0, files=500,
                                min_size=512, max_size=16384, seed=15)
        return sum(stats[k] for k in ("create", "append", "read", "delete")) / 10.0
    if name == "disk":
        if shutil.which("fio") is None:
            return None
        out = subprocess.run(["fio", "--name=seq", "--rw=write", "--bs=1M", "--direct=1", "--ioengine=libaio",
                              "--iodepth=8", "--size=2G", "--runtime=20", "--time_based",
                              f"--filename={os.path.join(work, 'fio.dat')}", "--output-format=json"],
                             capture_output=True, text=True, check=True).stdout
        os.remove(os.path.join(work, "fio.dat"))
        return parse_fio_write_mbps(out)
    raise ValueError(f"unknown job {name!r}")


def parse_fio_write_mbps(fio_json: str) -> float:
    """Write bandwidth of the first fio job, in MB/s (10^6 bytes)."""
    data = json.loads(fio_json[fio_json.index("{"):])   # fio may print a notice before the JSON
    return data["jobs"][0]["write"]["bw_bytes"] / 1e6


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("job", choices=sorted(JOBS))
    ap.add_argument("--work", default=os.environ.get("WORK", "/tmp"), help="scratch directory")
    args = ap.parse_args(argv)
    os.makedirs(args.work, exist_ok=True)
    value = run_job(args.job, args.work)
    unit, better, _ = JOBS[args.job]
    line = {"job": args.job, "value": value, "unit": unit, "better": better}
    if value is None:
        line["skipped"] = "required tool not installed (fio)"
    print(json.dumps(line))
    return 0


if __name__ == "__main__":
    sys.exit(main())
