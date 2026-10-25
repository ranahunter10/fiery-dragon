# SPDX-License-Identifier: MIT
"""Shared plumbing for the small phase-0 probes (P6, P8): build a test program,
start a bpftrace script and wait until it is attached, run the program as the
sudo user, stop the script cleanly, and record the conditions.

Each probe's own run.py holds the question, the expected results and the
analysis. This file holds nothing a reviewer needs to judge a result.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import platform
import pwd
import signal
import subprocess
import time
from pathlib import Path

ATTACH_TIMEOUT_S = 60
STOP_TIMEOUT_S = 30


class ProbeError(RuntimeError):
    pass


def sh(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return (r.stdout or r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"<error: {e}>"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sudo_user() -> str | None:
    """Test programs run as the human who called sudo, not as root."""
    user = os.environ.get("SUDO_USER")
    return user if os.geteuid() == 0 and user and user != "root" else None


def conditions(here: Path, files: list[Path], bpftrace: str) -> dict:
    cfg = Path(f"/boot/config-{platform.release()}")
    ia32 = ([l for l in cfg.read_text().splitlines() if "IA32_EMULATION" in l] if cfg.exists() else ["<no config>"])
    return {
        "utc_start": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "kernel": platform.release(),
        "cmdline": Path("/proc/cmdline").read_text().strip(),
        "kconfig_ia32": ia32,
        "bpftrace": sh([bpftrace, "--version"]),
        "gcc": sh(["gcc", "--version"]).splitlines()[0] if sh(["gcc", "--version"]) else None,
        "git_commit": sh(["git", "-C", str(here), "rev-parse", "HEAD"]),
        "git_dirty": bool(sh(["git", "-C", str(here), "status", "--porcelain"])),
        "sha256": {f.name: sha256(f) for f in files},
        "cpus": os.cpu_count(),
        "loadavg_before": Path("/proc/loadavg").read_text().strip(),
        "user": sudo_user() or "root",
    }


def build(src: Path, out: Path, flags: list[str], log: Path) -> bool:
    """Compile src with gcc. The full compiler output goes to log, success or not."""
    cmd = ["gcc", *flags, "-o", str(out), str(src)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    log.write_text(" ".join(cmd) + f"\nexit {r.returncode}\n" + r.stdout + r.stderr)
    return r.returncode == 0


def start_probe(bpftrace: str, script: Path, out: Path, err: Path, marker: str) -> subprocess.Popen:
    """Start bpftrace (text output) and return once `marker` (printed in BEGIN) appears."""
    out_f, err_f = open(out, "w"), open(err, "w")
    p = subprocess.Popen([bpftrace, str(script)], stdout=out_f, stderr=err_f)
    out_f.close(); err_f.close()
    deadline = time.monotonic() + ATTACH_TIMEOUT_S
    while time.monotonic() < deadline:
        if p.poll() is not None:
            raise ProbeError(f"bpftrace exited ({p.returncode}) before attaching; see {err}")
        if marker in out.read_text(errors="replace"):
            return p
        time.sleep(0.2)
    stop_probe(p)
    raise ProbeError(f"probe did not attach within {ATTACH_TIMEOUT_S} s; see {err}")


def stop_probe(p: subprocess.Popen) -> bool:
    """SIGINT so END runs. True if bpftrace stopped cleanly."""
    if p.poll() is not None:
        return p.returncode == 0
    time.sleep(0.5)  # let the last events reach the output buffer
    p.send_signal(signal.SIGINT)
    try:
        return p.wait(timeout=STOP_TIMEOUT_S) == 0
    except subprocess.TimeoutExpired:
        p.kill(); p.wait()
        return False


def run_as(user: str | None, argv: list[str], out: Path, timeout: int, cwd: Path) -> int:
    """Run argv as `user` (or as the caller), stdout+stderr to out. Returns the exit code; -9 if killed."""
    cmd = (["runuser", "-u", user, "--"] if user else []) + argv
    with open(out, "w") as f:
        try:
            return subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=timeout, cwd=cwd,
                                  env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                       "HOME": pwd.getpwnam(user).pw_dir if user else "/root"}).returncode
        except subprocess.TimeoutExpired:
            return -9
