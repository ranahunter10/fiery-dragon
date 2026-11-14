#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# trace: full
# Attack 3, code with no file left on disk: python3 copies `uname` into a memfd and runs it (R2,
# and R1: written by one process, run by another); then copies `hostname` to a hidden file on the
# work directory's disk filesystem, unlinks it while holding it open and runs it through
# /proc/self/fd (R3).
set -eu
W=$1 M=$2
python3 - "$W" <<'PY'
import os, sys
w = sys.argv[1]
fd = os.memfd_create("kworker")
os.write(fd, open("/usr/bin/uname", "rb").read())
pid = os.fork()
if pid == 0:
    os.execv(f"/proc/self/fd/{fd}", ["kworker", "-a"])
os.waitpid(pid, 0)
p = f"{w}/.hidden-upd"
with open("/usr/bin/hostname", "rb") as src, open(p, "wb") as dst:
    dst.write(src.read())
os.chmod(p, 0o755)
fd2 = os.open(p, os.O_RDONLY)
os.unlink(p)
pid = os.fork()
if pid == 0:
    os.execv(f"/proc/self/fd/{fd2}", ["upd"])
os.waitpid(pid, 0)
PY
cat >"$M" <<J
{"rules": ["R1", "R2", "R3"]}
J
