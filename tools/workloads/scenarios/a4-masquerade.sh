#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# trace: full
# Attack 4, masquerade and persistence: a copy of `sleep` is dropped as .X11/kworker and run (R1);
# a python3 process renames itself to "kworker/0:1" (prctl PR_SET_NAME) and writes a cron line into
# a cron.d directory under the work directory (not the system's).
set -eu
W=$1 M=$2
mkdir -p "$W/.X11" "$W/etc/cron.d"
cp /usr/bin/sleep "$W/.X11/kworker"
# Ubuntu 26.04's coreutils is one multi-call binary that picks its tool by argv[0]: run the copy
# with argv[0] "sleep". The process's name (comm) still comes from the file: "kworker".
bash -c 'exec -a sleep "$0" 0.2' "$W/.X11/kworker"
python3 - "$W" <<'PY'
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
assert libc.prctl(15, b"kworker/0:1", 0, 0, 0) == 0     # PR_SET_NAME
open(f"{sys.argv[1]}/etc/cron.d/backdoor", "w").write("* * * * * root /tmp/.X11/kworker\n")
PY
cat >"$M" <<J
{"reach": [{"name": "dropped program to the cron line", "from": {"path": "$W/.X11/kworker"}, "to": {"path": "$W/etc/cron.d/backdoor"}, "expect": false}],
 "rules": ["R1"], "comm": ["kworker/0:1"]}
J
