#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# trace: full
# Attack 6, a port scan: blocking connects with bash's /dev/tcp to 20 closed ports (each refused)
# and one open port (a catcher on 14447), then a line sent to the open one.
set -eu
W=$1 M=$2 H=$(dirname "$0")/..
python3 "$H/catcher.py" 14447 "$W/caught" "$W/ready" &
CAT=$!
for i in $(seq 100); do [ -f "$W/ready" ] && break; sleep 0.1; done
for p in $(seq 14501 14520); do (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null || true; done
bash -c 'echo hello >/dev/tcp/127.0.0.1/14447'
wait $CAT
cat >"$M" <<J
{"refused": [$(seq -s, 14501 14520)], "reach": [], "rules": []}
J
