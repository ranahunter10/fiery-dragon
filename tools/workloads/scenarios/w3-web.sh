#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# trace: full
# A web server under parallel clients: python3's threading http.server on 127.0.0.1:18080 serving a
# 2 MiB file and a page; 30 requests by curl, 10 at a time; every download is checked by sha256.
set -eu
W=$1
mkdir -p "$W/site"
head -c 2097152 /dev/urandom >"$W/site/big.bin"
echo '<html>p15 workload</html>' >"$W/site/index.html"
want=$(sha256sum <"$W/site/big.bin" | cut -d' ' -f1)
python3 -u -m http.server 18080 --bind 127.0.0.1 --directory "$W/site" >"$W/server.log" 2>&1 &
SRV=$!
for i in $(seq 100); do grep -q "Serving HTTP" "$W/server.log" && break; sleep 0.1; done   # python3 says it once it listens
for round in 1 2 3; do
	pids=()
	for i in $(seq 10); do
		if [ $((i % 2)) = 0 ]; then curl -s -o "$W/got.$round.$i" http://127.0.0.1:18080/big.bin &
		else curl -s -o "$W/got.$round.$i" http://127.0.0.1:18080/index.html & fi
		pids+=($!)
	done
	wait "${pids[@]}"
done
kill $SRV; wait $SRV 2>/dev/null || true
bad=0
for f in "$W"/got.*; do
	case $f in *[02468]) [ "$(sha256sum <"$f" | cut -d' ' -f1)" = "$want" ] || bad=$((bad + 1)) ;; esac
done
echo "downloads checked, bad $bad"
[ $bad = 0 ]
