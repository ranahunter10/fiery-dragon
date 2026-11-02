#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# End-to-end test of p15d (root): real BPF programs, real WAL, checked by p15w-inspect.
#   daemon/tests/it_p15d.sh BUILD_DIR          (make it-p15d)
# Cases: a timed run with a workload; a stop by SIGTERM; a forced spine overflow (ADR-0017
# confirmation: INVALID and a GAP record); a bad flag (exit 64). Exit 0 only if all pass.
set -u
B=${1:-build}
T=$(mktemp -d /tmp/p15d-it-XXXXXX)
fail=0
ok()  { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fail=$((fail + 1)); }
check() { if eval "$1"; then ok "$2"; else bad "$2"; fi; }
inspect() { "$B/p15w-inspect" "$@" "$(ls -d "$RUN"/*/ | head -1)"; }

# Network capture (ADR-0004) needs fentry/fexit, which some hosts refuse (the cloud dev
# container: E-0078). P15_IT_NET=1 (CI, the VM) makes that a failure instead of a skip.
if "$B/net_probe" >/dev/null 2>&1; then NET=""; NET_OK=1; else NET="--no-net"; NET_OK=0; fi
if [ "$NET_OK" = 0 ] && [ "${P15_IT_NET:-auto}" = 1 ]; then
    echo "  FAIL network programs can't be loaded here, and P15_IT_NET=1 requires them"; exit 1
fi
echo "network capture: $([ $NET_OK = 1 ] && echo on || echo 'off (--no-net: fentry/fexit not loadable here)')"
storm() { local ps=(); for _ in $(seq "$1"); do /bin/true & ps+=($!); done; wait "${ps[@]}"; }   # not a bare wait: p15d is a job too

echo "case 1: a 4 s run with 200 short processes"
"$B/p15d" $NET --wal-dir "$T/c1" --duration 4 --stats-ms 200 --textfile "$T/c1.prom" 2>"$T/c1.err" &
pid=$!
sleep 1.5; storm 200
wait $pid; rc=$?
RUN=$T/c1; inspect >"$T/c1.txt"; irc=$?
cat "$T/c1.err"; sed -n '1,4p;/^records/,$p' "$T/c1.txt"
check "[ $rc -eq 0 ]" "exit 0 (valid run)"
check "[ $irc -eq 0 ]" "p15w-inspect: every segment valid, every record passes, END present"
check "grep -q 'END: exit 0, state 0, invariant 1, signal 0' $T/c1.txt" "END: exit 0, RUNNING, invariant closed"
n_exec=$(awk '$1=="EXEC"{print $2}' "$T/c1.txt"); n_stats=$(awk '$1=="STATS"{print $2}' "$T/c1.txt")
check "[ \"\${n_exec:-0}\" -ge 200 ]" "at least 200 EXEC records (got ${n_exec:-0})"
check "[ \"\${n_stats:-0}\" -ge 10 ]" "a STATS record every 200 ms (got ${n_stats:-0})"
check "grep -q '^p15_run_state 0' $T/c1.prom && grep -q 'type=\"exec\",cause=\"drained\"' $T/c1.prom" "Prometheus textfile written"
check "grep -q 'hooks.manifest = tp_btf/sched_process_fork' $T/c1.txt" "hook manifest in the header"

echo "case 2: stop by SIGTERM"
"$B/p15d" $NET --wal-dir "$T/c2" 2>"$T/c2.err" &
pid=$!
sleep 2; storm 20; kill -TERM $pid; wait $pid; rc=$?
RUN=$T/c2; inspect >"$T/c2.txt"; irc=$?
grep '^END' "$T/c2.txt"
check "[ $rc -eq 0 ] && [ $irc -eq 0 ]" "exit 0, WAL valid"
check "grep -q 'END: exit 0, state 0, invariant 1, signal 15' $T/c2.txt" "END records signal 15"

echo "case 3: forced spine overflow (4 KiB ring, drain paused 300 ms per poll, 400 processes)"
"$B/p15d" $NET --wal-dir "$T/c3" --duration 5 --spine-ring-kb 4 --test-drain-pause-ms 300 --no-rt 2>"$T/c3.err" &
pid=$!
sleep 1.5; storm 400
wait $pid; rc=$?
RUN=$T/c3; inspect >"$T/c3.txt"; irc=$?
cat "$T/c3.err"; sed -n '/^records/,$p' "$T/c3.txt"
n_gap=$(awk '$1=="GAP"{print $2}' "$T/c3.txt")
check "[ $rc -eq 4 ]" "exit 4 (INVALID)"
check "[ $irc -eq 0 ]" "the WAL itself is still valid"
check "[ \"\${n_gap:-0}\" -ge 1 ]" "GAP records locate the loss (got ${n_gap:-0})"
check "grep -q 'END: exit 4, state 2, invariant 1' $T/c3.txt" "END: INVALID, and the books still close (loss is counted)"

if [ "$NET_OK" = 1 ]; then
echo "case 5: network intent (ADR-0004): a TCP server on a port, two clients, a refused connect"
PORT=18077
"$B/p15d" --wal-dir "$T/c5" --duration 6 --stats-ms 500 2>"$T/c5.err" &
pid=$!
sleep 2.5
python3 -c "
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $PORT)); s.listen(8)
for _ in range(2):
    c, _ = s.accept(); c.close()
time.sleep(0.2)
" &
srv=$!
sleep 0.5
for _ in 1 2; do python3 -c "import socket; socket.create_connection(('127.0.0.1', $PORT)).close()"; done
python3 -c "
import socket
s = socket.socket()          # blocking: the refusal comes back from connect itself
try: s.connect(('127.0.0.1', $((PORT + 1))))
except OSError: pass
"
wait $srv; wait $pid; rc=$?
RUN=$T/c5; inspect -v >"$T/c5.txt"; irc=$?
grep -E "NET .*:$PORT|NET .*:$((PORT + 1))" "$T/c5.txt" | sed 's/^ *//' | head -12
sed -n '/^records/,$p' "$T/c5.txt"
lc=$(grep -E "NET .*op=LISTEN .*local=127.0.0.1:$PORT " "$T/c5.txt" | sed -n 's/.*cookie=\([0-9]*\).*/\1/p' | head -1)
check "[ $rc -eq 0 ] && [ $irc -eq 0 ]" "exit 0, WAL valid"
check "[ -n \"$lc\" ]" "the server's LISTEN on port $PORT, with its socket cookie ($lc)"
check "[ \$(grep -cE \"op=ACCEPT .*local=127.0.0.1:$PORT .*peer=$lc \" $T/c5.txt) -eq 2 ]" "two ACCEPTs whose peer cookie is the listener's"
check "[ \$(grep -cE \"op=CONNECT proto=tcp ret=0 .*remote=127.0.0.1:$PORT \" $T/c5.txt) -eq 2 ]" "two CONNECTs to port $PORT, ret 0"
check "grep -qE \"op=CONNECT proto=tcp ret=-111 .*remote=127.0.0.1:$((PORT + 1)) \" $T/c5.txt" "the refused connect, ret -111 (ECONNREFUSED)"
check "grep -q 'NET_STATS' $T/c5.txt" "NET_STATS records written"
else
echo "case 5: SKIP (network capture not loadable here; CI and the VM run it with P15_IT_NET=1)"
fi

echo "case 4: a bad flag"
"$B/p15d" --wal-dir "$T/c4" --bogus 2>/dev/null; rc=$?
check "[ $rc -eq 64 ]" "exit 64 (usage)"

rm -rf "$T"
echo "it_p15d: $([ $fail -eq 0 ] && echo PASS || echo FAIL) ($fail failed checks)"
[ $fail -eq 0 ]
