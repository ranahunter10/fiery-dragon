#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# End-to-end test of p15d (root): real BPF programs, real WAL, checked by p15w-inspect and
# by the Python reader.
#   daemon/tests/it_p15d.sh BUILD_DIR          (make it-p15d)
# Cases: a timed run with a workload; a stop by SIGTERM; a forced spine overflow (ADR-0017
# confirmation: INVALID and a GAP record); a bad flag (exit 64). Exit 0 only if all pass.
set -u
B=${1:-build}
T=$(mktemp -d /tmp/p15d-it-XXXXXX)
fail=0
PY=${P15_PYTHON:-python3}   # sudo resets PATH: CI passes its Python 3.14 here
ok()  { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fail=$((fail + 1)); }
check() { if eval "$1"; then ok "$2"; else bad "$2"; fi; }
# Every run is read by both readers: the C p15w-inspect and the Python one (python/p15/wal.py).
# Their record counts must agree line for line (ADR-0007: one format, readers kept in step).
counts() { sed -n '/^records:/,/^[^ r]/p' | grep -E '^(records:|  [A-Z_]+ +[0-9]+$)'; }
inspect() {
    local d rc pc; d=$(ls -d "$RUN"/*/ | head -1)
    "$B/p15w-inspect" "$@" "$d"; rc=$?
    if ! pc=$(PYTHONPATH=python "$PY" -m p15.wal "$d" 2>&1); then
        echo "python reader: $pc" >&2; bad "the Python reader accepts $RUN" >&2
    elif [ "$(printf '%s\n' "$pc" | counts)" != "$("$B/p15w-inspect" "$d" | counts)" ]; then
        bad "the Python reader's counts equal p15w-inspect's ($RUN)" >&2
    else
        ok "the Python reader's counts equal p15w-inspect's ($(basename "$RUN"))" >&2
    fi
    return $rc
}

# Network capture (ADR-0004) needs fentry/fexit, which some hosts refuse (the cloud dev
# container: E-0078). P15_IT_NET=1 (CI, the VM) makes that a failure instead of a skip.
if "$B/net_probe" >/dev/null 2>&1; then NET=""; NET_OK=1; else NET="--no-net"; NET_OK=0; fi
if [ "$NET_OK" = 0 ] && [ "${P15_IT_NET:-auto}" = 1 ]; then
    echo "  FAIL network programs can't be loaded here, and P15_IT_NET=1 requires them"; exit 1
fi
echo "network capture: $([ $NET_OK = 1 ] && echo on || echo 'off (--no-net: fentry/fexit not loadable here)')"
storm() { local ps=(); for _ in $(seq "$1"); do /bin/true & ps+=($!); done; wait "${ps[@]}"; }   # not a bare wait: p15d is a job too
# p15d prints code=start once its hooks are attached and both self-tests passed: wait for that,
# not for a fixed time, so a slow start never hides events from the test (E-0089 follow-up)
started() { for _ in $(seq 150); do grep -q code=start "$1" 2>/dev/null && return 0; sleep 0.1; done; echo "  FAIL p15d did not start within 15 s: $(cat "$1")"; return 1; }
# the run's EXEC records of /bin/true, and the kernel's skips from the last STATS (ADR-0020)
true_execs() { PYTHONPATH=python "$PY" -c "
import sys; from pathlib import Path; from p15 import wal
run = wal.read_run(Path(sys.argv[1]))
print(sum(1 for r in run.ring_records(0) if r.name == 'EXEC' and r.var['filename'] == b'/bin/true'))" "$1"; }
skips() { PYTHONPATH=python "$PY" -c "
import sys; from pathlib import Path; from p15 import wal
st = [r for r in wal.read_run(Path(sys.argv[1])).ring_records(2) if r.name == 'STATS'][-1]
print(' '.join(f'{t}={st.f[t + \"_missed\"]}' for t in ('fork', 'exec', 'exit', 'rename')))" "$1"; }

echo "case 1: an 8 s run with 200 short processes, started once p15d is ready"
"$B/p15d" $NET --wal-dir "$T/c1" --duration 8 --stats-ms 200 --textfile "$T/c1.prom" 2>"$T/c1.err" &
pid=$!
started "$T/c1.err" && storm 200
wait $pid; rc=$?
RUN=$T/c1; inspect >"$T/c1.txt"; irc=$?
cat "$T/c1.err"; sed -n '1,4p;/^records/,$p' "$T/c1.txt"
check "[ $rc -eq 0 ]" "exit 0 (valid run)"
check "[ $irc -eq 0 ]" "p15w-inspect: every segment valid, every record passes, END present"
check "grep -q 'END: exit 0, state 0, invariant 1, signal 0' $T/c1.txt" "END: exit 0, RUNNING, invariant closed"
d1=$(ls -d "$T"/c1/*/ | head -1); n_exec=$(true_execs "$d1"); sk=$(skips "$d1"); n_stats=$(awk '$1=="STATS"{print $2}' "$T/c1.txt")
check "[ \"\${n_exec:-0}\" -ge 200 ]" "every one of the 200 children's EXEC of /bin/true is in the WAL (got ${n_exec:-0})"
check "[ \"$sk\" = 'fork=0 exec=0 exit=0 rename=0' ]" "the kernel skipped no spine event (ADR-0020: $sk)"
check "[ \"\${n_stats:-0}\" -ge 10 ]" "a STATS record every 200 ms (got ${n_stats:-0})"
check "grep -q '^p15_run_state 0' $T/c1.prom && grep -q 'type=\"exec\",cause=\"drained\"' $T/c1.prom" "Prometheus textfile written"
check "grep -q 'hooks.manifest = tp_btf/sched_process_fork' $T/c1.txt" "hook manifest in the header"

echo "case 2: stop by SIGTERM"
"$B/p15d" $NET --wal-dir "$T/c2" 2>"$T/c2.err" &
pid=$!
started "$T/c2.err" && storm 20; kill -TERM $pid; wait $pid; rc=$?
RUN=$T/c2; inspect >"$T/c2.txt"; irc=$?
grep '^END' "$T/c2.txt"
check "[ $rc -eq 0 ] && [ $irc -eq 0 ]" "exit 0, WAL valid"
check "grep -q 'END: exit 0, state 0, invariant 1, signal 15' $T/c2.txt" "END records signal 15"

echo "case 3: forced spine overflow (4 KiB ring, drain paused 300 ms per poll, 400 processes)"
"$B/p15d" $NET --wal-dir "$T/c3" --duration 5 --spine-ring-kb 4 --test-drain-pause-ms 300 --no-rt 2>"$T/c3.err" &
pid=$!
started "$T/c3.err" && storm 400
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
started "$T/c5.err"
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
# the demo query (STATE 19.4) on the same real run: p15-trace, text and HTML
d5=$(ls -d "$T"/c5/*/ | head -1)
PYTHONPATH=python "$PY" -m p15.trace --port $PORT "$d5" --html "$T/c5-$PORT.html" >"$T/c5-trace.txt" 2>&1; trc=$?
PYTHONPATH=python "$PY" -m p15.trace --port $((PORT + 1)) "$d5" >"$T/c5-trace-refused.txt" 2>&1; trc2=$?
sed -n '/^Summary/,/^Processes/p' "$T/c5-trace.txt" | head -14
check "[ $trc -eq 0 ] && [ $trc2 -eq 0 ] && head -c 15 $T/c5-$PORT.html | grep -q '<!doctype html>'" "p15-trace: text and HTML reports made"
check "grep -q 'Summary: 1 listener(s); 2 connection(s) accepted, 2 of them from a process on this host; 2 connect(s) to the port, 0 refused' $T/c5-trace.txt" "p15-trace: 1 listener, 2 accepts, both clients found on this host"
check "grep -qE '^  127.0.0.1:$PORT tcp  cookie $lc  listening from .* by python3 \\($srv\\)' $T/c5-trace.txt" "p15-trace: the listener is the server process ($srv), cookie $lc"
check "[ \$(grep -cE 'client: python3 \\([0-9]+\\) ← ' $T/c5-trace.txt) -eq 2 ]" "p15-trace: each accept joined to its client process and that process's parent"
check "[ \$(grep -cE 'client: python3 \\([0-9]+\\) ← .*\\(exact, by TCP sequence number' $T/c5-trace.txt) -eq 2 ]" "p15-trace: both clients joined exactly, by the TCP client sequence number (ADR-0022)"
check "grep -q 'client -> accept: 2 exact, by the TCP client sequence number' $T/c5-trace.txt && grep -q '0 same-endpoint connect(s) set aside' $T/c5-trace.txt && grep -q ' 0 TCP record(s) without a sequence number' $T/c5-trace.txt" "p15-trace: 2 exact joins, 0 set aside, every TCP record carries its ISN"
check "grep -qE 'ECONNREFUSED \\(-111\\) +by python3' $T/c5-trace-refused.txt" "p15-trace: the refused connect to port $((PORT + 1)), with its process"
if [ -n "${P15_IT_KEEP:-}" ]; then     # CI keeps the real run and its reports as an artifact
    mkdir -p "$P15_IT_KEEP" && cp -r "$d5" "$P15_IT_KEEP/" && cp "$T"/c5-trace*.txt "$T/c5-$PORT.html" "$T/c5.txt" "$P15_IT_KEEP/"
fi
else
echo "case 5: SKIP (network capture not loadable here; CI and the VM run it with P15_IT_NET=1)"
fi

echo "case 4: a bad flag"
"$B/p15d" --wal-dir "$T/c4" --bogus 2>/dev/null; rc=$?
check "[ $rc -eq 64 ]" "exit 64 (usage)"

rm -rf "$T"
echo "it_p15d: $([ $fail -eq 0 ] && echo PASS || echo FAIL) ($fail failed checks)"
[ $fail -eq 0 ]
