#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# End-to-end test of p15d (root): real BPF programs, real WAL, checked by p15w-inspect and
# by the Python reader.
#   daemon/tests/it_p15d.sh BUILD_DIR          (make it-p15d)
# Cases: a timed run with a workload; a stop by SIGTERM; a forced spine overflow (ADR-0017
# confirmation: INVALID and a GAP record); network intent; code provenance (ADR-0025, with
# daemon/tests/it_provenance.py); no map syscall after attach (ADR-0026, strace); a bad flag (exit 64). Exit 0 only if all pass.
# Every run's process snapshots are checked too (ADR-0007 rule 3, ADR-0023 confirmations 2-3).
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
# File identity (ADR-0015) needs fentry and kprobe.session as well, so it follows the same switch.
if "$B/net_probe" >/dev/null 2>&1; then NET=""; NET_OK=1; else NET="--no-net --no-files"; NET_OK=0; fi
if [ "$NET_OK" = 0 ] && [ "${P15_IT_NET:-auto}" = 1 ]; then
    echo "  FAIL network programs can't be loaded here, and P15_IT_NET=1 requires them"; exit 1
fi
echo "network capture and file identity: $([ $NET_OK = 1 ] && echo on || echo 'off (--no-net --no-files: fentry/fexit not loadable here)')"
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
# the snapshots and the ADR-0023 reconciliation, as p15-trace computes them:
#   <verdict> <forks unexplained> <exits unexplained> <fork losses> <exit losses> <kind:procs:complete>...
recon() { PYTHONPATH=python "$PY" -c "
import sys; from pathlib import Path; from p15 import trace
c = trace.load(Path(sys.argv[1])); r = c.recon
print(r.verdict.replace(' ', '_'), len(r.fork_unexplained), len(r.exit_unexplained), r.fork_losses, r.exit_losses,
      ' '.join(f'{s.kind}:{len(s.procs)}:{int(s.complete)}' for s in c.snapshots))" "$1"; }
# pid 1 must be in the opening snapshot. The cloud dev container's kernel never shows pid 1 to a
# task iterator, even one asked for tid 1 alone (E-0105): there, P15_IT_PID1=0 turns this check off.
pid1() { PYTHONPATH=python "$PY" -c "
import sys; from pathlib import Path; from p15 import trace
c = trace.load(Path(sys.argv[1])); print(int(any(k[0] == 1 for k in c.snapshots[0].procs)))" "$1"; }

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
rc1=$(recon "$d1"); echo "  reconciliation: $rc1"
check "grep -q 'END: .*closing snapshot 1' $T/c1.txt" "END v2: the closing snapshot was taken (ADR-0023 rule 1)"
check "echo '$rc1' | grep -qE ' opening:[0-9]+:1 closing:[0-9]+:1$'" "an opening and a closing snapshot, both complete (their books close)"
check "echo '$rc1' | grep -q '^complete 0 0 '" "ADR-0023 confirmation 2: fork_unexplained = exit_unexplained = 0, verdict complete"
check "grep -qE 'PROC .* tgid=$pid .*path=\"[^\"]*/p15d\"' <(\"$B/p15w-inspect\" -v \"$d1\")" "the snapshot lists p15d itself, with its resolved path"
if [ "${P15_IT_PID1:-1}" = 1 ]; then
    check "[ \"$(pid1 "$d1")\" = 1 ]" "pid 1 is in the opening snapshot"
fi

echo "case 2: stop by SIGTERM"
"$B/p15d" $NET --wal-dir "$T/c2" 2>"$T/c2.err" &
pid=$!
started "$T/c2.err" && storm 20; kill -TERM $pid; wait $pid; rc=$?
RUN=$T/c2; inspect >"$T/c2.txt"; irc=$?
grep '^END' "$T/c2.txt"
check "[ $rc -eq 0 ] && [ $irc -eq 0 ]" "exit 0, WAL valid"
check "grep -q 'END: exit 0, state 0, invariant 1, signal 15' $T/c2.txt" "END records signal 15"
check "grep -q 'END: .*closing snapshot 1' $T/c2.txt" "a stop by signal is orderly: the closing snapshot was taken"

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
rc3=$(recon "$(ls -d "$T"/c3/*/ | head -1)"); echo "  reconciliation: $rc3"
read -r v3 fu3 eu3 fl3 el3 _ <<<"$rc3"
check "[ \"$v3\" = complete ] || [ \"$v3\" = repaired ]" "ADR-0023 confirmation 3: the reconciliation is not INVALID under forced loss ($v3)"
check "[ \"$fu3\" -le \"$fl3\" ] && [ \"$eu3\" -le \"$el3\" ]" "unexplained forks $fu3 <= counted $fl3, exits $eu3 <= counted $el3"

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

echo "case 6: code provenance (ADR-0025): a program run from memory, three stream kinds, a pipe, PROC v2 against EXEC v2"
"$B/p15d" $NET --wal-dir "$T/c6" --duration 6 --stats-ms 500 2>"$T/c6.err" &
pid=$!
started "$T/c6.err" && "$PY" daemon/tests/it_provenance.py workload "$T"
wait $pid; rc=$?
kill "$(cat "$T/c6-live.pid" 2>/dev/null)" 2>/dev/null
RUN=$T/c6; inspect >"$T/c6.txt"; irc=$?
check "[ $rc -eq 0 ] && [ $irc -eq 0 ]" "exit 0, WAL valid"
d6=$(ls -d "$T"/c6/*/ | head -1)
while IFS= read -r line; do
    case "$line" in ok\ *) ok "${line#ok }";; FAIL\ *) bad "${line#FAIL }";; *) bad "unexpected checker output: $line";; esac
done < <(PYTHONPATH=python "$PY" daemon/tests/it_provenance.py check "$d6" "$T" 2>&1)

echo "case 7: no map syscall once a program is attached (ADR-0026), traced with strace"
if command -v strace >/dev/null; then
    strace -f -v -e trace=bpf -o "$T/c7.strace" "$B/p15d" $NET --wal-dir "$T/c7" --duration 3 --stats-ms 200 2>"$T/c7.err"; rc=$?
    c7=$("$PY" -c "
import re, sys
lines = open(sys.argv[1]).read().splitlines()
first = next((i for i, l in enumerate(lines) if 'BPF_LINK_CREATE' in l and 'BPF_TRACE_ITER' not in l), None)
if first is None:
    print('no-attach'); sys.exit()
mapc = re.compile(r'BPF_MAP_(LOOKUP|UPDATE|DELETE|GET_NEXT)')
print(sum(bool(mapc.search(l)) for l in lines[first:]), sum('BPF_OBJ_GET_INFO_BY_FD' in l for l in lines[first:]))" "$T/c7.strace")
    check "[ $rc -eq 0 ]" "exit 0 under strace"
    check "[ \"\${c7%% *}\" = 0 ]" "after the first event attach: 0 map lookups, updates or deletes (got: ${c7%% *})"
    check "[ \"\${c7##* }\" -gt 0 ] 2>/dev/null" "  ... while p15d did read the kernel's skip counters by info call (${c7##* } calls): the trace saw the run"
else
    bad "strace is not installed: case 7 cannot run (install strace)"
fi

echo "case 8: file identity (ADR-0015, step 2a part 2): a file created, reopened and read, a FIFO open that fails in ->open"
if [ "$NET_OK" = 1 ]; then
"$B/p15d" --wal-dir "$T/c8" --duration 4 --stats-ms 200 2>"$T/c8.err" &
pid=$!
if started "$T/c8.err"; then
    D8=$(mktemp -d /tmp/p15d-it8-XXXXXX); D8=$(realpath "$D8")
    printf 'it_p15d\n' > "$D8/f1"; cat "$D8/f1" >/dev/null; mkfifo "$D8/fifo"
    "$PY" -c "
import errno, os, sys
try: os.open(sys.argv[1], os.O_WRONLY | os.O_NONBLOCK)
except OSError as e: sys.exit(0 if e.errno == errno.ENXIO else 1)
sys.exit(1)" "$D8/fifo"; frc=$?
fi
wait $pid; rc=$?
RUN=$T/c8; inspect -v >"$T/c8.txt"; irc=$?
grep -E "OPEN .*path=\"$D8" "$T/c8.txt" | sed 's/^ *//' | head -4
f1fid=$(grep -E "OPEN .*path=\"$D8/f1\"" "$T/c8.txt" | sed -n 's/.* fid=\([0-9]*\) .*/\1/p' | head -1)
fifofid=$(grep -E "OPEN .*path=\"$D8/fifo\"" "$T/c8.txt" | sed -n 's/.* fid=\([0-9]*\) .*/\1/p' | head -1)
check "[ $rc -eq 0 ] && [ $irc -eq 0 ] && [ \"${frc:-1}\" -eq 0 ]" "exit 0, WAL valid, the FIFO open failed with ENXIO"
check "[ \$(grep -cE \"OPEN .*path=\\\"$D8/f1\\\"\" $T/c8.txt) -ge 2 ]" "an OPEN with its path for the create and the read of f1"
check "grep -qE \"OPEN .*path=\\\"$D8/f1\\\".* dev=[0-9]+:[0-9]+ ino=[0-9]+\" $T/c8.txt" "  ... the first one carries the object's facts"
check "[ -n \"$f1fid\" ] && grep -qE \"CLOSE .* fid=$f1fid obj=[0-9]+ fflags=0x0 \" $T/c8.txt" "a CLOSE for f1's first open file (fid $f1fid), opened"
check "[ -n \"$fifofid\" ] && grep -qE \"CLOSE .* fid=$fifofid obj=[0-9]+ fflags=0x[26]0 \" $T/c8.txt" "the FIFO open ends with CLOSE NEVER_OPENED (fid $fifofid)"
check "grep -q 'FILE_STATS' $T/c8.txt && ! grep -qE 'FILE_STATS .* open_lost=[1-9]' $T/c8.txt" "FILE_STATS records written, no OPEN lost"
check "grep -q 'END: exit 0, state 0, invariant 1' $T/c8.txt" "END: exit 0, RUNNING, the books close with file identity in them"
rm -rf "$D8"
else
echo "case 8: SKIP (file identity not loadable here; CI and the VM run it with P15_IT_NET=1)"
fi

echo "case 4: a bad flag"
"$B/p15d" --wal-dir "$T/c4" --bogus 2>/dev/null; rc=$?
check "[ $rc -eq 64 ]" "exit 64 (usage)"

rm -rf "$T"
echo "it_p15d: $([ $fail -eq 0 ] && echo PASS || echo FAIL) ($fail failed checks)"
[ $fail -eq 0 ]
