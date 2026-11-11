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

echo "case 1: an 8 s run with 200 short processes, started once p15d is ready [t+${SECONDS}s]"
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

echo "case 2: stop by SIGTERM [t+${SECONDS}s]"
"$B/p15d" $NET --wal-dir "$T/c2" 2>"$T/c2.err" &
pid=$!
started "$T/c2.err" && storm 20; kill -TERM $pid; wait $pid; rc=$?
RUN=$T/c2; inspect >"$T/c2.txt"; irc=$?
grep '^END' "$T/c2.txt"
check "[ $rc -eq 0 ] && [ $irc -eq 0 ]" "exit 0, WAL valid"
check "grep -q 'END: exit 0, state 0, invariant 1, signal 15' $T/c2.txt" "END records signal 15"
check "grep -q 'END: .*closing snapshot 1' $T/c2.txt" "a stop by signal is orderly: the closing snapshot was taken"

echo "case 3: forced spine overflow (4 KiB ring, drain paused 300 ms per poll, 400 processes) [t+${SECONDS}s]"
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
echo "case 5: network intent (ADR-0004): a TCP server on a port, two clients, a refused connect [t+${SECONDS}s]"
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
echo "case 5: SKIP (network capture not loadable here; CI and the VM run it with P15_IT_NET=1) [t+${SECONDS}s]"
fi

echo "case 6: code provenance (ADR-0025): a program run from memory, three stream kinds, a pipe, PROC v2 against EXEC v2 [t+${SECONDS}s]"
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

echo "case 7: no map syscall once a program is attached (ADR-0026), traced with strace [t+${SECONDS}s]"
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

echo "case 8: file identity (ADR-0015, step 2a part 2): a file created, reopened and read, a FIFO open that fails in ->open [t+${SECONDS}s]"
if [ "$NET_OK" = 1 ]; then
# A file opened over and over while p15d starts: some open falls inside the load-time self-tests,
# whose reader throws its record away. The object's facts must still reach the WAL (the facts
# epoch, E-0151).
E8=$(mktemp /tmp/p15d-it8-early-XXXXXX); E8=$(realpath "$E8"); D8=/nonexistent
# the loop ends when the file goes, or after 20 s on its own, whatever happens to this script
( end=$(( $(date +%s) + 20 )); while [ -e "$E8" ] && [ ! -e "$E8.stop" ] && [ "$(date +%s)" -lt "$end" ]; do cat "$E8" >/dev/null 2>&1; done ) &
loop=$!
trap 'rm -f "$E8" "$E8.stop"' EXIT
# p15d pauses after its self-tests, before the WAL opens (a test switch): the loop stops there, and
# one last open of the file falls in that window. With the loop's opens during the self-tests taken
# by their reader, only the loader's facts epoch puts this file's facts in the WAL (E-0161).
"$B/p15d" --wal-dir "$T/c8" --duration 4 --stats-ms 200 --test-start-pause-ms 1500 2>"$T/c8.err" &
pid=$!
for _ in $(seq 150); do grep -q code=test_pause "$T/c8.err" 2>/dev/null && break; sleep 0.1; done
touch "$E8.stop"; wait $loop 2>/dev/null; cat "$E8" >/dev/null   # the last open of it, in the window
if started "$T/c8.err"; then
    rm -f "$E8" "$E8.stop"
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
check "grep -qE \"OPEN .*path=\\\"$E8\\\".* dev=[0-9]+:[0-9]+ ino=[0-9]+\" $T/c8.txt" "a file first opened while p15d was starting has its facts in the WAL (facts epoch)"
check "[ \$(grep -E \"OPEN .*path=\\\"$E8\\\"\" $T/c8.txt | sed 's/.* obj=\\([0-9]*\\) .*/\\1/' | sort -u | wc -l) -eq 1 ]" "  ... and every open of it names one object"
check "[ -n \"$f1fid\" ] && grep -qE \"CLOSE .* fid=$f1fid obj=[0-9]+ fflags=0x0 \" $T/c8.txt" "a CLOSE for f1's first open file (fid $f1fid), opened"
check "[ -n \"$fifofid\" ] && grep -qE \"CLOSE .* fid=$fifofid obj=[0-9]+ fflags=0x[26]0 \" $T/c8.txt" "the FIFO open ends with CLOSE NEVER_OPENED (fid $fifofid)"
check "grep -q 'FILE_STATS' $T/c8.txt && ! grep -qE 'FILE_STATS .* open_lost=[1-9]' $T/c8.txt" "FILE_STATS records written, no OPEN lost"
check "grep -q 'END: exit 0, state 0, invariant 1' $T/c8.txt" "END: exit 0, RUNNING, the books close with file identity in them"
rm -rf "$D8"; rm -f "$E8"; kill $loop 2>/dev/null
else
echo "case 8: SKIP (file identity not loadable here; CI and the VM run it with P15_IT_NET=1) [t+${SECONDS}s]"
fi

echo "case 9: files already open at start (ADR-0015 rule 7, the snapshot's FD pass) [t+${SECONDS}s]"
if [ "$NET_OK" = 1 ]; then
D9=$(mktemp -d /tmp/p15d-it9-XXXXXX); D9=$(realpath "$D9")
printf 'held\n' > "$D9/held"; printf 'again\n' > "$D9/again"
# opened before p15d starts, held on fd 3, stdin a pipe: only the FD pass can name them
( exec 3<"$D9/held"; exec sleep 6 ) < <(exec sleep 6) &
holder=$!
sleep 0.3
# segments of 1 s: each opening snapshot repeats the FD pass and starts a new facts epoch, so a
# file opened in two segments has its facts in both (ADR-0007's self-describing segments, E-0160)
"$B/p15d" --wal-dir "$T/c9" --duration 4 --stats-ms 200 --rotate-s 1 2>"$T/c9.err" &
pid=$!
if started "$T/c9.err"; then
    sleep 0.3; cat "$D9/held" "$D9/again" >/dev/null; kill $holder 2>/dev/null; wait $holder 2>/dev/null
    sleep 2.2; cat "$D9/again" >/dev/null
fi
wait $pid; rc=$?
RUN=$T/c9; inspect -v >"$T/c9.txt"; irc=$?
row=$(grep -E "FD .* tgid=$holder .* snap=0 fd=3 " "$T/c9.txt" | head -1)
echo "$row" | sed 's/^ *//' | cut -c1-240
hfid=$(echo "$row" | sed -n 's/.* fid=\([0-9]*\) .*/\1/p'); hobj=$(echo "$row" | sed -n 's/.* obj=\([0-9]*\) .*/\1/p')
check "[ $rc -eq 0 ] && [ $irc -eq 0 ]" "exit 0, WAL valid"
held_ok=0; case "$row" in *"path=\"$D9/held\""*) held_ok=1;; esac
check "[ $held_ok = 1 ]" "an FD row for the holder's fd 3, with the file's path (fid $hfid, obj $hobj)"
check "[ \$(grep -cE \"FD .* tgid=$holder .* snap=0 fd=[012] \" $T/c9.txt) -eq 3 ]" "  ... and for its fds 0, 1 and 2 (the streams of a process older than capture)"
check "[ -n \"$hobj\" ] && grep -qE \"OPEN .* obj=$hobj .*path=\\\"$D9/held\\\"\" $T/c9.txt" "a later open of the same file names the FD row's object"
check "[ -n \"$hfid\" ] && grep -qE \"CLOSE .* fid=$hfid \" $T/c9.txt" "the holder's exit ends that open file: CLOSE fid $hfid"
check "grep -qE 'SNAP_DONE .* fd: error=0 .* write_failed=0 .* invalid=0 unwritten=0' $T/c9.txt" "SNAP_DONE carries the FD pass's books, nothing lost"
nseg=$(ls "$T"/c9/*/seg-*.p15w 2>/dev/null | wc -l)
check "[ $nseg -ge 2 ] && [ \$(grep -cE 'SNAP_DONE .*/opening .* fd: error=0' $T/c9.txt) -ge 2 ]" "every segment's opening snapshot has an FD pass ($nseg segments)"
check "[ \$(grep -cE \"OPEN .*path=\\\"$D9/again\\\".* dev=[0-9]+:[0-9]+ ino=\" $T/c9.txt) -eq 2 ]" "a file opened in two segments carries its facts in both (the facts epoch)"
check "grep -q 'END: exit 0, state 0, invariant 1' $T/c9.txt" "END: exit 0, RUNNING, the books close"
rm -rf "$D9"
else
echo "case 9: SKIP (file identity not loadable here; CI and the VM run it with P15_IT_NET=1)"
fi

echo "case 10: the stop's watchdog (E-0162): a writer that stands still, and one that is only slow [t+${SECONDS}s]"
t0=$(date +%s)
"$B/p15d" --wal-dir "$T/c10" $NET --duration 1 --stop-stall-s 2 --test-writer-stall-ms 30000 2>"$T/c10.err"; rc=$?
dt=$(( $(date +%s) - t0 ))
RUN=$T/c10; inspect >"$T/c10.txt" 2>&1
check "[ $rc -eq 75 ]" "a writer stuck in the closing snapshot: exit 75 (STUCK), got $rc"
check "[ $dt -lt 20 ]" "  ... within the watchdog's bound, not the writer's 30 s ($dt s)"
check "grep -q 'code=stuck .*the closing snapshot' $T/c10.err" "  ... the log names the phase"
check "grep -q 'valid to the end' $T/c10.txt && grep -q 'END: none' $T/c10.txt" "  ... the WAL is valid and has no END"
"$B/p15d" --wal-dir "$T/c10b" $NET --duration 1 --stop-stall-s 2 --test-writer-stall-ms 800 2>"$T/c10b.err"; rc=$?
RUN=$T/c10b; inspect >"$T/c10b.txt" 2>&1
check "[ $rc -eq 0 ] && grep -q 'END: exit 0' $T/c10b.txt" "a writer slow for 0.8 s, under the 2 s bound: an orderly stop, END written"

echo "case 11: a full queue loses nothing (E-0173): 4 batches of 16 KiB, a writer slowed to 100 ms a batch, 2000 processes, spine only [t+${SECONDS}s]"
# from the last STATS and FILE_STATS: queue_full, the spine's reserve failures, file records lost to the bulk ring
qstat() { PYTHONPATH=python "$PY" -c "
import sys; from pathlib import Path; from p15 import wal
last = {r.name: r for r in wal.read_run(Path(sys.argv[1])).ring_records(2)}
st, fs = last['STATS'], last.get('FILE_STATS')
bulk = sum(v for k, v in fs.f.items() if k.endswith('_lost')) if fs else 0
print(st.f['queue_full'], sum(st.f[t + '_reserve_failed'] for t in ('fork', 'exec', 'exit', 'rename')), bulk)" "$1"; }
"$B/p15d" --wal-dir "$T/c11" --no-net --no-files --queue-batches 4 --batch-kb 16 --test-writer-batch-ms 100 --stop-stall-s 60 2>"$T/c11.err" &
pid=$!
started "$T/c11.err" && storm 2000
sleep 1; kill -TERM $pid; wait $pid; rc=$?
RUN=$T/c11; inspect >"$T/c11.txt" 2>&1
d11=$(ls -d "$T"/c11/*/ | head -1); n_exec=$(true_execs "$d11"); read -r qf rf _ <<<"$(qstat "$d11")"
echo "  queue_full $qf, spine reserve failures $rf; EXEC of /bin/true: ${n_exec:-0}; $(grep -o 'END: [^\"]*' "$T/c11.txt")"
check "[ \"\${qf:-0}\" -gt 0 ]" "the queue was full during the run (the path under test ran: queue_full ${qf:-none})"
check "[ \"\${rf:-1}\" = 0 ]" "the spine ring absorbed the backlog: no reserve failed"
check "[ $rc -eq 0 ] && grep -q 'END: exit 0, state 0, invariant 1' $T/c11.txt" "exit 0, RUNNING, the invariant closed: no record was taken and dropped (rc $rc)"
check "[ \"\${n_exec:-0}\" -ge 2000 ]" "every one of the 2000 children's EXEC is in the WAL (got ${n_exec:-0})"
if [ "$NET_OK" = 1 ]; then
    # the bulk ring's turn: every exec opens a few files, so 600 processes flood it with OPEN and CLOSE.
    # A bulk ring that fills is a counted loss (DEGRADED, exit 3) and allowed; a broken invariant is not.
    "$B/p15d" --wal-dir "$T/c11b" --queue-batches 4 --batch-kb 16 --test-writer-batch-ms 20 --stop-stall-s 60 2>"$T/c11b.err" &
    pid=$!
    started "$T/c11b.err" && storm 600
    sleep 1; kill -TERM $pid; wait $pid; rc=$?
    RUN=$T/c11b; inspect >"$T/c11b.txt" 2>&1
    d11=$(ls -d "$T"/c11b/*/ | head -1); read -r qf rf bl <<<"$(qstat "$d11")"
    echo "  with file identity and NET: queue_full $qf, spine reserve failures $rf, bulk records lost to the ring $bl; $(grep -o 'END: [^\"]*' "$T/c11b.txt")"
    check "[ \"\${qf:-0}\" -gt 0 ]" "  ... the queue was full during the run (queue_full ${qf:-none})"
    check "{ [ $rc -eq 0 ] || [ $rc -eq 3 ]; } && grep -qE 'END: exit [03], state [01], invariant 1' $T/c11b.txt" "  ... the invariant closed with the bulk ring flooded: every record written or counted (rc $rc)"
    check "[ $rc -eq 0 ] || [ \"\${bl:-0}\" -gt 0 ]" "  ... and a DEGRADED end only with a counted loss (lost $bl)"
else
    echo "  SKIP the bulk ring's flood (file identity not loadable here; CI and the VM run it)"
fi

echo "case 12: the path program left unattached: the session return writes every open, walked, with its object (E-0190, ADR-0029) [t+${SECONDS}s]"
if [ "$NET_OK" = 1 ]; then
    "$B/p15d" --wal-dir "$T/c12" --test-no-path-fentry --duration 2 2>"$T/c12.err"; rc=$?
    RUN=$T/c12; inspect >"$T/c12.txt" 2>&1
    # a failed self-test ends p15d with its own exit code before start: rc 0 means its no-path checks passed
    check "[ $rc -eq 0 ] && grep -q 'END: exit 0, state 0, invariant 1' $T/c12.txt" "the self-test's no-path checks passed; exit 0, RUNNING, the invariant closed (rc $rc)"
    c12=$(PYTHONPATH=python "$PY" -c "
import sys; from pathlib import Path; from p15 import wal
from p15 import records as R
run = wal.read_run(Path(sys.argv[1]))
bulk = list(run.ring_records(1))
opens = {r.f['fid']: r for r in bulk if r.name == 'OPEN'}
closes = [r for r in bulk if r.name == 'CLOSE' and r.f['fid'] in opens]
walked = [r for r in opens.values() if r.f['fflags'] & R.gen.FF_PATH_WALKED]
named = sum(1 for r in walked if r.var['path'] and (r.var['path'][:1] == b'/' or b':' in r.var['path']))
unnamed = [r for r in opens.values() if r.f['fflags'] & R.gen.FF_PATH_MISSING]
missing = len(unnamed)
by_fs = {}   # unnamed opens by filesystem magic (a d_dname the walk does not know): for the log
for r in unnamed:
    fm = r.var['facts']['fs_magic'] if r.var.get('facts') is not None else 0
    by_fs[fm] = by_fs.get(fm, 0) + 1
fs = [r for r in run.ring_records(2) if r.name == 'FILE_STATS']
print(len(opens), len(walked), missing, named, len(closes), sum(1 for r in closes if r.f['obj'] == opens[r.f['fid']].f['obj'] != 0),
      fs[-1].f['walked'] if fs else -1, ','.join(f'{k:#x}:{v}' for k, v in sorted(by_fs.items())) or '-')" "$(ls -d "$T"/c12/*/ | head -1)")
    read -r n_open n_walked n_missing n_named n_close n_same fs_walked fs_unnamed <<<"$c12"
    echo "  OPEN $n_open (PATH_WALKED $n_walked, $n_named with a path; PATH_MISSING $n_missing, by fs magic $fs_unnamed); CLOSE of those $n_close, naming the OPEN's object $n_same; last FILE_STATS walked $fs_walked"
    check "[ \"\${n_open:-0}\" -gt 0 ] && [ \"$n_open\" = \"\$((n_walked + n_missing))\" ]" "every OPEN came from the session return (PATH_WALKED or PATH_MISSING)"
    check "[ \"\${n_walked:-0}\" -gt 0 ] && [ \"$n_walked\" = \"$n_named\" ]" "every walked OPEN has a path, rooted or made as the filesystem names it"
    # the last FILE_STATS is written before the final drain, so it can trail the records; the books (END above) close exactly
    check "[ \"\${fs_walked:-0}\" -gt 0 ] && [ \"$fs_walked\" -le \"\${n_walked:-0}\" ]" "FILE_STATS counts walked opens, never more than the WAL holds"
    check "[ \"\${n_close:-0}\" -gt 0 ] && [ \"$n_close\" = \"$n_same\" ]" "every CLOSE of those opens names the OPEN's object, not 0"
else
    echo "  SKIP (file identity not loadable here; CI and the VM run it)"
fi

echo "case 4: a bad flag [t+${SECONDS}s]"
"$B/p15d" --wal-dir "$T/c4" --bogus 2>/dev/null; rc=$?
check "[ $rc -eq 64 ]" "exit 64 (usage)"

rm -rf "$T"
echo "it_p15d: $([ $fail -eq 0 ] && echo PASS || echo FAIL) ($fail failed checks)"
[ $fail -eq 0 ]
