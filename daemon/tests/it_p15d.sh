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
inspect() { "$B/p15w-inspect" "$(ls -d "$1"/*/ | head -1)"; }
storm() { local ps=(); for _ in $(seq "$1"); do /bin/true & ps+=($!); done; wait "${ps[@]}"; }   # not a bare wait: p15d is a job too

echo "case 1: a 4 s run with 200 short processes"
"$B/p15d" --wal-dir "$T/c1" --duration 4 --stats-ms 200 --textfile "$T/c1.prom" 2>"$T/c1.err" &
pid=$!
sleep 1.5; storm 200
wait $pid; rc=$?
inspect "$T/c1" >"$T/c1.txt"; irc=$?
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
"$B/p15d" --wal-dir "$T/c2" 2>"$T/c2.err" &
pid=$!
sleep 2; storm 20; kill -TERM $pid; wait $pid; rc=$?
inspect "$T/c2" >"$T/c2.txt"; irc=$?
grep '^END' "$T/c2.txt"
check "[ $rc -eq 0 ] && [ $irc -eq 0 ]" "exit 0, WAL valid"
check "grep -q 'END: exit 0, state 0, invariant 1, signal 15' $T/c2.txt" "END records signal 15"

echo "case 3: forced spine overflow (4 KiB ring, drain paused 300 ms per poll, 400 processes)"
"$B/p15d" --wal-dir "$T/c3" --duration 5 --spine-ring-kb 4 --test-drain-pause-ms 300 --no-rt 2>"$T/c3.err" &
pid=$!
sleep 1.5; storm 400
wait $pid; rc=$?
inspect "$T/c3" >"$T/c3.txt"; irc=$?
cat "$T/c3.err"; sed -n '/^records/,$p' "$T/c3.txt"
n_gap=$(awk '$1=="GAP"{print $2}' "$T/c3.txt")
check "[ $rc -eq 4 ]" "exit 4 (INVALID)"
check "[ $irc -eq 0 ]" "the WAL itself is still valid"
check "[ \"\${n_gap:-0}\" -ge 1 ]" "GAP records locate the loss (got ${n_gap:-0})"
check "grep -q 'END: exit 4, state 2, invariant 1' $T/c3.txt" "END: INVALID, and the books still close (loss is counted)"

echo "case 4: a bad flag"
"$B/p15d" --wal-dir "$T/c4" --bogus 2>/dev/null; rc=$?
check "[ $rc -eq 64 ]" "exit 64 (usage)"

rm -rf "$T"
echo "it_p15d: $([ $fail -eq 0 ] && echo PASS || echo FAIL) ($fail failed checks)"
[ $fail -eq 0 ]
