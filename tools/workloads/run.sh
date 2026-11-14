#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Real workloads and attack scenarios, each captured by p15d and watched by strace, then compared
# (tools/workloads/README.md). Run as root on the VM, from the repo:
#   sudo P15_PYTHON=$HOME/p15venv/bin/python tools/workloads/run.sh OUT_DIR [SCENARIO...]
# SCENARIO is a file name in tools/workloads/scenarios without .sh (default: all of them).
# Per scenario, OUT_DIR/<name>/ gets p15d's log and exit code, the workload's output, strace's log
# (gzipped), the graph's books, the rules' alerts and compare.py's report (text and JSON).
# OUT_DIR/summary.txt has one line per scenario. The WAL and the graph file are removed after the
# comparison unless P15_KEEP=1. Exit 0 when every scenario ran and was compared (the verdicts are
# in the reports), 1 if one could not run, 2 on a usage error.
set -u
OUT=${1:?usage: run.sh OUT_DIR [SCENARIO...]}
shift
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
B=${B:-$REPO/build}
PY=${P15_PYTHON:-python3}
[ "$(id -u)" = 0 ] || { echo "run.sh: needs root (p15d loads BPF programs)"; exit 2; }
for t in strace curl tar gzip sha256sum git make cc; do
	command -v $t >/dev/null || { echo "run.sh: '$t' is missing"; exit 2; }
done
[ -x "$B/p15d" ] && [ -x "$B/p15w-inspect" ] || { echo "run.sh: $B/p15d or p15w-inspect not built (make)"; exit 2; }
"$PY" -c 'import duckdb, google_crc32c' || { echo "run.sh: $PY lacks duckdb or google_crc32c"; exit 2; }
mkdir -p "$OUT" || exit 2
OUT=$(cd "$OUT" && pwd)
names=("$@")
[ ${#names[@]} -gt 0 ] || names=($(cd "$HERE/scenarios" && ls *.sh | sed 's/\.sh$//'))
export PYTHONPATH="$REPO/python" P15_REPO="$REPO" P15_PYTHON="$PY"
strace -V | head -1 > "$OUT/strace-version.txt"
uname -r > "$OUT/kernel.txt"
failed=0

wait_for() {   # wait_for FILE PATTERN SECONDS PID: an event, bounded; stops early if PID has exited
	local i
	for i in $(seq $(($3 * 10))); do
		grep -q "$2" "$1" 2>/dev/null && return 0
		kill -0 "$4" 2>/dev/null || return 1
		sleep 0.1
	done
	return 1
}

for n in "${names[@]}"; do
	S="$HERE/scenarios/$n.sh"
	[ -f "$S" ] || { echo "run.sh: no scenario $n"; failed=1; continue; }
	W="$OUT/$n"; rm -rf "$W"; mkdir -p "$W/work"
	trace=$(sed -n 's/^# trace: *//p' "$S" | head -1)
	if [ "$trace" = light ]; then set_=$("$PY" -c "import sys; sys.path.insert(0,'$HERE'); import oracle; print(oracle.TRACE_LIGHT)"); light=--light
	else set_=$("$PY" -c "import sys; sys.path.insert(0,'$HERE'); import oracle; print(oracle.TRACE)"); light=; fi
	echo "== $n ($trace trace) $(date -u +%H:%M:%S)"
	"$B/p15d" ${P15D_FLAGS:---flow} --wal-dir "$W/wal" --stats-ms 1000 --textfile "$W/p15d.prom" 2>"$W/p15d.err" &
	P=$!
	if ! wait_for "$W/p15d.err" code=start 60 $P; then
		echo "   p15d did not start: $(tail -2 "$W/p15d.err")"; kill -INT $P 2>/dev/null; wait $P; failed=1; continue
	fi
	t0=$(date +%s%N)
	( cd "$W/work" && timeout 900 strace -f -yy -qq -ttt -s 0 -e signal=none -e trace="$set_" -o "$W/strace.txt" \
		bash "$S" "$W/work" "$W/manifest.json" ) >"$W/workload.out" 2>&1
	wrc=$?
	t1=$(date +%s%N)
	kill -INT $P; wait $P; prc=$?
	RUN=$(ls -d "$W"/wal/*/ 2>/dev/null | head -1)          # p15d writes one run directory under --wal-dir
	"$B/p15w-inspect" "$RUN" >"$W/inspect.txt" 2>&1; irc=$?
	"$PY" -m p15.graph "$RUN" "$W/graph.duckdb" >"$W/graph.txt" 2>&1; grc=$?
	man=; [ -s "$W/manifest.json" ] && man="--manifest $W/manifest.json"
	if [ $grc = 0 ]; then
		"$PY" "$HERE/compare.py" "$W/graph.duckdb" "$W/strace.txt" $light $man --p15d-rc $prc --json "$W/compare.json" >"$W/compare.txt" 2>&1
		crc=$?
		"$PY" -m p15.graph.rules "$W/graph.duckdb" >"$W/rules.txt" 2>&1
	else crc=9; fi
	v=$(grep '^VERDICT' "$W/compare.txt" 2>/dev/null | head -1)
	printf '%-14s workload rc=%-3s %6s ms  p15d rc=%s inspect rc=%s graph rc=%s compare rc=%s  %s\n' \
		"$n" $wrc $(( (t1 - t0) / 1000000 )) $prc $irc $grc $crc "${v:-no verdict}" | tee -a "$OUT/summary.txt"
	sed -n '2,/^VERDICT/p' "$W/compare.txt" | sed 's/^/   /'
	gzip -f "$W/strace.txt"
	du -sb "$W/wal" 2>/dev/null | awk '{print "wal bytes " $1}' >>"$W/graph.txt"
	[ "${P15_KEEP:-0}" = 1 ] || rm -rf "$W/wal" "$W/graph.duckdb" "$W/work"
	[ $crc = 0 ] || failed=1
done
exit $failed
