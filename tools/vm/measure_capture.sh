#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# The standing measurement matrix of the capture layer (audit 2026-11-12, §4 and §6 Phase A).
# One command on the VM, run for every capture PR before it merges, so that a cost or a regression
# is seen before the work is called done, not after.
#
#   make all build/open_cost build/prim_cost build/crc32c_bench        # as the user, first
#   sudo tools/vm/measure_capture.sh [--quick] [--dry-run] [--soak SECONDS] [--out DIR] [-- P15D_OPTIONS...]
#
# --dry-run checks the build and writes the manifest, then lists each step's command without running it.
#
# It builds nothing (CLAUDE.md: build as the user, sudo only to run). It refuses to run if a binary
# is missing or older than the newest source that goes into it, and it records the commit, whether
# the tree is clean, and every binary's sha256. P15D_OPTIONS after `--` go to every p15d it starts
# (for example `-- --batch-kb 1024 --queue-batches 16` to measure U1).
#
# Steps, each with its raw output, exit code and wall time, all in DIR:
#   1 env        kernel, CPUs, the host's speed (a null syscall), the commit
#   2 it_p15d    the end-to-end functional cases (daemon/tests/it_p15d.sh)
#   3 crc32c     the checksum's cost per byte (bench/crc32c)
#   4 prog_stats the BPF programs' bodies per open+close, unprofiled (bench/prim_cost/prog_stats.py)
#   5 open_cost  what capture adds to an open+close end to end, and p15d's CPU and switches
#   6 profile    p15d's profile with call graphs (open_cost --perf, perf report)
#   7 idle       p15d's CPU per second with nothing to do (bench/idle_cost, the default arm only)
#   8 soak       real programs for SECONDS: recall per step kind, names, graph checks, memory, WAL
# A step that fails is recorded and the next one runs; the exit code is 1 if any step failed.
# summary.md has one line per figure, taken from each step's own report.
set -u

QUICK=0
DRY=0
SOAK_S=600
OUT=""
P15D_OPTS=()
while [ $# -gt 0 ]; do
	case "$1" in
	--quick) QUICK=1 ;;
	--dry-run) DRY=1 ;;
	--soak) SOAK_S="$2"; shift ;;
	--out) OUT="$2"; shift ;;
	--) shift; P15D_OPTS=("$@"); break ;;
	*) echo "usage: sudo $0 [--quick] [--dry-run] [--soak SECONDS] [--out DIR] [-- P15D_OPTIONS...]" >&2; exit 2 ;;
	esac
	shift
done

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
if [ "$(id -u)" != 0 ]; then
	echo "measure_capture: run with sudo (the programs need root); build first as the user" >&2
	exit 2
fi
PY=${P15_PYTHON:-}
if [ -z "$PY" ]; then
	for c in "/home/${SUDO_USER:-root}/p15venv/bin/python" "$(command -v python3)"; do
		if [ -x "$c" ] && "$c" -c "import google_crc32c, duckdb" 2>/dev/null; then PY=$c; break; fi
	done
fi
if [ -z "$PY" ]; then
	echo "measure_capture: no Python with google_crc32c and duckdb; set P15_PYTHON" >&2
	exit 2
fi

B=build
need() {   # binary, sources...: present and newer than every source
	local bin=$1 s
	shift
	[ -x "$B/$bin" ] || { echo "measure_capture: $B/$bin is missing: make it as the user" >&2; exit 2; }
	for s in "$@"; do
		if [ "$s" -nt "$B/$bin" ]; then
			echo "measure_capture: $s is newer than $B/$bin: rebuild as the user" >&2
			exit 2
		fi
	done
}
need p15d daemon/*.c daemon/*.h bpf/progs/*.c bpf/include/*.h
need p15w-inspect
need open_cost bench/open_cost/open_cost.c
need prim_cost bench/prim_cost/prim_cost.c bench/prim_cost/prim_cost.bpf.c
need crc32c_bench bench/crc32c/crc32c_bench.c daemon/crc32c.c

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=${OUT:-/var/tmp/p15-measure/$STAMP}
mkdir -p "$OUT" || exit 2
if [ "$QUICK" = 1 ]; then R_PS=3; R_OC=6; R_IDLE=3; else R_PS=7; R_OC=20; R_IDLE=5; fi
EXTRA=()
for o in "${P15D_OPTS[@]}"; do EXTRA+=("--p15d-arg=$o"); done

FAILED=0
step() {   # name, command...: run, keep its output, time it
	local name=$1 t0 t1 rc
	shift
	echo "== $name" >&2
	if [ "$DRY" = 1 ]; then
		printf '%s would run:%s\n' "$name" "$(printf ' %q' "$@")" >> "$OUT/steps.txt"
		return 0
	fi
	t0=$(date +%s.%N)
	"$@" > "$OUT/$name.txt" 2> "$OUT/$name.err"
	rc=$?
	t1=$(date +%s.%N)
	awk -v n="$name" -v r="$rc" -v a="$t0" -v b="$t1" 'BEGIN { printf "%s rc=%d seconds=%.1f\n", n, r, b - a }' >> "$OUT/steps.txt"
	[ "$rc" = 0 ] || FAILED=1
	return 0
}

{
	echo "stamp $STAMP"
	echo "commit $(git rev-parse HEAD) $(git diff --quiet && git diff --cached --quiet && echo clean || echo DIRTY)"
	echo "kernel $(uname -r) cpus $(nproc)"
	echo "python $PY"
	echo "p15d_options ${P15D_OPTS[*]:-(defaults)}"
	echo "quick $QUICK soak_seconds $SOAK_S"
	sha256sum $B/p15d $B/p15w-inspect $B/open_cost $B/prim_cost $B/crc32c_bench
} > "$OUT/manifest.txt"

step it_p15d daemon/tests/it_p15d.sh "$B"
step crc32c sh -c "$B/crc32c_bench 4096 9 && $B/crc32c_bench 120 9"
step prog_stats python3 bench/prim_cost/prog_stats.py --p15d "$B/p15d" "${EXTRA[@]}" --ops 220000 --rounds "$R_PS" \
	--ref-nullsys-ns 89.1 -- "$B/open_cost" /var/tmp/p15-open-cost 200000 20000
step open_cost "$PY" bench/open_cost/run.py --p15d "$B/p15d" --workload "$B/open_cost" --dir /var/tmp/p15-open-cost \
	--rounds "$R_OC" "${EXTRA[@]}"
step open_cost_report "$PY" bench/open_cost/summarize.py "$OUT/open_cost.txt"
rm -rf "$OUT/perf"
step profile_run "$PY" bench/open_cost/run.py --p15d "$B/p15d" --workload "$B/open_cost" --dir /var/tmp/p15-open-cost \
	--rounds 3 "${EXTRA[@]}" --perf "$OUT/perf"
if [ -f "$OUT/perf/perf-0.data" ]; then
	step profile perf report -i "$OUT/perf/perf-0.data" --no-children -g none --sort dso,sym --stdio --percent-limit 0.5
	step profile_callers perf report -i "$OUT/perf/perf-0.data" --no-children --percent-limit 5 -g --stdio
fi
IDLE_OPTS=()                    # idle_cost's arm is NAME=OPT[=V],OPT...: P15D_OPTIONS in that form
i=0
while [ $i -lt ${#P15D_OPTS[@]} ]; do
	o=${P15D_OPTS[$i]}
	n=${P15D_OPTS[$((i + 1))]:-}
	if [ -n "$n" ] && [ "${n#-}" = "$n" ]; then
		o="$o=$n"
		i=$((i + 1))
	fi
	IDLE_OPTS+=("$o")
	i=$((i + 1))
done
IDLE_SPEC="default=$(IFS=,; echo "${IDLE_OPTS[*]}")"
IDLE_ARM=(--arm "$IDLE_SPEC")
step idle "$PY" bench/idle_cost/run.py --p15d "$B/p15d" --work /var/tmp/p15-idle --rounds "$R_IDLE" "${IDLE_ARM[@]}"
step idle_report "$PY" bench/idle_cost/summarize.py "$OUT/idle.txt"
step soak "$PY" bench/soak/soak.py --p15d "$B/p15d" --work /var/tmp/p15-measure-soak --duration "$SOAK_S" --clean \
	"${EXTRA[@]}"
step soak_report "$PY" bench/soak/summarize.py "$OUT/soak.txt"

{
	echo "# Capture measurement matrix, $STAMP"
	echo
	sed 's/^/    /' "$OUT/manifest.txt"
	echo
	echo "## Steps"
	echo
	sed 's/^/- /' "$OUT/steps.txt"
	echo
	echo "## Figures (each from its step's own report)"
	echo
	grep -h -E "failures|PASS|FAIL" "$OUT/it_p15d.txt" 2>/dev/null | tail -3 | sed 's/^/- it_p15d: /'
	grep -h -E "ns per byte|speed-up" "$OUT/crc32c.txt" 2>/dev/null | sed 's/^/- crc32c: /'
	grep -h -E "^\| (file_|\*\*all)" "$OUT/prog_stats.txt" 2>/dev/null | head -5 | sed 's/^/- prog_stats: /'
	grep -h -E "added per open\+close|p15d per open\+close|thread switches|lost to the ring|p15d idle" \
		"$OUT/open_cost_report.txt" 2>/dev/null | sed 's/^ *-* */- open_cost: /'
	grep -h -E "^ +[0-9.]+%" "$OUT/profile.txt" 2>/dev/null | head -8 | sed 's/^ */- profile: /'
	grep -h -E "median|budget" "$OUT/idle_report.txt" 2>/dev/null | head -4 | sed 's/^ *-* */- idle: /'
	grep -h -E "PASS|FAIL|recall|memory|WAL|graph" "$OUT/soak_report.txt" 2>/dev/null | head -14 | sed 's/^ *-* */- soak: /'
} > "$OUT/summary.md"
( cd "$OUT" && find . -type f ! -name SHA256SUMS ! -path './perf/*' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
chown -R "${SUDO_USER:-root}" "$OUT" 2>/dev/null
echo "measure_capture: $OUT/summary.md" >&2
cat "$OUT/summary.md"
exit "$FAILED"
