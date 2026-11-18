#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# What p15d costs a real workload, end to end: each benign scenario timed without p15d and with
# p15d --flow, alternating (A B B A per pair of rounds, so drift hits both arms alike), no strace.
#   sudo P15_PYTHON=$HOME/p15venv/bin/python tools/workloads/cost.sh OUT_DIR [ROUNDS] [SCENARIO...]
# OUT_DIR/cost.csv: scenario, round, arm, wall ms, p15d exit; OUT_DIR/cost.txt: per scenario the
# median of each arm and their ratio. On this VM the host can stall the guest (E-0088): a round a
# stall touched is slow in one arm only, which is why the medians and every round are reported.
set -u
OUT=${1:?usage: cost.sh OUT_DIR [ROUNDS] [SCENARIO...]}
ROUNDS=${2:-5}
shift; shift 2>/dev/null
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
B=${B:-$REPO/build}
PY=${P15_PYTHON:-python3}
[ "$(id -u)" = 0 ] || { echo "cost.sh: needs root"; exit 2; }
names=("$@")
[ ${#names[@]} -gt 0 ] || names=(w1-build w3-web w4-archive w5-python w6-pipeline)
mkdir -p "$OUT" && OUT=$(cd "$OUT" && pwd)
export P15_REPO="$REPO" P15_PYTHON="$PY"
echo "scenario,round,arm,wall_ms,p15d_rc" >"$OUT/cost.csv"
one() {   # one NAME ROUND ARM
	local W="$OUT/tmp" P= prc=- t0 t1
	rm -rf "$W"; mkdir -p "$W/work"
	if [ "$3" = p15d ]; then
		"$B/p15d" ${P15D_FLAGS:---flow} --wal-dir "$W/wal" --stats-ms 1000 2>"$W/p15d.err" &
		P=$!
		for i in $(seq 600); do grep -q code=start "$W/p15d.err" && break; kill -0 $P 2>/dev/null || break; sleep 0.1; done
		grep -q code=start "$W/p15d.err" || { echo "p15d did not start: $(tail -1 "$W/p15d.err")"; return 1; }
	fi
	sync; echo 3 >/proc/sys/vm/drop_caches
	t0=$(date +%s%N)
	( cd "$W/work" && bash "$HERE/scenarios/$1.sh" "$W/work" "$W/manifest.json" ) >"$W/out" 2>&1 || echo "  $1 round $2 $3: workload failed: $(tail -1 "$W/out")"
	t1=$(date +%s%N)
	if [ -n "$P" ]; then kill -INT $P; wait $P; prc=$?; fi
	echo "$1,$2,$3,$(( (t1 - t0) / 1000000 )),$prc" | tee -a "$OUT/cost.csv"
}
for n in "${names[@]}"; do
	for r in $(seq "$ROUNDS"); do
		if [ $((r % 2)) = 1 ]; then one "$n" "$r" none; one "$n" "$r" p15d
		else one "$n" "$r" p15d; one "$n" "$r" none; fi
	done
done
rm -rf "$OUT/tmp"
echo "p15d flags: ${P15D_FLAGS:---flow}; rounds: $ROUNDS" >"$OUT/cost.txt"
"$PY" - "$OUT/cost.csv" >>"$OUT/cost.txt" <<'PY'
import csv, statistics, sys
rows = list(csv.DictReader(open(sys.argv[1])))
for n in dict.fromkeys(r["scenario"] for r in rows):
    a = [int(r["wall_ms"]) for r in rows if r["scenario"] == n and r["arm"] == "none"]
    b = [int(r["wall_ms"]) for r in rows if r["scenario"] == n and r["arm"] == "p15d"]
    rc = sorted({r["p15d_rc"] for r in rows if r["scenario"] == n and r["arm"] == "p15d"})
    ma, mb = statistics.median(a), statistics.median(b)
    print(f"{n:<12} without {ma:8.0f} ms  with p15d {mb:8.0f} ms  ratio {mb / ma:6.3f}  "
          f"(rounds without {a}, with {b}; p15d exits {rc})")
PY
cat "$OUT/cost.txt"
