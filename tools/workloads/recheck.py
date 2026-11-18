# SPDX-License-Identifier: MIT
"""Re-read a finished run's strace logs with today's witness (oracle.py) and compare its byte
totals with the graph totals that run's compare.json kept. For a run whose WAL and graph were
removed (run.sh does so unless P15_KEEP=1), after a change to the witness's rules.

    python3 tools/workloads/recheck.py OUT_DIR

One line per scenario and kind: EXACT, or DIFF with both totals. Exit 1 if any kind differs.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import oracle as O  # noqa: E402


def main(out: Path) -> int:
    bad = 0
    for d in sorted(p for p in out.iterdir() if (p / "compare.json").exists()):
        r = json.loads((d / "compare.json").read_text())
        f = O.load(d / "strace.txt.gz", light=not r["bytes"])
        cells = []
        for k, v in r["bytes"].items():
            mine = sum(f.bytes[t][k] for t in f.procs)
            ok = mine == v["graph"]
            bad += not ok
            cells.append(f"{k} {'EXACT' if ok else 'DIFF'} {v['graph']}" + ("" if ok else f" vs {mine}"))
        unseen = ", ".join(f"{k} {f.unseen[k]} ({f.unseen_bytes[k]} B)" for k in sorted(f.unseen))
        into = ", ".join(f"{k} {v}" for k, v in sorted(f.counts.items()) if k.endswith("_to_socket"))
        print(f"{d.name:<14} " + ("; ".join(cells) or "light trace: no bytes")
              + (f"; unseen: {unseen}" if unseen else "") + (f"; into a socket: {into}" if into else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
