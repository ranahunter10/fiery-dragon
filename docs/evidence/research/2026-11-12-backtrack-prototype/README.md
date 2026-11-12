# BackTracker's threshold rule as one DuckDB query: raw output (2026-11-12)

Evidence for STATE decision 35 and E-0205; the query is in `docs/research/2026-11-12-full-capture-graph-duckdb.md` §2.

| File | What | Where it ran |
|---|---|---|
| `backtrack_check.py` | The `WITH RECURSIVE ... USING KEY` query; a hand-made graph checked against BackTracker's answer worked by hand; a uniform random graph and a graph with hubs (1 % of the nodes on half of the edges), 900,000 edges over 150,000 nodes, three rounds each | dev container, 2 CPUs, DuckDB 2.0.0, `python3 backtrack_check.py > output.txt`, 2026-11-12 |
| `output.txt` | Its output | same |

What it shows (MEAS, dev container, not the target): the query returns BackTracker's set and thresholds on the hand-made graph (EQUAL). Uniform random: 3 nodes reached, about 0.04 s. Hubs: 133,701 of 150,000 nodes reached, 0.24-0.27 s. What it does not show: the time on a real provenance graph or on the VM; that is the soak's graph (decision waiting 8, item 2).

`SHA256SUMS` covers the two files above (`sha256sum -c SHA256SUMS`).
