# The backtracking query on the hour's soak graph (2026-11-12)

Evidence for E-0206 and STATE decision 35. VM `p15-dev-2604`, DuckDB 2.0.0 in `~/p15venv`, the graph of the one-hour soak (`/var/tmp/p15-soak/graph.duckdb`, built in E-0204), opened read-only. The two scripts were given in chat on 2026-11-12; the VM checked each against the sha256 given with it (`bt_soak.py: OK`, `bt_diag.py: OK`), and those sums match the committed scripts. The two outputs were transcribed from the maintainer's terminal paste.

| File | What |
|---|---|
| `bt_soak.py`, `output.txt` | The `USING KEY` backtrack (the note's §2 query on `edge(src, dst, ts_ns)`), from the process with the graph's latest edge, three rounds |
| `bt_diag.py`, `diag.txt` | The edges into each kind of node, by operation; who run 1 started from; the same backtrack from the most recent process with a CLONE and an EXECUTE edge into it |

What it shows (MEAS):
- **Speed:** 0.055 to 0.113 s per backtrack on 925,014 edges and 153,914 nodes.
- **No edge points into a file.** The eight (kind, op) rows sum to 925,014, every edge, and none has kind `file`. A backtrack therefore stops at every file it reaches (the note's §1, now measured).
- **Run 1 started from p15d itself** (tgid 60801, a process from the opening snapshot, with no CLONE edge into it). It reached the 3,840 files p15d had opened, and no other process.
- **Run 2** started from a python process forked in the run (tgid 60805). It reached its parent (node 139, the parent p15d also has, with no CLONE edge into it either) and 34,239 files, and stopped.
- **p15d's process is named `p15d-writer`.** That is its writer thread's name (`daemon/p15d.c` `pthread_setname_np`). `python/p15/proctree.py` gives a process the comm of any of its threads' RENAME records, without comparing the record's tid with the tgid (SRC). This is decision waiting 9.

What it does not show: a backtrack that crosses a write or a TCP connection. Neither has an edge yet (step 2b; `sock_pair` is a table, not an edge).

`SHA256SUMS` covers every file here except this README (`sha256sum -c SHA256SUMS`).
