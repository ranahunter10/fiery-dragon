# The full capture layer, the causal graph and DuckDB: what is settled, what to change, what is open (2026-11-12)

Research for the maintainer's request of 2026-11-12: build the full capture layer efficiently, learn from the state-of-the-art tools' code and the papers, model the data and the graph properly in DuckDB, and leave no question unanswered. This note builds on the project's earlier research and does not repeat it:
- reads and writes: the project doc `RESEARCH_capture_read_write_2026-10-21.md`, `research_capture_rw_2026-10-21/*`, `docs/research/2026-11-06-dataflow-slice-b/*`;
- reduction, read in the PDFs: `2026-11-09-slice-b-design-checks.md` (Xu et al. CCS'16; Hossain et al. USENIX Sec'18), ADR-0005;
- the tools' volume, identity and loss handling: `2026-11-06-dataflow-slice-b/tools.md`.

It fills the three gaps those left:
1. **DuckDB:** no research behind ADR-0028 beyond "DuckDB 2.0.0".
2. **The graph's query algorithms:** backtracking, forward tracking, ranking, storage.
3. **The tools' process-state code,** which our graph builder now reimplements.

Grades as in `CONTRIBUTING.md` §5. Sources are R-045 to R-051 in `papers.csv`.

## 1. Where the capture layer stands against the full design

| Flow | Captured now | Planned | Evidence |
|---|---|---|---|
| Process lifecycle (fork, exec, exit, comm) | Yes, never shed; snapshot and reconciliation | — | ADR-0009, -0017, -0023, -0025; soak E-0202 |
| File identity (open, close, open file, object) | Yes; a path even when the fentry is skipped; pseudo files named as the kernel names them | — | ADR-0015, -0027, -0029; E-0198 |
| Network intents (connect, accept, listen, bind), exact client join | Yes | NET v3 with the socket's object id (2e) | ADR-0004, -0022 |
| **Reads and writes (files, pipes, sockets)** | **No** | 2b, one FLOW per call, then 2c folding by Xu's rule | ADR-0005 |
| splice, sendfile, copy_file_range, tee, vmsplice; mmap at map time; rename, unlink, link, truncate | No | 2d | slice-B checks K15-K17, V1-V2 |
| io_uring completions | No (counted as out of scope today) | 2e | K18 |
| Memory made executable; writes into another process; module and BPF loads, setxattr | No | slices C, D, E (steps 3-5) | STATE decision 22 |

**What this means for the graph (SRC):** ADR-0028 writes every open as one edge from file to process, whatever its access mode (graph.sql `edge_src`). A file a process writes therefore has no edge *from* the writer. **A backtrack from a written file cannot reach its writer until 2b's FLOW records exist.** That makes step 2b the prerequisite of investigation, not one more data source. The soak's dropper-chain check (E-0202) passes because it tests the shape (written, then executed), not a flow.

## 2. DuckDB: how to load, model and query

### Findings

| # | Finding | Grade | Source |
|---|---|---|---|
| D1 | DuckDB keeps a min-max zonemap per column per row group and skips row groups whose range excludes a filter; "the more ordered the data within a column, the more valuable the zonemap indexes will be." | DOC | R-051 (indexing guide) |
| D2 | ART indexes (created by PRIMARY KEY, UNIQUE, FOREIGN KEY or CREATE INDEX) slow every insert, do not help joins, aggregations or sorts, and must fit in memory when built; they pay off only for very selective point lookups (< 0.1 %). | DOC | R-051 |
| D3 | Avoid row-by-row INSERT beyond about 100k rows; maximize the data per statement. MotherDuck's guide calls `executemany` slow beyond about 500 rows. | DOC | R-051 (import guide, insert page) |
| D4 | Measured: `executemany` cost 11 ms per row on the VM (55,247 rows: 626 s); one statement over numpy columns 2.4 us per row in the dev container. | MEAS | E-0203 |
| D5 | ASOF JOIN matches each left row with the nearest preceding right row on an inequality (usually `>=`) plus equalities, by sorting both sides and merging. It replaces a window function plus an inequality join. | DOC/BLOG | R-051 (ASOF guide, 2023 and 2025 blog posts) |
| D6 | `WITH RECURSIVE ... USING KEY (k)` keeps one row per key in the union table: a new row with key k replaces the old one, and `recurring.<cte>` reads the keyed state. In v2.0, `UNION` passes to the next iteration only new keys and keys whose payload changed, and stops when no key changes. Reported in v2.0 preview: reachability 42.6x faster than 1.5.5 (4.051 s to 0.095 s, 1M edges), LDBC SF100 pathfinding 6.55x (19.3 to 2.9 s). | DOC/BLOG/PDF | R-045 |
| D7 | DuckPGQ (SQL/PGQ, VLDB'23, CIDR'23) adds graph pattern matching and shortest paths as an extension. It has no time-respecting paths. | ABS | R-049 |
| D8 | AIQL partitions monitoring data by space and time ("one database per day", agent groups per partition), indexes the attributes queried most (executable, file name, IPs), and runs the most constrained pattern of a multi-event query first so its results narrow the rest. Reported: 124x faster than PostgreSQL and 157x than Neo4j on one APT case, 16x than Greenplum on average; scheduling alone 40x. | PDF | R-047 §3.2, §5.2, §6 |

### What this means for our tables

- **Load by column, always** (D3, D4): `raw.insert_rows` and the raw loader. No `executemany` anywhere in the build. The pidsmaker `ops` table (a handful of rows) is the one left.
- **No constraints, no ART** (D2): the graph tables have none today. Keep it so; joins are hash joins.
- **Order by time where we filter by time** (D1): `edge` is built ordered by `ts_ns`, so a time-window query skips row groups. The raw tables are in ring and sequence order, which is close to time order per ring. Nothing to change. Check it with `EXPLAIN ANALYZE` when the first time-window query exists.
- **One DuckDB file per run** is AIQL's time partition (D8). For runs longer than a day, export each day's edges to Parquet under a date-partitioned directory; DuckDB prunes the partitions. Nothing needed before a multi-day run.
- **Time-versioned attributes by ASOF** (D5, and Tracee's changelog in §4): `proc.cmd` and `proc.exe_path` hold a process's *last* image (`build.py` `proc_rows`). An event before an exec is labelled with the program run later; a Python process that then runs a memfd shows the memfd's name on its earlier opens. The graph needs a `proc_image` table, one row per exec (process key, image number, time, filename, argv, object of the executable), and each edge's image found by `ASOF JOIN proc_image ON key AND edge.ts_ns >= image.ts_ns`. **Recommendation R1.**

### Backtracking in one query (D6, BackTracker)

BackTracker (King and Chen, SOSP'03, §2.3; R-046, PDF) builds a backward dependency graph from a detection point with a **time threshold per object**: an event P→O over [x, y] adds P if x < threshold(O), and P's threshold becomes min(threshold(O), y); the log is scanned from the latest event back. Keeping the *largest* threshold per node and repeating until no threshold changes gives the same set without scanning order. That is a keyed fixpoint, which `USING KEY` evaluates directly:

```sql
WITH RECURSIVE bt(node, thr) USING KEY (node) AS (
    SELECT :poi_node, :poi_time
    UNION
    SELECT e.src, max(least(bt.thr, e.t1))          -- the latest time the source can still matter
    FROM bt JOIN edge e ON e.dst = bt.node AND e.t0 < bt.thr
    LEFT JOIN recurring.bt r ON r.node = e.src
    WHERE r.thr IS NULL OR least(bt.thr, e.t1) > r.thr
    GROUP BY e.src
)
SELECT * FROM bt;
```

- Checked in this session (MEAS, dev container with 2 CPUs, DuckDB 2.0.0; [script and output](../evidence/research/2026-11-12-backtrack-prototype/)):
  - On a hand-made graph it returns BackTracker's answer exactly. It excludes a source whose event came after the sink's threshold, and a writer that wrote after the reader had read; a later cycle back does not matter.
  - On 900,000 random edges over 150,000 nodes, the backtrack reaches 3 nodes in about 0.04 s. Times fall as the walk goes backward, so a uniform random graph dies out fast.
  - **With hubs** (half of all edges start or end at 1 % of the nodes, as shells and shared libraries do), it reaches 133,701 of the 150,000 nodes, the dependency explosion, in about 0.25 s, because no path is enumerated.
- On the VM, on the hour's soak graph (MEAS; [evidence](../evidence/vm/2026-11-12-backtrack-soak/)): 0.055 to 0.113 s per backtrack over 925,014 edges and 153,914 nodes. No edge points into a file, so every backtrack stops at the files it reaches. From p15d it reached 3,840 files and no other process. From a python process forked in the run it reached that process's parent and 34,239 files. Both stop at a process from the opening snapshot, which has no CLONE edge into it.
- **What the query cannot cross today** (SRC, `graph.sql`): a write (no file→writer edge until 2b), a TCP connection (the client-to-server join is the `sock_pair` table, not an edge), and an overlay file's backing file (`file_backing`, also a table). `track.py` (R2) must follow `sock_pair` and `file_backing` as edges, and its tests must cross a connection.
- Forward tracking is the mirror: the earliest time each node can be affected, `min(greatest(...))`.
- No path is enumerated, so the query cannot blow up with paths. It can still return a large node set: dependency explosion is a property of the data, met by reduction (Hossain's FD downstream) and ranking (DepImpact, §3).
- **Recommendation R2:** `python/p15/graph/track.py` with backward and forward queries, tested against a straightforward Python BackTracker on generated graphs (equal node sets and thresholds); on the VM, run on the soak's graph and time it. Its answers are only meaningful once 2b gives write edges, so the code can come now and the first real use after 2b.

### Loading speed (gate 10)

The hour's graph builds in about 80 s; 67 s of that is Python decoding each record and building its row (E-0204). Earlier research measured batch `np.frombuffer` with a structured dtype at 8-11 ns per record, against 0.4-1.5 us for per-record decoding (project doc `research_capture_rebuild_2026-10-21/loaders_userspace.md` Q6, dev container). Our records have a fixed part and variable parts, so the vectorizable step is:
1. walk a batch's record headers once to get each record's offset, type and length (one cheap step per record);
2. per type, gather the fixed parts with one fancy-indexing operation on a `uint8` view (`buf[offsets[:, None] + arange(size)]`) and view them as the generated structured dtype;
3. slice only the variable parts (paths, argv) per record.

`schema/gen/gen.py` already knows every layout, so it can emit the numpy dtypes. **Recommendation R3**, for gate 10, judged by the soak's `--strict-graph-time`.

## 3. The graph's algorithms from the papers

| # | Paper | What it gives us | Grade |
|---|---|---|---|
| G1 | King and Chen, *Backtracking Intrusions*, SOSP'03 | The threshold rule above. Dependency types: fork, read/write, mmap by mode, attribute calls, and any call naming a file. Default "high-control" events only. Filters: hide files read but never written in the period (cannot cut a chain); fold helper processes fed only by their parent; intersect the graphs of several detection points. | PDF, R-046 |
| G2 | Hossain et al., USENIX Sec'18 (read before) | Versioned nodes built online (BuildVer, REO/RNO), FD and SD reductions 4.6-19.1x, downstream of capture. | PDF, R-040 |
| G3 | Fang et al., *DepImpact*, USENIX Sec'22 | Weights each edge by discriminative features (data flow amount, time, node degree), propagates impact backward from the point of interest to entry nodes, then forward from the top-ranked entries, to cut graphs of over 100,000 edges to the critical part. | ABS + DOC, R-048 |
| G4 | Gao et al., *AIQL*, USENIX ATC'18 | Time and host partitioning; the most constrained pattern first (D8). | PDF, R-047 |
| G5 | Xu et al., CCS'16 (read before) | The causality-preserving fold, local and online; done in the kernel in 2c (ADR-0005). | PDF, R-039 |

What follows for us (INF unless marked):
- **Keep bytes and counts on FLOW** (G3): DepImpact's weights need the data-flow amount. ADR-0005's FLOW already carries first and last time, count and bytes; folding keeps them summed. Nothing to change, a reason not to drop them.
- **Versions come from writes** (G2, CamFlow): a file node gets a new version when something flows into it. With FLOW records, the graph can version file nodes at each write interval, so a backtrack through a file stops at the version the reader saw. The threshold query already gets that answer from times alone. Versions are needed for the export (CDM-style objects) and for FD. Step 7 open item from the slice-B checks: map FLOW's [first, last] onto the theorems' instantaneous events, and say how.
- **Read-only files hidden by default in views, never in tables** (G1): a view for analysts, never a deletion.
- **Order of reductions** (G2, G5): Xu's fold in the kernel (2c), then FD on a copy downstream. The slice-B checks argue FD on folded records gives what FD gives on unfolded ones (INF); 2c's tests check it on generated streams.

## 4. The tools' process-state code

| # | Tool, commit | Code | What it does | Grade |
|---|---|---|---|---|
| T1 | Tetragon `63332a1c7523` | `pkg/process/process.go` `GetProcessID` | A process is (pid, ktime) | SRC |
| T2 | Tetragon | `pkg/process/cache.go` | An LRU with reference counts (a child holds its parent). Deletion takes two GC ticks (delete-pending, delete-ready, deleted), so a late event still finds its process. An LRU eviction drops the parent's reference, counted (`processCacheEvictions`). | SRC |
| T3 | Tetragon | `pkg/eventcache/eventcache.go` | An event whose process or parent is not yet known is held and retried a bounded number of times, each retry counted by cause (`CacheRetries(ProcessInfo/ParentInfo/AncestorsInfo)`). | SRC |
| T4 | Tracee `2f9dc40c20b1` | `pkg/datastores/process/taskid.go` | A process is a 32-bit murmur hash of (pid, start time rounded to 100 ms), rounded so procfs start times (clock ticks) match the kernel's | SRC |
| T5 | Tracee | `taskinfo.go`, `fileinfo.go` | A task's name, parent, uid and gid, and a file's info, are kept as a changelog of three values with times, read "at" a time (`GetNameAt`, `GetPPidAt`) | SRC |

What follows for us:
- **Our identity is stricter than both** (T1, T4): (tgid, start_ns) read exactly by a BPF iterator in the snapshot (ADR-0009, -0024). There is no hash, so no collision, and no rounding, so two processes with the same pid started within 100 ms stay apart. Nothing to change.
- **Time-versioned attributes** (T5) are R1, done by ASOF over a full history instead of a three-entry changelog. The graph is built offline from the WAL, so it can keep every value.
- **A streaming builder** (gate 10) faces T2's and T3's problem: an event can arrive before its process's FORK (the rings are separate) and must wait, bounded and counted. BackTracker keeps such pending interval events in a hash table keyed by sink (G1 §2.3). **Recommendation R4:** gate 10's builder holds early events in a bounded pending table and resolves them when the process appears. It counts each held, resolved and expired event, the expired ones being the offline builder's placeholders (ADR-0028) made explicit. The offline builder stays the reference the streaming one is tested against.

## 5. Recommendations

| # | Change | When | Test |
|---|---|---|---|
| R1 | `proc_image` per exec; edges get the image current at their time by ASOF JOIN; `proc.cmd` kept as the last image for compatibility | graph v1 (gate 10), or a small PR before 2b | graph tests: an open before and after an exec name different images; the soak's memfd step |
| R2 | `track.py`: backward and forward queries with `USING KEY`, BackTracker's thresholds; `sock_pair` and `file_backing` followed as edges | code now; first real use after 2b | equal to a Python reference on generated graphs; timed on the soak's graph on the VM |
| R3 | Bulk decode of the WAL with generated numpy dtypes | gate 10 | the soak's graph build under 60 s per hour (`--strict-graph-time`) |
| R4 | A streaming builder with a bounded, counted pending table | gate 10 | equal to the offline builder on the soak's WAL |
| R5 | Step 2b as planned (ADR-0005): first a cost harness for the read/write hooks and the event rates under the soak's workload, then FLOW per call and the ceiling gate, then 2c. Keep bytes and counts. The graph's write-direction edges come from FLOW. | next (gate 5) | the ceiling gate (N3); the soak with backtracking from written files |

## 6. Questions and where each stands

| Question | Status |
|---|---|
| Does capture miss what real programs do? | Answered for what is hooked: 38,363 of 38,363 operations in an hour (E-0202) |
| Does it hold for an hour without leaking or drifting? | Answered: memory flattens at 27.65 MiB, CPU flat (E-0203) |
| What does it cost idle and under load? | Answered: 1.14 ms/s idle (E-0200), 4.3 ms/s under the soak's load (E-0202); program bodies 897 ns per open+close (E-0192), against a 500 ns budget: **open** |
| Can the graph answer "who wrote this file and where did it come from"? | **No, until 2b** (§1); the query exists in design (R2) |
| Is the graph's labelling of processes right at every event time? | **No**: the last image labels everything (R1); and a process takes any of its threads' new names, so p15d is named `p15d-writer` (E-0206, decision waiting 9) |
| Can the graph keep up with capture? | **Not yet**: about 80 s per hour, target 60 (R3, gate 10) |
| Will reads and writes fit the pipeline? | **Open**: 2b's ceiling gate decides; folding by Xu's rule (2c) and per-CPU batching (decision waiting 6) are the answers ready |
| Are the network programs skipped under contention? | **Open**: decision waiting 2, measured in 2e |
| Is the spine starved behind bulk under a flood? | **Open**: decision waiting 3, measured in 2b's ceiling gate |
| How do we compare with the published tools? | **Open**: step 6, with the tamper window (decision waiting 5) |
| What is out of scope? | Declared: the kernel's internal I/O, per-access mapped I/O (STATE decision 22) |

None of these is unanswered in the sense of unknown status. Each is answered, measured, or has the gate that answers it.
