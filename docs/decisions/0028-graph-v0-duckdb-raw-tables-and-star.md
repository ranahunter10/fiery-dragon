---
status: accepted
date: 2026-11-11
owner: Ashish Rana
consulted: [STATE decision 22 step 7 and 22a.3 (graph v0 before 2b), ADR-0009, ADR-0015 rule 3 and decision 3, ADR-0019 G1, ADR-0022, ADR-0027, PIDSMaker at commit 15e5515 (read, not run), Xu et al. CCS'16 (R-039), DuckDB 2.0.0]
supersedes: none
---

# 0028: Graph v0: generated raw tables in DuckDB, a star built in SQL over them, and a PIDSMaker export that states what it leaves out

Accepted under the standing acceptance of STATE decision 22a (2026-11-10): recorded with its evidence for the maintainer's final review.

## Context and problem statement

The capture layer writes records; nothing yet turns a run into a graph. Decision 22a.3 put a first graph before step 2b so that the path from capture to a detection number runs end to end on the records that exist: FORK, EXEC, EXIT, OPEN, CLOSE, FD, BACKING and NET. Three things were open: where a run's records live for analysis, where the node rules of ADR-0009, ADR-0015 and ADR-0027 are implemented, and what an evaluation framework receives.

**Question:** how is a run's WAL turned into a provenance graph that can be queried, checked and exported, without a second copy of any rule?

## Decision drivers

1. **Never merge two different objects** (ADR-0015 driver 1): a false merge is false connectivity.
2. **Nothing is stated that capture did not observe.** An open's access mode is not a read or a write; an inferred join is not a join.
3. **No silent drop.** Every record that does not become a row, and every node named by a fallback, is counted.
4. **One source per rule** (ADR-0019 G1): layouts come from `schema/records.toml`; the process rules from `p15/proctree.py`; the file rules from one place.
5. The graph must be rebuildable from the WAL at any time: the WAL stays the record, the graph file is derived.

## Considered options

1. **Generated raw tables plus a star in SQL** (below).
2. Build nodes and edges in Python objects and insert only the graph.
3. Write PIDSMaker's four tables directly from the WAL.

## Decision outcome

**Chosen option:** option 1. The raw tables keep every field (driver 5) and make each rule a query that can be read and tested (driver 4). Option 2 hides the records the graph came from. Option 3 ties our graph to one consumer's vocabulary, which has no place for an open file, a denied open or an anonymous inode.

### Rules

1. **Raw tables are generated.** `schema/gen/gen.py` writes `schema/generated/p15_records.sql`: one table `raw_<name>` per record type, every version in it. Columns: `ring`, `seq`, the header (without `type` and `len`), the latest version's fields, then fields only an older version has; a variable field is a BLOB; a part is one nullable column per part field. The loader (`python/p15/graph/raw.py`) names no field: it fills the generated column list. A column the row's version lacks is NULL. A record that fails its check goes to `record_error`, never into a table.
2. **Process nodes come from the process tree** (`p15/proctree.py`, ADR-0009): the key is (tgid, start_ns). A process that only a bulk or snapshot record names is a node too, a placeholder the tree counts.
3. **File nodes follow the reader's trust table** (ADR-0015 rule 3, decision 3), in `python/p15/graph/graph.sql`:
   - ext4 (`0xEF53`), xfs (`0x58465342`), tmpfs (`0x01021994`), and btrfs (`0x9123683E`) without `SUBVOL_UNKNOWN`: the node is (dev, subvol, ino, gen);
   - the anonymous-inode filesystem (`0x09041934`): the node is the open file, `fid` (ADR-0027);
   - everything else, and an object whose facts the run does not hold: the node is the object id.
4. **The file an exec ran** is named from the EXEC record's own (dev, ino, gen) where the filesystem is in rule 3's first list and is not btrfs (EXEC carries no subvolume); otherwise it is the object capture saw with those three numbers most recently before the exec; otherwise it is a node of its own (`x:dev:ino:gen`), counted as `exec_file_unjoined`.
5. **Socket nodes are socket cookies** (ADR-0004 rule 5). Two sockets of one TCP connection on the host are paired only by the exact rule of ADR-0022 (same ISN, mirrored endpoints, one network namespace) in `sock_pair`; an accept without such a pair is counted, not paired by time.
6. **Edges point the way information can flow**, one row per record, with `ok` saying whether the kernel let it happen:

   | op | source → destination | from |
   |---|---|---|
   | CLONE | parent → child | FORK kind 1 |
   | EXECUTE | file → process | EXEC |
   | OPEN | file → process, with `access` r / w / rw from `f_mode` | OPEN; `ok` false for a denial (OPEN_VERDICT, or a negative verdict) and for `NEVER_OPENED` |
   | HELD | file → process | the first FD row of (process, open file) |
   | CONNECT, LISTEN, BIND | process → socket | NET |
   | ACCEPT | socket → process | NET |

   BACKING is a relation between two file nodes (`file_backing`), not an edge. An open is one edge whatever access it asked for: bytes are measured from step 2b on, and those FLOW records replace the open-level edge as the carrier of reads and writes.
7. **The PIDSMaker export** (`python/p15/graph/pidsmaker.py`) writes the four tables PIDSMaker reads, as CSV in its column order, and a manifest:
   - only allowed edges (`ok`), as EVENT_CLONE, EVENT_EXECUTE, EVENT_OPEN, EVENT_CONNECT, EVENT_ACCEPT, in PIDSMaker's own direction (object → subject for EXECUTE, OPEN and ACCEPT);
   - no EVENT_READ, EVENT_WRITE, EVENT_SENDTO/SENDMSG or EVENT_RECVFROM/RECVMSG until capture measures them (driver 2);
   - `timestamp_rec` is wall-clock ns through the nearest earlier clock anchor; `hash_id` is sha256 of the node's uuid, as PIDSMaker's loaders compute it;
   - the manifest lists every edge not exported, by reason, and the export refuses to finish if its counts do not close.
8. **The books.** `graph_count` holds, by name: three counts that must be zero (`edge_without_node`, `obj_facts_conflict`, `fid_two_objs`: the last two are ADR-0015's falsifiers), the file nodes per rule, the open files per first sighting, the opens without a path, denied or failed, the execs per join, the accepts without a pair, and the edges per operation. `python3 -m p15.graph` exits 1 when a must-be-zero count or a record error is not zero.
9. **A graph file is written once.** The builder refuses an existing file and removes a half-built one.

### Consequences

- Good: every rule is in one tested place; a run can be queried in SQL beside its graph; the export says what it does not contain.
- Good: DuckDB reads a dict of numpy arrays directly, so loading needs no pandas or Arrow.
- Bad: one more pinned dependency (duckdb 2.0.0, MIT, one abi3 wheel for CPython 3.12 and later).
- Bad: until NET v3 (step 2e) a socket seen as a descriptor (an FD row on sockfs) and the same socket in a NET record are two nodes; nothing joins them yet, and nothing guesses.
- Bad: with open-level edges only, a file a process writes has an edge towards the process, not from it. A detection number computed on this export measures the pipeline, not the detector's ceiling. Step 2b fixes the cause.
- Bad: processes alive before the capture have their program as text (`proc.exe_path`), not as an EXECUTE edge: no exec happened in the run.

### Confirmation

- `python/tests/test_graph.py` (28 tests): each rule above has a test that fails when it is broken, including ADR-0027's confirmation (one object id with two fids is two nodes; one fid in two processes is one node) and ADR-0015's (an evicted ext4 file is one node; two pipes with one inode number are two).
- `schema/gen/test_gen.py` `SqlTest`: the generated tables, and that the committed SQL loads into DuckDB with exactly the generated columns.
- `tools/ci/mutate_py.py`: 95 mutants of the generator's SQL part, the loader, the builder, `graph.sql`, the export and the CLI.
- Not yet shown: a run with real OPEN, FD and NET records. The dev container loads only the spine programs (the file and net programs fail with EPERM there), so the first real graph is built on the VM (the commands are in the PR).

### Falsifier

Reopen if:
- a real run has a non-zero `obj_facts_conflict`, `fid_two_objs` or `edge_without_node`;
- `exec_file_unjoined` is common on the VM's ext4 root (it should be zero there: rule 4's first branch needs no OPEN);
- PIDSMaker's graph construction rejects the four tables as written (its loader or its `build_default_graphs` needs a column or an operation this export does not give);
- building a day-long run does not fit the VM's memory (the builder decodes a run's records into memory before loading: measured in step 6).

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | PIDSMaker reads four PostgreSQL tables with these columns | SRC | PIDSMaker `postgres/init-create-databases.sh` L18-60 at 15e5515 |
| 2 | Its loaders store an event from the source of information to the destination (EXECUTE, OPEN, ACCEPT, READ, RECV* reversed), and hash a node as sha256 of its uuid | SRC | `pidsmaker/utils/dataset_utils.py` L8-20; `dataset_preprocessing/darpa_tc/create_database_e3.py` L22-26, L280-305 |
| 3 | Its graph construction cuts windows by wall-clock time and keeps only operations in the dataset's vocabulary (ten for DARPA TC; ACCEPT is not one) | SRC | `pidsmaker/preprocessing/build_graph_methods/build_default_graphs.py` L255-345; `dataset_utils.py` L33-55 |
| 4 | PIDSMaker is Apache-2.0; nothing of it is copied here | SRC | its `LICENSE` |
| 5 | A dependency graph's edges carry a type, a time and the direction of information flow; backtracking follows them by time | PDF | Xu et al. CCS'16 §2.1 (R-039) |
| 6 | DuckDB 2.0.0 inserts from a dict of numpy arrays, keeps u64 above 2^63, BLOBs with NULs and masked NULLs | MEAS | [`2026-11-11-graph-v0`](../evidence/graph/2026-11-11-graph-v0/README.md) |
| 7 | The 28 tests pass and the 95 mutants are killed in the dev container | MEAS | same |
| 8 | The file and net programs do not load in the dev container (EPERM), so no real OPEN or NET record was graphed here | MEAS | same |
| 9 | The export is accepted by PIDSMaker | OPEN | PIDSMaker has not been run (the maintainer decides where) |

## Pros and cons of the options

### 1. Generated raw tables plus a star in SQL (chosen)
- Good: the records stay queryable; rules are short and tested; one generator.
- Bad: the raw tables repeat the WAL's content in the graph file.

### 2. Graph only, built in Python
- Good: a smaller file.
- Bad: a question the graph cannot answer needs a new program; the rules hide in loops.

### 3. PIDSMaker's tables directly
- Good: the shortest way to a number.
- Bad: its vocabulary cannot hold a denied open, an open file, a backing relation or a count of what was left out.
