---
status: accepted
date: 2026-11-12
owner: Ashish Rana
consulted: [python/p15/proctree.py and python/p15/graph at 7273603; fs/exec.c v7.0 (begin_new_exec, __set_task_comm); include/trace/events/task.h v7.0; the hour's soak graph on the VM (E-0206); Tracee pkg/datastores/process at 2f9dc40 (time-versioned task info); DuckDB AsOf join documentation (R-051); maintainer 2026-11-12 ("recommendations accepted": STATE decisions waiting 8 item 3 and 9)]
supersedes: none (extends ADR-0028 rule 2: what a process node says about its program and its name)
---

# 0031: The graph keeps every program a process ran, each edge names the program at its time, and a process's name comes from its leader

## Context and problem statement

ADR-0028's `proc` table gives a process one program, its last (`proc.cmd`, `proc.exe_path`), and the process tree gives it the comm of any of its threads' renames. On the hour's soak graph this named p15d `p15d-writer`, its writer thread's name (E-0206). It also means an open made before an exec is shown with the program run after it. An investigation asks "which program did this", at the time it was done. How should the graph record a process's programs and its name?

## Decision drivers

1. Every edge must say which program its process was running at the edge's time.
2. A thread's rename must not relabel its process, because programs rename threads all the time (browsers, JVMs, our own p15d) and so can malware.
3. Nothing in the WAL changes. The records already carry what is needed: EXEC times, the opening snapshot, RENAME's tid.
4. Lookups must be set-based and fast at a million edges.

## Considered options

1. One row per image in a `proc_image` table, and each edge's image found by ASOF JOIN on time (Tracee's changelog idea, kept whole because the graph is built offline).
2. One process node per image, so an exec makes a new node (CDM-style subject versions).
3. Keep the last image, and add the first image beside it.

## Decision outcome

**Chosen option:** option 1. It meets drivers 1 and 4 without changing the node set ADR-0028 and PIDSMaker's export rely on (option 2 would split every process at each exec). Option 3 is wrong for any process with more than two images.

### Rules

1. **`proc_image`:** one row per program a process ran: `(node_id, image_no, valid_from, ts_ns, seen_in, filename, cmd, truncated, exe_major, exe_minor, exe_ino, backing, exe_node)`. Image `i` is in effect from its `valid_from` until image `i+1`'s. `seen_in` says where it came from:
   - `exec`: an EXEC record, valid from its time. `exe_node` is the file node of the EXECUTE edge at that time.
   - `snapshot`: the opening snapshot's program of a process that started before the capture, valid from the process's start (`start_ns`) when it is the process's first image.
   - `fork`: a child before its first exec runs its parent's code. The row copies the image the parent ran at the fork (found the same way for the parent) and is valid from the fork.
2. **Each edge's program:** `edge.src_image` and `edge.dst_image` are the `image_no` of the process at that end, found by `ASOF LEFT JOIN proc_image ON node_id AND edge.ts_ns >= valid_from`. They are NULL when that end is not a process, or when the process had no known program then. Edges into a process with no program are counted (`edge_proc_end_without_image`).
3. **Names from the leader:** a RENAME whose tid is the tgid (the leader) sets the process's comm. Every exec renames as the leader, because de_thread runs before `__set_task_comm` in `begin_new_exec` (fs/exec.c v7.0). Any other thread's rename names that thread only. It goes to `thread_name (node_id, tid, ts_ns, old_comm, new_comm, ring, seq)` and is counted (`thread_rename` in the books, `rename_thread` in the tree).
4. **Compatibility:** `proc.cmd` and `proc.exe_path` stay the last image, as ADR-0028 has them.
5. **Books:** `image_exec`, `image_snapshot` and `image_fork` count the images by source. `image_exec_without_edge` (an exec image with no EXECUTE edge at its time) must be 0: `python3 -m p15.graph` exits 1 otherwise.

### Consequences

- Good: "which program did this" is one join, correct at every edge's time, and a forked child's work before its exec is attributed to the code that did it.
- Good: a process keeps its own name. Thread names are still kept, with times, for analysts.
- Bad: two more tables and two ASOF joins in the build. Their cost on the soak graph is measured on the VM before this is called done (Confirmation).
- Bad: a process alive before the capture and not in the opening snapshot has no program until its first exec (counted, as today).

### Confirmation

- `python/tests/test_graph.py` `Images` (4 tests):
  - an open before and after an exec names different images;
  - a child before its exec has its parent's program;
  - a snapshot program holds from the process's start;
  - a thread's rename leaves the process's comm alone and lands in `thread_name`;
  - the CLI fails a run whose `image_exec_without_edge` is not 0.
- `tools/ci/mutate_py.py`: 15 mutants of the rules above.
- On the VM: the hour's soak graph rebuilt. Expected: p15d is named `p15d`, `image_exec_without_edge` is 0, and the build time is reported against decision 34's 60 s target.

### Falsifier

Reopen if:
- `image_exec_without_edge` is not 0 on a real run;
- a real run shows a leader rename with tid ≠ tgid (an exec that renames before de_thread) by an `exec` image whose process comm did not change;
- the two ASOF joins add more than 5 s to the hour's graph build on the VM.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | p15d's process is named `p15d-writer` in the soak graph, and `proctree.py` set the comm from any thread's RENAME | MEAS, SRC | E-0206, `python/p15/proctree.py` at 6244d48 |
| 2 | `begin_new_exec` calls `de_thread(me)` before `__set_task_comm`, and `trace_task_rename` records `task->pid` | SRC | fs/exec.c L1115, L1234-1238, L1079; include/trace/events/task.h (v7.0) |
| 3 | The RENAME record's tid is the renamed task's pid | SRC | bpf/progs/spine.bpf.c `spine_rename` (`r->h.tid = ctx->pid`) |
| 4 | Tracee keeps a task's name, parent and ids as a short changelog read at a time | SRC | Tracee `pkg/datastores/process` at 2f9dc40 (R-050) |
| 5 | ASOF JOIN matches each row with the nearest earlier row by an inequality plus equalities | DOC | R-051 |

## Pros and cons of the options

### 1. `proc_image` and ASOF (chosen)
- Good: exact at every edge; no change to nodes; one set-based join.
- Bad: two more tables.

### 2. A node per image
- Good: the CDM model; each version is a node of its own.
- Bad: splits every process at each exec, which breaks ADR-0028 rule 2's process key and the export's subject identity.

### 3. Last and first image
- Good: smallest change.
- Bad: wrong for any process with three or more images, and silent about which one applies.
