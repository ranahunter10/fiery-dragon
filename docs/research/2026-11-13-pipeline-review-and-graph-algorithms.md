# The pipeline end to end: a review of capture, WAL, DuckDB and graph, and what the algorithms and other fields add (2026-11-13)

The maintainer's request of 2026-11-13: read the research the project holds, the state-of-the-art tools and the graph algorithms; review the whole capture layer through to the graph; and say where the design can be made stronger, with numbers, before the PIDSMaker export.

This note builds on the earlier ones and does not repeat them:
- the tools' kernel side and user side: `2026-11-12-open-cost-against-the-tools.md`, `2026-11-12-userspace-pipelines.md`, `2026-11-06-dataflow-slice-b/tools.md`;
- DuckDB, BackTracker and the reductions: `2026-11-12-full-capture-graph-duckdb.md`, `2026-11-09-slice-b-design-checks.md`;
- what "done" means: `docs/audits/2026-11-12-capture-review.md` §5.

What it adds:
1. a review of PR #90's programs and of the path from a FLOW record to a graph edge (§1, §2);
2. one kernel feature of 7.0 that no harness has measured (§3);
3. the graph algorithms, each tied to a query the project needs (§4);
4. patterns from other fields, each tied to a part of the pipeline (§5).

Grades as in `CONTRIBUTING.md` §5. Sources are R-053 to R-057 in `papers.csv`. **No number is quoted here that the project has not measured**; every candidate is INF until its harness runs on the VM. No third-party code was run.

## 1. Review of the flow programs (PR #90, `capture/flow-programs` at e07d9d7; SRC)

| # | Finding | Where | Effect | Proposed fix |
|---|---|---|---|---|
| V1 | `fixed_size()` gave every STATS version from 1 up the v1 size | `daemon/records.c` L17 | every STATS v2 record refused; CI's `make test-c` failed | fixed: `version == 1` again (commit 868745a on the branch) |
| V2 | **A `read()` or `write()` on a socket is recorded twice:** once by the VFS session as READ or WRITE, once by the socket tracepoint as RECV or SEND | `bpf/progs/file.bpf.c` `rw_entry` L975, `rw_return` L1000: no test for a socket | double bytes and two edges per transfer; the books still close, because each record is counted | ADR-0005 rule 11 and the design checks §4 item 1 ask for it: the VFS hook sees the socket (`S_ISSOCK(inode->i_mode)`), counts `V_OWNED_BY_SOCK` and writes nothing. At the entry, so the return does not run. Book B1 gains the term |
| V3 | **A lost FILE record is never retried, and its object's facts are marked as sent** | L921-922: `write_file_rec()` returns nothing; `facts_done()` runs whether or not the record was reserved. The open-file entry stays, so `created` is 0 at the next transfer | after one bulk-ring reserve failure, that open file has no FILE in the run and the object no facts in that segment. `p15_flow.h` says "the file stays unregistered, retried next time": the code does not do that | `write_file_rec()` returns whether it submitted; on failure, delete the entry it created and skip `facts_done()`. A test that fails the reserve (the forced-overflow case) must then see the FILE at the next transfer |
| V4 | Two early returns without a counter: `if (!inode) return 0;` after `V_ATTEMPT` and after `S_ATTEMPT` | L1031, L1112 | book B4 would not close, so it is not silent, but the cause would have no name | a `NO_INODE` counter as a term of B4, or drop the branches if the verifier lets the trusted pointer through |
| V5 | "One FILE record before its first FLOW" does not hold under a race: a second thread that finds the entry just created writes its FLOW at once, possibly before the creator's FILE is submitted | `emit_flow` L915-925 | none for the graph (it joins by `fid`, in any order); a reader that needs the order would be wrong | state it in the FILE record's doc, or check it in the reader's books |
| V6 | Every transfer reads the inode's facts and looks up the object map before it looks up the open file, although an existing open-file entry already holds the object id | `emit_flow` L912-916 | INF: on the open path the facts read measured 5.9 ns and the object lookup about 14 ns (the open-cost note §1; E-0187, E-0192); a FLOW costs 113.9 ns over the bare session (E-0237). What the reorder saves per transfer is not measured | a `flow_cost` arm that looks up the open file first; a change only if it resolves on the VM. The facts epoch per segment must still resend facts |

V2 and V3 are defects against the accepted rules. V2 changes the books and the FLOW_STATS layout, which is still unmerged, so it belongs in #90 or a PR stacked on it before the VM matrix runs.

## 2. From a FLOW record to a graph edge (SRC; built in this PR)

Before this PR, `graph.sql` did not read `raw_flow` or `raw_file`: a run captured with `--flow` built the same graph as one without. The audit's question "who wrote this file" therefore stayed unanswered whatever the capture recorded.

What the PR builds, by the rules already accepted (ADR-0005 rule 8, ADR-0028 rule 6):
- **FLOW is an edge over an interval.** `edge` gains `end_ns`, `bytes` and `n`. READ and RECV point object → process, WRITE and SEND process → object. The edge's time is the transfer's (`first_ts`, `last_ts`), not the record's.
- **FILE registers an open file** (`openfile.how = 'file'`), with the dentry's own name kept apart from a path (`name`), because a last component is not a path (ADR-0028 driver 2).
- **A FLOW names its open file by itself** when nothing else in the run does (UNREGISTERED, or a lost OPEN or FILE): no edge is dropped, and `openfile_flow` counts them.
- **Tracking follows intervals** by BackTracker's rule as written (R-046 §2.3): backward, an edge over [t0, t1] is followed when t0 is before the sink's threshold, and narrows it to min(threshold, t1); forward is the mirror. An event is the case t0 = t1, so the old answers are unchanged.
- Tested against a plain-Python reference on random graphs, half of whose edges are intervals; 27 new mutants, all killed.

What the review of that path found:

| # | Finding | Effect | Status |
|---|---|---|---|
| G1 | **A socket is two nodes.** A SEND or RECV points at the socket's file object (`o:<obj>`); the connection's node is the socket cookie (`s:<cookie>`) of its NET records. Nothing in the WAL joins the two | a backward walk from a server reaches the client's connect through `sock_pair`, but not the bytes; the demo's question "given a port, what happened" cannot follow data across a connection | counted (`flow_sock_not_joined`), not guessed. NET v3 carries the object id in step 2e. **Decision 1 below** |
| G2 | **Open-level edges still point file → process whatever the access.** With FLOW in the run, a process that only wrote a file still "depends" on it by its open, and through it on every earlier writer | false connectivity in a backward walk: BackTracker follows such "low-control" events only on request (R-046) | not changed here. **Decision 2 below** |
| G3 | PIDSMaker tells SENDTO from SENDMSG and RECVFROM from RECVMSG; FLOW has SEND and RECV, because the socket tracepoints do not know the system call | the export cannot give 10 of 10 edge types as its consumers trained on them without a stated rule | FLOW edges are not exported until the rule exists (`edges_not_exported`). **Decision 3 below** |

## 3. `fsession` on 7.0: a hook type no harness has measured (DOC, SRC)

- Linux 7.0 has `BPF_TRACE_FSESSION`: one trampoline program that runs at a function's entry and at its return, with `bpf_session_cookie()` and `bpf_session_is_return()`, as kprobe.session has (R-053, the series' cover letter).
- The VM's kernel has it: `BPF_TRACE_FSESSION = 58` and `struct bpf_fsession_link` in `bpf/vmlinux/vmlinux-7.0.0-38.h`. The vendored libbpf has `SEC("fsession+")` (`third_party/libbpf/src/libbpf.c` L9872).
- **Why it matters:** the read path's hook cost is the largest part of a FLOW. On a trivial body, kprobe.session added 141 ns per `vfs_read`, fentry 14.2 ns and fexit 21.5 ns (E-0138). An fsession takes the trampoline's path, so its cost should be near fentry plus fexit (INF: not measured).
- **Why it was not chosen, and still may not be:** the trampoline family is skipped for another task under contention (`kernel-v7.0.md` §1.2 names fsession), and STATE decisions 17 and 18 chose hooks that are not skipped. Whether a skipped entry also skips its return is OPEN.
- **What to do:** an `fsession` arm in `bench/rw_hook_cost` and in `bench/flow_cost`, with its `recursion_misses` under the contention pattern of E-0189. The number then says what never being skipped costs per read, which the project has only for the open path. No design change before that. **Decision 4 below.**

## 4. Graph algorithms, each tied to a query (INF unless graded)

The graph is a temporal graph: an edge can be followed only in time order. That decides which textbook algorithms apply as they are, and which do not.

| # | Algorithm | What it gives here | When |
|---|---|---|---|
| A1 | **Bottleneck (widest) path.** Backward tracking is: for each node, the largest over all paths of the smallest edge time on the path. The tests' reference is Dijkstra with max and min in place of min and plus, O(E log V) | the `USING KEY` query computes the same fixpoint by repeated relaxation, as Bellman-Ford does. The first form of the query measured 0.055 to 0.113 s per backtrack on the soak's graph (E-0206), so nothing needs replacing; the interval form is to be timed there. The reference stays the oracle | done |
| A2 | **One pass over edges in time order** (Wu et al., R-054, ABS): on a temporal graph, earliest-arrival times come from a single scan of the edges sorted by time, with no queue | **forward tracking is incremental.** A streaming builder (R4) receives edges nearly in time order, so "what has this alert reached so far" is one update per new edge, with no query. Backward tracking is the same scan in reverse, which is BackTracker's own log scan: it needs the stored graph. This splits the two uses: forward for a live response, backward for investigation | with R4 |
| A3 | **Pre-order and post-order numbers on the process tree** (an Euler tour; cp-algorithms, R-056) | "every process this shell started" becomes `tin BETWEEN ? AND ?` on two columns of `proc`, instead of a recursive query; ordered by `tin`, DuckDB's zonemaps skip the rest (R-051). One depth-first pass in `build.py` | graph v1 |
| A4 | **Binary lifting** for ancestors (R-056) | the nearest common ancestor of two suspicious processes, in O(log depth) per pair | only if a query needs it |
| A5 | **Strongly connected components and the condensation graph** (Tarjan; R-056) | on the graph with times dropped, a walk never leaves the components reachable from its start: an upper bound on any backtrack, computed once per graph, and the size of the largest component is a measure of dependency explosion per run. ADR-0005 rule 14's cycle collapse is the two-node case | graph v1, as a measurement first |
| A6 | **Disjoint set union** (R-056) | node identity that arrives as pairs: an overlay file and its real file, a socket's file object and its cookie (G1). Today these are relations followed as timeless edges; a union at build time makes them one node, and every query simpler. Only where the pair is exact | with NET v3 |
| A7 | **Dominators** (Lengauer and Tarjan, R-057, not read) | in the subgraph a backward walk returns, a node that dominates the point of interest is on every path from the entry to it: the place where one block would have cut the attack. That is the question the FPGA enforcement stage asks, and it complements DepImpact's ranking (R-048). It is defined on the time-respecting subgraph, not on the static one | after the export |
| A8 | **Versioned nodes are static single assignment** (compilers) | Hossain's versions (R-040) give each write of a file a new name, and a read uses the version that reaches it: reaching definitions. On versioned nodes the graph is acyclic, a topological order is the time order, and A5 and A7 apply without the time caveat | with FD (ADR-0005 rule 14) |

Not useful here: shortest paths by hop count (a shorter path that breaks time order is not a path), and static reachability indexes (2-hop labels and the like), which do not hold thresholds.

## 5. Patterns from other fields, each tied to a part of the pipeline (INF: framing, never a result)

| Field | The pattern | Where the pipeline already has it, or lacks it |
|---|---|---|
| Network drivers | NAPI: take an interrupt when idle, switch to polling under load | the drain: a wake only above a high-water mark, else an adaptive timer (ADR-0020, ADR-0030). Already there; the name helps a reader |
| Databases | Group commit: many transactions, one `fsync` | the WAL's batches and its one-second `fdatasync` (ADR-0007). Already there |
| Databases | A log-structured merge tree: an append-only log, then immutable sorted runs, merged later | a rotated WAL segment never changes. **The graph can be built a segment at a time** as each one closes, keyed by segment index and so safe to repeat, instead of an hour at once. That is R4 in its simplest form, and it removes the gate "an hour's graph in under 60 s" (G1: 80 to 108 s today, E-0204, E-0211) as a batch problem: each segment is a small batch. The star's tables that span segments (process images, open files) need an upsert by key, which is where it is harder than it sounds |
| Computer architecture | False sharing: two cores writing one cache line | the ring's consumer position, stored per record by libbpf and read by every producer (U3 in the pipelines note, decision waiting 11.2). Unmeasured still |
| Computer architecture | Write-combining buffers: gather small writes, flush a line | eAudit's per-CPU record caches (decision waiting 6) |
| Messaging (LMAX Disruptor, not read) | One writer per sequence, consumers take what is there in one batch | the SPSC queue and `ring__consume_n`. Already there |
| Epidemiology | Contact tracing follows contacts in time order: who could have infected whom | exactly forward tracking on a temporal graph (A2); the field's result that a later contact cannot carry an earlier infection is the threshold rule |
| Compilers | SSA, reaching definitions, dominators | A7 and A8 |
| Accounting, clinical trials | Books that close; every participant accounted for at each stage | the counter books (the 2026-11-05 note §5). FLOW_STATS extends them; V2 to V4 above are where the new books are not yet exact |

## 6. Where the whole pipeline stands against the acceptance criteria

Unchanged from the audit's §5 except for what this session touched:

| Criterion | Before | After this PR, once #90 is merged and run with `--flow` |
|---|---|---|
| F1, the consumers' vocabulary | 4 of 10 | READ and WRITE in the graph; SEND and RECV in the graph but not joined to their connection (G1) and not mapped to the four socket types (G3) |
| "Who wrote this file?" | no | yes, in tests on generated runs; on a real run after the VM matrix on #90 |
| Across a TCP connection by data | no | no (G1) |
| Everything else (F2 to F5, P1 to P3, R1, R2, S1, G1) | as the audit states | unchanged |

## 7. Decisions for the maintainer

1. **Join a socket's two nodes before 2e, or wait.** Options: (a) wait for NET v3 in 2e, as planned; data flow stops at every socket until then. (b) Pull NET's object id forward, into 2b: `net.bpf.c` reads the socket's inode and looks up the object map, which the two objects must then share. (c) FLOW of kind SEND or RECV carries the socket cookie (the tracepoint has the `sock`; `bpf_get_socket_cookie` is available to tracing programs), a FLOW version 2. Recommendation: (b) or (c) before the ceiling gate, chosen by a short design check, because the demo track and the soak's ground truth for sends and receives both need the join, and (c) changes a record that has not shipped. Evidence: G1; `graph_count.flow_sock_not_joined`.
2. **Open-level edges when the run has FLOW.** Options: keep following every OPEN (today); or follow an OPEN in a walk only on request, as BackTracker's low-control events, when the run's header says the flow programs were attached. Recommendation: the second, by a new ADR that supersedes ADR-0028 rule 6 in part, after a run on the soak's graph shows how much the node sets differ. Evidence: G2.
3. **The export's rule for SEND and RECV.** Options: one PIDSMaker type each (SENDTO, RECVFROM), stated in the manifest; or the system call recorded in FLOW (a kprobe on the socket calls, or `syscall_get_nr` at the tracepoint: OPEN whether that is exact inside `sendmmsg`). Recommendation: a design check of what PIDSMaker's featurization does with the four types before choosing; if it only one-hot encodes them, the first option with the shift stated. Evidence: G3; R-041.
4. **Measure `fsession`.** Recommendation: add the arm to `rw_hook_cost` and `flow_cost` (a `bench/` PR, no capture change) and run it on the VM with the contention pattern. Evidence: §3.
5. **V2 and V3 in PR #90.** Recommendation: fix both in #90 before its VM matrix, since V2 changes FLOW_STATS and the books that the matrix would otherwise record. Evidence: §1.
6. **Build the graph a segment at a time** (§5). Recommendation: a design check with R4, after 2b; it changes how gate G1 is stated.
