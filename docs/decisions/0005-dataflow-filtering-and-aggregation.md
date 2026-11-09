---
status: proposed
date: 2026-11-09
owner: Ashish Rana
consulted: [Xu et al. CCS'16 (read in the PDF, design-checks §1), research note 2026-11-06-dataflow-slice-b (provenance-and-pids.md §1, §4-5; tools.md §2, §4, §7; kernel-v7.0.md §1-2, §6-7), research note 2026-11-09-slice-b-design-checks.md, ADR-0006 rules 2 and 6, ADR-0007, ADR-0015, ADR-0017, ADR-0020, ADR-0026, maintainer's slice B plan (STATE decisions 15.5 and 17)]
supersedes: none (fills the reserved number 0005; the planned list's working title "who/what-kind only, no in-kernel dedup in v1" is replaced by the maintainer's slice B plan, which puts Xu's reduction in the kernel)
---

# 0005: Data flow in the kernel: what is filtered, what is aggregated, and by which rule

## Context and problem statement

The read, write, send and receive hooks of slice B fire on every transfer: far more often than the spine's fork, exec and exit. One record per transfer would fill the bulk ring and the WAL under ordinary workloads (v3.7 lost records at about 9,400 per second, ADR-0006 evidence 5), and most of those records add nothing to a trace: a process reading a file in 4 KiB chunks produces hundreds of edges that say the same thing.

The usual remedies break causality. A first-touch flag (Kunai) hides every read after the first, including the one that saw an attacker's write. A time window or a rate limit (Tetragon, Falco) drops events or merges across a dependency: In Xu et al.'s evaluation a naive 10-second window gave false connectivity in 2,778 of 20,000 random backtrackings (13.9 %), against none for their causality-preserving reduction (design-checks X9). The capture records facts; it may only reduce in ways that leave every backward and forward trace unchanged, and it must count each reduction.

**Question:** which data-flow events does the kernel filter out, which does it fold into aggregates, under what rule, when is an aggregate written, and how is all of it counted?

## Decision drivers

1. **No false connectivity:** fold only where Xu's checks allow it, so that every backward and forward trace over the folded records equals the trace over the raw events.
2. **No silent loss:** every event that reaches a hook is either written as its own record, counted into exactly one written aggregate, or counted as excluded by a stated rule; every bound has a counter (CLAUDE.md, ADR-0006 rule 6).
3. **No policy in the kernel:** filtering is by *who* (capture itself, kernel threads), never by what a rule thinks is interesting.
4. **Hooks that are not skipped for other tasks** (STATE decision 17), and kernel state that is bounded, with every bound counted.
5. **What the consumers need:** the first time of each run (PIDSMaker keeps the first edge of each run, provenance-and-pids.md §4), the last time, the count and the bytes.
6. **A crash loses at most the durability window** of ADR-0007 (one second).

## Considered options

1. **No aggregation:** one record per transfer (Elastic, Tracee).
2. **First touch** per (task, inode) (Kunai).
3. **Rate limits or time windows** (Tetragon `rateLimit`, Falco's dropping mode).
4. **Causality-preserving reduction (Xu's CPR) in the kernel, per (process, open file, type),** with the two checks taken over one conservative window (chosen).
5. **Stronger reductions** (Hossain's FD and SD, NodeMerge, LogGC, dropping temporary files).
6. **Discarders** (Datadog): a kernel cache of objects no rule can match.

## Decision outcome

**Option 4,** because it is the only one that reduces volume while keeping every trace exact (driver 1), and its checks need only per-object and per-process state that the kernel can hold in bounded maps (driver 4). The stronger reductions (option 5) need global or offline state, and LogGC and the temporary-file rules delete exactly the trace a memfd payload leaves (provenance-and-pids.md §5): they may run downstream, on copies, never in capture.

### Rules

1. **Filtering, by who only.**
   - p15d's own process is excluded (its WAL writes would record themselves), counted `excluded_self` per type.
   - Kernel threads and I/O with no user process (`PF_KTHREAD`) are excluded, counted `excluded_kthread`. The kernel's own internal reads and writes (`kernel_read`, `__kernel_read`, `__kernel_write`, `vfs_iter_*` called by the kernel, core dumps) are out of scope (rule 11).
   - Nothing is filtered by kind or by path: regular files, directories, pipes, sockets, terminals, devices and anonymous files are all recorded. Kunai and Elastic drop non-regular files (tools.md §3); fileless chains run through pipes and sockets (research note 2026-11-06 §1a).
   - A transfer that moved no data is counted, not recorded: `failed` (a negative return) and `empty` (0 bytes), per type. It creates no causal edge.
2. **Which events fold.** Only the transfers: READ and WRITE (`vfs_read`, `vfs_write`, `vfs_readv`, `vfs_writev`, and io_uring read and write completions), RECV and SEND (`sock:sock_recv_length`, `sock:sock_send_length`). A RECV with `MSG_PEEK` is a RECV with flag `PEEK`; flags are part of the key, so peeks and reads never fold together.
3. **Never folded, each its own record:** OPEN (FILE), PATH, CLOSE, OBJ, FD, BACKING (ADR-0015); MMAP at map time, every protection; MPROTECT (slice C); EXEC, FORK, EXIT, RENAME of the spine; file RENAME, LINK, UNLINK and TRUNCATE; SPLICE, TEE, VMSPLICE, SENDFILE and COPY_FILE_RANGE; the NET records. Each of these is a distinct causal step, or carries arguments the aggregate cannot.
4. **The key.** An aggregate belongs to one (process, open file, type, flags): the process by ADR-0009's key, the open file by its `fid` (ADR-0015 rule 1), as Xu's definition requires the same source, destination, type and open descriptor (X1).
   - An open file holds **at most one pending aggregate**. An event on that open file with another key (another process or thread, another type or flags) closes it first. Xu would let some of those stay open side by side; giving that up costs reduction, never exactness.
   - The aggregate is owned by the thread of its first event (rule 10).
5. **The fold rule (Xu's checks).** Let e1 be the aggregate's first event and e2 a new event with the same key.
   - **Input to P** (READ, RECV: object O → process P) folds only if, in the window, O had **no incoming flow** (nothing written or sent into O, by anyone, through any open file) and P had **no outgoing event**. That is Xu's backward check on the source O and forward check on the destination P (X2, X3).
   - **Output of P** (WRITE, SEND: P → O) folds only if, in the window, P had **no incoming flow** and O had **no outgoing flow** (nobody read, received, mapped or executed O).
   - **The window** is [start of e1, end of e2]. It contains both of Xu's windows ([te(e1), te(e2)] and [ts(e1), ts(e2)]), so an event that blocks either check blocks this one: the rule never folds where Xu's would not.
   - What counts as an incoming or outgoing flow of a process or an object is the table of rule 6, for every record type, whichever program writes it.
   - Every incoming flow of O and every outgoing flow of P counts, including a flow between P and O themselves in the other direction (a write of P into O blocks P's read aggregate on O). That is what Xu's Algorithms 2 and 3 test; the paper's Def. 2 leaves those reverse-direction events out (X10). Following the algorithms gives up the reduction of a process alternating reads and writes on one file, never exactness.
   - Algorithm 1 takes its input sorted by start time (X11). Per key that holds here: an aggregate has one owner thread (rule 4), and one thread's events on one open file begin and end in order. The kernel sees events when they end, not sorted; the in-progress marks below are what let the check run online.
   - The order of events across CPUs comes from one atomic counter, not from timestamps, so a mark set on another CPU is never seen as earlier than it was.
   - **In-progress events block too:** a hook with entry and return runs marks its objects at the entry and again at the return, and an event still in progress blocks a fold (Xu tests window overlap, X2-X3). Hooks with one run only (the socket tracepoints, io_uring completion) are taken as instants at the moment they fire; an interleaving socket or io_uring event that began before the window but fires after it is therefore not seen as overlapping. That is the one place this rule is looser than Xu's, stated here, limited to those two hook kinds, and seen at the next fold of the same key.
   - A mark that is missing (its map is full, or the entry was recreated) counts as changed: the aggregate closes, counted `mark_lost`.
6. **What moves the marks.** Every recorded event of P on an object O moves the marks marked "yes" in its row:

   | Event | P incoming | P outgoing | O incoming | O outgoing |
   |---|---|---|---|---|
   | READ, RECV | yes | | | yes |
   | WRITE, SEND | | yes | yes | |
   | SPLICE, SENDFILE, COPY_FILE_RANGE, TEE (from object I to object O) | yes | yes | O | I |
   | VMSPLICE, user memory into a pipe | | yes | the pipe | |
   | VMSPLICE, a pipe into user memory | yes | | | the pipe |
   | MMAP readable | yes | | | yes |
   | MMAP shared and writable | yes | yes | yes | yes |
   | OPEN (FILE) | yes | with `O_CREAT` or `O_TRUNC` | with `O_CREAT` or `O_TRUNC` | yes |
   | EXEC of O | yes | yes | | yes |
   | FORK (in the parent) | | yes | | |
   | EXIT, RENAME of comm | yes | yes | | |
   | file RENAME, LINK, UNLINK, TRUNCATE of O | | yes | yes | |
   | NET (connect, accept, bind, listen) on socket O | yes | yes | yes | yes |
   | any other record of P | yes | yes | | |

   CLOSE moves no mark: it ends the open file's aggregate (rule 7) but carries no data. The table is code-reviewed as a table (one constant per row in the BPF source), and the mutation sweep removes each row.
7. **When an aggregate closes, and why.** Each close is counted by reason, per type:
   - `obj_flow`, `proc_flow`: the check of rule 5 failed (found at the next event on the open file, or by the sweep);
   - `other_key`: another process, thread, type or flags on the same open file (rule 4);
   - `close`: the open file is freed (ADR-0015 rule 8); the aggregate is written before CLOSE;
   - `exec`, `exit`: these move both of P's marks (rule 6), so they close P's aggregates through rule 5. The aggregate's `last_ts` is before them even when it is written later;
   - `sweep`, `segment`, `end`: rule 9;
   - `race`, `map_full`, `mark_lost`: rules 5, 8 and 10.

   The record says which reason closed it.
8. **The FLOW record and the books.**
   - FLOW carries: type and flags, `fid`, `obj`, the thread of the first event, `count`, `bytes`, `first_ts` (start of the first event), `last_ts` (end of the last), and the closing reason. Its header time is when it was written, so records stay in ring order and the reader sorts by `first_ts`.
   - An event that cannot be folded (no open-file entry because its map is full, a lost race) is written as a FLOW of count 1 with the identity facts inline (ADR-0015 rule 9), counted by reason. No event is dropped because of a bound.
   - **Books, per type**, at quiescence (after the final sweep):
     - events seen = excluded + failed + empty + folded + started + written alone;
     - FLOW records emitted + FLOW records lost = started + written alone, where "lost" is a failed ring reservation, counted with the `count` it carried (`events_lost`);
     - the sum of `count` over the FLOW records emitted + `events_lost` = started + folded + written alone.

     The WAL side is ADR-0006 rule 6 as for every record. p15d writes these counters in a FLOW_STATS record like NET_STATS (ADR-0020 rule 3), from a counter map of its own built by ADR-0026's rules, and the reader checks the third equation against the records.
   - **Run state:** any loss of data-flow records (a bulk-ring reserve failure, a kernel skip of a slice B program, an io_uring CQ overflow or skipped completion) makes the run DEGRADED, as for NET. Effects that only reduce folding (`race`, `map_full`, `mark_lost`) do not change the run state; they are reported.
9. **The sweep writes every aggregate within one second.**
   - p15d runs a BPF iterator over the open-file map every second (ADR-0007's durability window), at every segment rotation, and once at stop. It closes and writes every pending aggregate (reasons `sweep`, `segment`, `end`). The next event on that open file starts a new one.
   - So an aggregate reaches the ring within one second of its last event, and a crash loses no more than ADR-0007 already allows. p15d rotates a segment only after the drain has taken the rotation sweep's records, so a segment's FLOW records end before its rotation, and the next segment's FD pass (ADR-0015 rule 7) describes the files still open.
   - A non-sleepable iterator takes no `bpf_prog_active` and walks the hash map under RCU only (K13), so the sweep cannot make the kernel skip a kprobe for another task, and it is not a map syscall in ADR-0026's sense. Deleting the current element from inside the iterator is OPEN (design-checks O4); the sweep needs it only if the closed slot must be removed rather than reset, which step 2 decides.
   - Its cost grows with the number of open files; it is measured in slice B's tests, and the interval is a parameter recorded in the WAL header.
10. **Concurrency without locks.** kprobe programs cannot take `bpf_spin_lock` on 7.0 (K12). An aggregate lives in its open file's map entry with an atomic state word:
    - only the owner thread folds into it, from a non-preemptible program, after moving the state from idle to busy with a compare-and-exchange;
    - any other actor (another thread, the sweep, the free) takes the whole aggregate by moving the state from idle to taken and writes it; another thread then starts its own aggregate in the slot, and the sweep leaves it empty;
    - an actor that finds the state busy or taken does not wait and does not fold: it writes its event as its own record, counted `race`. Nothing is lost on a race, and no program spins.
    The free cannot race with a fold: no I/O runs on a `struct file` whose last reference is gone.
11. **Each transfer is counted at exactly one hook, and some transfers are out of scope.**

    | Transfer | Counted at | Not counted at, and why |
    |---|---|---|
    | read/write family on files, pipes, terminals, devices | `vfs_read`, `vfs_write`, `vfs_readv`, `vfs_writev` (kprobe.session) | — |
    | the same calls on a socket | `sock_send_length` / `sock_recv_length` | the VFS hooks, counted `owned_by_sock` (K15) |
    | io_uring read/write on a non-socket file | `io_uring_complete`, attributed to the submitting task (`req->tctx->task`), not `current` | — |
    | io_uring on a socket | the socket tracepoints | `io_uring_complete`, counted `owned_by_sock` |
    | splice, sendfile, copy_file_range, tee, vmsplice | their own records (rule 3) | a socket tracepoint fired inside one of them, counted `inside_splice` |
    | overlay I/O | the user's overlay file | the backing file's `vfs_iter_*` call (ADR-0015 rule 4) |
    | **out of scope:** loads and stores through a mapping; the kernel's internal reads and writes; anonymous shared memory between processes; another process's memory (slice D) | — | no per-access hook exists (kernel-v7.0.md §6); the MMAP record is the edge |

    Other io_uring operations reach the same kernel functions as their system calls (an open reaches `security_file_open`, a splice `do_splice`) and are recorded there (INF from the call paths; the step 2 self-test runs one io_uring read and one io_uring open to confirm). io_uring completions that never fire their tracepoint are counted instead: CQ overflows at `io_uring_cqe_overflow` (K18) and `IOSQE_CQE_SKIP_SUCCESS` submissions at `io_uring_submit_req`.
12. **Folding next to memory mappings is made conservative.** A mapping moves data at loads and stores that capture cannot see (rule 11), so where one exists the fold rule assumes a flow at every moment:
    - an object with a shared, writable mapping has an incoming flow for as long as its object entry lives: READs of it never fold (`nofold_mapped`);
    - a process with a shared, writable file mapping has an outgoing flow until it execs or exits: its READ and RECV never fold;
    - an object with any readable mapping passes each new incoming flow on to every process that maps it, and the kernel side cannot name them; so an incoming flow into such an object closes every pending output aggregate system-wide, through one global mark, counted. It is rare (writing a file that someone else has mapped).

### Consequences

- Good: volume falls where it can without changing any trace; every event is accounted for; the consumers get first and last times, counts and bytes.
- Good: the books extend ADR-0006's invariant to data flow, and the reader can check them against the records.
- Bad: pipelines and request-response sockets alternate direction and fold little; CPR cannot do better there (a pipe write followed by its read is a real dependency). The reduction is whatever the workloads allow, measured in step 6, not promised here.
- Bad: several map lookups and atomic updates per transfer, and one sweep a second; their cost is measured in slice B's tests.
- Bad: rule 12 gives up folding around mappings, and rule 5's instants for socket and io_uring events are slightly looser than Xu's overlap test.
- Bad: the reduction the paper measured (56 % on average, 2.63x capacity on its Linux hosts) came from enterprise hosts with long-lived file handles; the census's file workloads open a file, read or write it about once and close it (`docs/evidence/census/2026-10-24T224617Z-v2/`, file-churn and super-producer), where folding per open file gives little (INF from those counts).

### Confirmation

Built in step 2:
1. **A reference implementation** of Xu's Algorithms 1-3, written from the paper (`python/p15/cpr.py`), with a property test on generated event streams: every backward and forward trace from every event is the same before and after reduction.
2. **Exact expectations on fixed workloads** (an `it_p15d.sh` case, harmless calls only): N reads of `/dev/zero` give one READ of count N; the same with one write to `/dev/null` in the middle gives two READs split at it (`proc_flow`) and one WRITE; a pipe written and read alternately k times gives k WRITEs and k READs; two threads reading one descriptor close each other's aggregates (`other_key`); the books of rule 8 close in every case.
3. **Kernel against reference:** a load-time switch turns folding off (recorded in the WAL header); for each single-threaded workload of (2), the folded capture equals `cpr.py` applied to the unfolded capture, as multisets of (type, process, open file, count, bytes).
4. A mutation sweep: remove each check, each row of rule 6, the in-progress marks, the race path, the global mark of rule 12, and the sweep.

### Falsifier

Reopen if:
- any trace over the folded records of a fixed workload differs from the trace over the unfolded capture of the same workload;
- the kernel folds an event that `cpr.py` would not, or the books of rule 8 do not close;
- slice B's measurement shows the sweep or the per-transfer state costing more than the maintainer accepts, or the measured reduction on the step 6 workloads being too small to keep the bulk ring from losing records.

## Decisions raised

1. **Decided 2026-11-09 (maintainer): rule 5 confirmed against the PDF (E-0132).** *The paper's checks as the rule.* The session read the PDF the maintainer supplied (design-checks §1, R-039 verified): X1-X8 hold, X9 is corrected, and X10-X11 add the two points rule 5 now states (reverse-direction events block; per-key order comes from the single owner). Recommendation: the maintainer confirms rule 5 against p. 4-6 of the PDF (Def. 2, Algorithms 1-3, §3.2.1-3.2.3), then accepts.
2. **Decided 2026-11-09 (maintainer): one second, closing (E-0132).** *Sweep interval one second, closing aggregates* (rule 9). Alternative: a longer interval (more reduction, a longer crash window than ADR-0007's), or a sweep that writes progress without closing (no gain in exactness, more state). Recommendation: one second, closing.
3. **Mappings** (rule 12), including the system-wide mark. Recommendation: accept; measure how often it fires in step 6.
4. **Run state** (rule 8): data-flow loss makes the run DEGRADED; reduced folding does not. Recommendation: accept.
5. **No file offsets in FLOW.** CDM has `location`, but nothing we consume reads it (provenance-and-pids.md §3-4), and it costs 16 bytes per record. Recommendation: leave them out; add them in a FLOW version if a consumer appears.
6. **Failed and empty transfers counted, not recorded** (rule 1). Recommendation: accept.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | Aggregability: same type, source, destination, attributes, and open descriptor for file I/O | PDF | Xu et al. §3.1.3, Def. 4, p. 5; design-checks X1 |
| 2 | Backward check over [te(e1), te(e2)] on the source's incoming events; forward check over [ts(e1), ts(e2)] on the destination's outgoing events; both by window overlap; the algorithms do not exempt reverse-direction events, Def. 2 does; input sorted by start time | PDF | Alg. 1-3, p. 5; Def. 2, p. 4-5; §3.2.1-3.2.2, p. 6; design-checks X2, X3, X10, X11 |
| 3 | Merged window [ts(e1), te(e2)]; attributes unspecified; no bounds (user-space prototype at about 4,000 events/s, under 2 GB) | PDF | Alg. 1, p. 5; §3.2.3, p. 6; §4.4, p. 11; design-checks X4, X5, X7 |
| 4 | CPR: 56 % average reduction, 0 false positives over 20,000 random backtrackings; naive 10 s window: 2,778 false positives (13.9 %) | PDF | §4.2, p. 8; Table 3, p. 10; design-checks X9 |
| 5 | Stronger reductions need global or offline state; LogGC and temporary-file rules remove memfd-like payload traces; the SoK measures detection loss growing with reduction | PDF (summaries) | provenance-and-pids.md §1, §5 |
| 6 | PIDSMaker keeps the first edge of each same-type run per pair and window, and never reads sizes | SRC | provenance-and-pids.md §4 |
| 7 | Kunai suppresses repeats with an uncounted re-arm; Tetragon's rate limit suppresses uncounted; Falco samples with in-band markers | SRC | tools.md §2, §4 |
| 8 | kprobe.multi and classic tracepoints run with preemption off and are not skipped through program nesting | SRC | kernel-v7.0.md §1.2 |
| 9 | No `bpf_spin_lock` in kprobe or tracepoint programs | SRC | design-checks K12 |
| 10 | A non-sleepable iterator takes no `bpf_prog_active`; the hash iterator uses RCU only | SRC | design-checks K13 |
| 11 | read/write on a socket reach both the VFS hooks and the socket tracepoints | SRC | design-checks K15 |
| 12 | Overlay I/O reaches the backing file only through `vfs_iter_*` | SRC | design-checks K5 |
| 13 | `vmsplice` and `tee` bypass the VFS read/write functions | SRC | design-checks K17 |
| 14 | io_uring CQE skip and CQ overflow fire no completion tracepoint; overflow has its own | SRC | kernel-v7.0.md §2; design-checks K18 |
| 15 | No per-access hook for mapped I/O | INF | kernel-v7.0.md §6 |
| 16 | The VFS and `security_file_open` hooks exist in BTF and ftrace on 7.0.0-38 | MEAS | `docs/evidence/phase0/02-p1-attach-points.txt` |
| 17 | Reduction achieved on our workloads | OPEN | step 6 |

## Pros and cons of the options

### 1. No aggregation
- Good: simplest; exact.
- Bad: volume grows with every transfer; the ring loses records under ordinary load, and loss is worse for traces than any reduction (driver 2).

### 2. First touch
- Good: very small output.
- Bad: hides the reads that matter (after a write); the re-arm is uncounted in Kunai.

### 3. Rate limits, time windows
- Good: bounded rate.
- Bad: drops or merges across dependencies (a 10 s window gave false connectivity in 13.9 % of Xu et al.'s random backtrackings).

### 4. CPR per (process, open file, type), conservative window (chosen)
- Good: exact traces; bounded per-object and per-process state; every fold counted.
- Bad: little reduction on alternating flows; per-transfer map work; rules 5 and 12 are conservative where the kernel cannot see.

### 5. FD, SD, NodeMerge, LogGC, temporary files
- Good: much larger reductions (7-19x for FD/SD).
- Bad: global or offline state; some delete fileless evidence. Downstream only.

### 6. Discarders
- Good: the safe in-kernel negative cache when there is a policy.
- Bad: needs rules evaluated in userspace; capture has no policy.
