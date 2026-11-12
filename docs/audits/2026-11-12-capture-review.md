# Capture layer review: what is built, what is measured, why problems were found late, and what "done" means (2026-11-12)

The maintainer's request of 2026-11-12: review the architecture rigorously, measure everything, find the root cause of why the capture layer is not finished and why problems keep being found after the work is done, and decide whether it can be deployed and whether it is functionally sound, all before the PIDSMaker export. This audit answers from the code, the ADRs and the journal. Grades as in `CONTRIBUTING.md` §5; every number cites its journal row.

## 0. Verdict

- **Is it functionally sound?** For what it captures, yes, and measured on the VM. Every operation of an hour of real programs is in the WAL: 38,363 of 38,363 over 3,158 steps (E-0202). The books close, nothing was lost, and processes, files and connections are named exactly (E-0198, E-0203).
- **Is it complete? No.** It records who ran, what was opened and who connected to whom. It records **no data flow**: no read, write, send or receive. So:
  - a backward trace stops at every file it reaches (measured on the soak graph, E-0206);
  - PIDSMaker's detectors get **4 of their 10 edge types**. They need CONNECT, EXECUTE, OPEN, READ, RECVFROM, RECVMSG, SENDMSG, SENDTO, WRITE and CLONE (`pidsmaker/utils/dataset_utils.py` L33-54 at 438a05a, R-041); we give CONNECT, EXECUTE, OPEN and CLONE.
  - The PIDSMaker export would therefore be a vocabulary and distribution shift against every trained model. Step 2b is the gap.
- **Can it be deployed? Not yet,** and not only because of 2b:
  - **Cost:** what capture adds to one open+close is 1,018 to 1,061 ns of the calling program's CPU (E-0220), against a budget of 500 ns for the programs' bodies alone, which cost 741 ns (E-0213).
  - **Not measured at all:** the overhead on ordinary workloads (ADR-0018's step 6), the zero-loss ceiling, skips under contention for the network and fork programs, and the tamper window. A deployment claim needs all four.

## 1. The architecture as built (SRC unless graded)

| Stage | Code | Hook or mechanism | Can the kernel skip it under contention? | Cost measured | Loss accounting |
|---|---|---|---|---|---|
| Process lifecycle: exec, exit, rename | `bpf/progs/spine.bpf.c` | classic tracepoints (ADR-0020) | no: 0 of 2,000 in every round (E-0092) | +49.4 ns per event over `tp_btf` (E-0101) | GAP, INVALID on a skip |
| Fork | same | `tp_btf/sched_process_fork` | **yes in principle** (preemptible, E-0089); 0 seen so far | — | `recursion_misses` read every poll |
| Opens | `bpf/progs/file.bpf.c` | fentry (path) + kprobe.session (verdict, fallback) on `security_file_open` | the fentry yes, 8 to 10 % under contention (E-0189, E-0198); the session no | bodies 489.6 ns of 741.4 per open+close (E-0213) | every skipped open walked (ADR-0029) |
| Closes, inode ends | same | kprobe.multi on `security_file_free`, `security_inode_free` | no (E-0189) | 229.5 ns per close (E-0213) | FILE_STATS v2 books |
| Network intent | `bpf/progs/net.bpf.c` | **fexit** on `inet_stream_connect`, `inet_dgram_connect`, `inet_accept`, `inet_listen`, `inet_bind`, `inet6_bind` | **yes in principle** (fexit, as the path fentry); not measured under contention | not measured per call | DEGRADED on a skip (ADR-0020 rule 3) |
| Opening and closing snapshot | `bpf/progs/snap.bpf.c`, `iter/task_file` | task and task_file iterators | not applicable | 1.4 µs per task, 0.6 µs per fd (E-0213's `prog_stats` table) | SNAP_DONE books; reconciliation (ADR-0023) |
| Transport | two BPF ring buffers (ADR-0006) | woken above a high-water mark, else polled (ADR-0020, ADR-0030) | — | ring copy 37.6 ns per OPEN (E-0192) | reserve failures counted per type |
| Drain | `daemon/drain.c` | libbpf `ring__consume_n`; record check, copy into a batch | — | p15d 203.6 ns per open+close at 1 MiB batches (E-0220) | `*_invalid`, `queue.full` |
| Queue, writer, WAL | `daemon/queue.c`, `writer.c`, `wal.c` | SPSC queue, an eventfd per batch, `writev`, CRC32C (ADR-0007) | — | CRC 6.5 % of p15d (E-0218); wakes 200 µs each at 256 KiB (E-0219) | torn-tail recovery; END record |
| Reader, graph, tracking | `python/p15/wal.py`, `graph/`, `track.py` | DuckDB 2.0 (ADR-0028, ADR-0031) | — | build 80 to 108 s per hour of soak (E-0204, E-0211); tracking under 0.5 s (E-0211) | `graph_count` books, must-be-zero counts |

## 2. Coverage against what the consumers need

| Needed by | Event | Captured? | Where it is planned |
|---|---|---|---|
| PIDSMaker, BackTracker, every detector | READ, WRITE (file data flow) | **no** | step 2b (ADR-0005) |
| PIDSMaker | SENDTO, SENDMSG, RECVFROM, RECVMSG | **no** (only connect, accept, listen, bind) | step 2b (socket tracepoints) |
| PIDSMaker | OPEN, EXECUTE, CLONE, CONNECT | yes | — |
| Investigation | file rename, unlink, link, truncate | no | 2d |
| Investigation | splice, sendfile, copy_file_range, tee, vmsplice | no | 2d |
| Investigation | mmap at map time; memory made executable | no | 2d; slice C |
| Investigation | io_uring reads and writes | no (they bypass `vfs_read`, E-0027) | 2e |
| Investigation | writes into another process (ptrace, `process_vm_writev`) | no | slice D |
| Investigation | module and BPF loads, setxattr | no | slice E |
| Known blind spot | `O_PATH` opens (no `security_file_open`, fs/open.c v7.0 L900-926) | no; counted only as unregistered frees | not planned: name it in ADR-0015's consequences |
| Known blind spot | 32-bit `socketcall` connect and accept (P7) | not tested | before phase 3 |

**The order was the wrong way round for the goal.** The last two weeks went into making opens exact and cheaper (gates 1 to 4), while the event type that matters most to both consumers, the data transfer, is not built. Gates 1 to 4 were needed. But no measurement of the open path changes the fact that, without 2b, the graph cannot answer "who wrote this file".

## 3. What is measured, and what is not

**Measured on the VM** (MEAS):
- every open named, under contention too (E-0198);
- the one-hour soak: 100 % of operations recorded, memory plateaus at 27.6 MiB, the WAL grows 184 MiB per hour, p15d uses 4.3 ms of CPU per second at about 530 records per second (E-0202, E-0203);
- idle 1.0 to 1.8 ms per second (E-0200, E-0213);
- the programs' bodies per open+close (E-0213, E-0215);
- what capture adds end to end per open+close (E-0213, E-0220);
- p15d per open+close and its profile (E-0215, E-0218 to E-0220);
- hook-type costs on a trivial body (E-0138);
- graph build and tracking (E-0204, E-0211).

**Not measured, and each one needed for a deployment claim:**
1. **Overhead on ordinary workloads.** ADR-0018's step 6: a kernel build, a postmark-like file load, a web server, a database, each against an untraced baseline with the paired protocol. Only microbenchmarks exist.
2. **The zero-loss ceiling.** The event rate at which records start to be lost (N3, the gate of 2b), and how it compares with the soak's 530 records per second.
3. **Skips under contention for the network fexit programs and the fork `tp_btf` program.** Decision waiting 2: the same mechanism skipped 8 to 10 % of path fentries (E-0189).
4. **The tamper window.** How many events are not yet durable when an attacker kills p15d (eAudit's measure, R-042; decision waiting 5).
5. **Adversarial load.** Mao et al.'s many-thread `find` and IPC storms (R-004), against which Sysdig loses 39 to 98 %.
6. **Long runs.** 24 hours, rotation across many segments, restart and recovery of a torn tail on the VM.
7. **p15d's new figures under the soak**, with 1 MiB batches (E-0220 was a microbenchmark).

## 4. Why problems were found after the work was done: root causes

| What was found late | Cost of finding it late | Why it was late | Root cause |
|---|---|---|---|
| p15d's CRC went one byte per step: a third of p15d's CPU (E-0215) | 244 ns per open+close for weeks | `crc32c.c` deferred the fast version "for a measurement that asks for it", and no harness ever profiled p15d | **R1. Components were measured, the pipeline was not profiled.** There was no profile of p15d until 2026-11-12 |
| A wake per 256 KiB batch: about 200 µs each on this VM (E-0219, E-0220) | 210 ns per open+close | `--batch-kb 256` was chosen when the writer was built and never swept | **R2. Defaults were never swept by a harness** |
| C1 was estimated to save about 250 ns; it saved nothing (E-0215) | a wrong recommendation, withdrawn the same day | the estimate counted the profiled body as removable | **R3. Inferences were offered as plans before a harness** |
| The user-space pipelines of the tools were never read (E-0221) | the two costs above were what eAudit's paper (in the project since 2026-11) and Falco's code would have shown | the research briefs asked about hooks, records and identity, not about ring readers, wake-ups and writers | **R4. Research covered the kernel side only** |
| "A third thread switching" (E-0215) was really the writer's wake (E-0219) | one recommendation withdrawn | the profile was read without call graphs, on a VM whose timer sampling credits time with interrupts off to where they come back on | **R5. Profiles were read without call graphs** |
| Data flow (2b) not built two weeks after its design was accepted (E-0140) | the graph cannot answer the investigation question; the export would be a vocabulary shift | gates 1 to 4 were all on the open path; cost work came before function | **R6. Function was scheduled after cost** |
| The graph's process names came from any thread's rename (E-0206) | wrong labels in the graph | found by chance in a timing run | **R7. No test checked labels against ground truth** (the soak checks events, not names) |

The common thread: **we built first and measured the whole thing later.** The fixes are process changes, and they come before more code:
1. **A standing measurement matrix** (§6, Phase A), run on the VM for every capture PR, before merging. It covers:
   - functional books: `it_p15d`, the soak's ground truth, names included;
   - the programs' bodies (`prog_stats`);
   - end to end (`open_cost`);
   - p15d's CPU, switches and profile with call graphs;
   - idle;
   - the graph's build and tracking time.
2. **Every default gets a sweep before it is accepted,** with the swept values in the ADR.
3. **An estimate is graded INF and never decides anything.** The harness is written first, as CLAUDE.md already says for numbers.
4. **Research briefs cover all four sides of a component:** the kernel side, the user side, storage and tests.
5. **Function before cost:** a gate's budget is checked once the function exists, not before.

## 5. What "done" means: the capture layer's acceptance criteria

Each criterion has a threshold and a harness. The thresholds marked "proposed" are the maintainer's to set.

| # | Criterion | Threshold | Harness |
|---|---|---|---|
| F1 | Coverage of the consumers' vocabulary | all 10 PIDSMaker edge types from real events, plus our own (ACCEPT, CLOSE, BACKING) | soak ground truth per type |
| F2 | Recall against ground truth | 100 % of logged operations per type over an hour of real programs, names included | `bench/soak` (extend to reads, writes, sends, receives, renames) |
| F3 | Precision | 0 edges the ground truth does not hold, in a controlled run | soak in a quiet window, plus planted-bug sweeps |
| F4 | Skips under contention | counted for every program; a skip of data flow makes the run DEGRADED, a spine skip INVALID; network and fork measured | a contention harness per hook family (as E-0189 for opens) |
| F5 | Zero-loss ceiling | proposed: at least 10 times the soak's record rate, with every loss beyond it counted | a ceiling harness: a rising producer until loss, as Falco's doubling ramp |
| P1 | Overhead on ordinary workloads | proposed: under 5 % CPU on a kernel build, a file server load and a web server load, 95 % interval stated | ADR-0018 step 6 |
| P2 | Per-operation cost | proposed: bodies under 500 ns per open+close; per read or write under a figure set after 2b's design check | `prog_stats`, `open_cost`, a read/write analogue |
| P3 | p15d | idle under 2 ms per second (met: 1.0 to 1.8, E-0213); per record proposed under 100 ns | `open_cost`, `idle_cost` |
| R1 | Long runs | 24 hours: memory flat, the WAL rotates, books close | soak at 24 h |
| R2 | Crash and restart | a killed p15d: the WAL's torn tail recovered, the gap visible in the next run | a kill harness on the VM |
| S1 | Tamper window | measured and stated (eAudit's definition); proposed under 1 s | a kill-at-a-signal harness |
| G1 | Graph | an hour's graph in under 60 s (decision 34); backtracking equal to the reference (met, #80); the export loads into PIDSMaker's own ingest code unchanged | soak graph timing; a PIDSMaker ingest test |

## 6. The plan to finish, in order

**Phase A: measure everything, now** (no capture design change):
1. `tools/vm/measure_capture.sh`: one command on the VM that runs the standing matrix against the built tree. It writes every raw output and a one-page summary into an evidence directory, with the commit and the binaries' hashes. It is in the PR with this audit.
2. U1 (1 MiB batches by default), by a STATE decision, measured under the soak by the matrix.
3. The two missing contention measurements (F4): network fexit and fork `tp_btf`, with the E-0189 harness's method.

**Phase B: data flow, step 2b** (ADR-0005 rules 1 to 3, FLOW per call, unfolded):
1. Design check, measured first:
   - the read and write rates of real workloads (E-0221 gave 317 per second for the soak's workload; add the kernel build and the server loads);
   - the cost per call of the candidate hooks on `vfs_read`/`vfs_write`: E-0138 gives kprobe.session 141 ns and fexit 21.5 ns on a trivial body, and the fexit can be skipped;
   - the socket tracepoints' cost.
   The choice between one kprobe.session (never skipped, 141 ns) and fexit with a counted fallback is made on those numbers, by a new ADR if it departs from ADR-0015 decision 1a.
2. Records, BPF, decoder, books (FLOW_STATS), an `it_p15d` case, and the soak's ground truth extended to reads, writes, sends and receives.
3. The ceiling gate (F5).

**Phase C: folding, step 2c** (Xu's causality-preserving reduction, CCS'16, R-039, ADR-0005 rules 4 to 12). The test is the algorithm's own claim: every backward and forward trace over the folded records equals the trace over the raw ones. `track.py` (#80) is the oracle, on the soak's raw and folded runs.

**Phase D: the rest of the vocabulary.** 2d (splice and its family, mmap, rename, unlink, link, truncate), 2e (io_uring, NET v3), then slices C, D and E, each with its ground truth in the soak.

**Phase E: deployment evidence:** P1, R1, R2, S1, and adversarial load (Mao's producers).

**Phase F: graph v1 and the export.**
- R3: read the WAL in bulk by numpy layouts, since reading the WAL is 37 to 68 s of an hour's build.
- R4: a streaming builder, bounded and counted.
- FLOW edges into `track.py`.
- The PIDSMaker export with its fusion rule reproduced exactly (`build_default_graphs.py` L392-452), validated by PIDSMaker's own loader.

What is not in the plan: any new optimization of the open path before Phase B. C1b and C2 (the open-cost note) wait for the matrix to show the open path is the bottleneck of a real workload, not of a microbenchmark.
