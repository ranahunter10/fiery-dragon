# A more robust capture layer, and how we get from here to a detection result (2026-11-13)

**For:** the maintainer's request of 2026-11-13: research the state-of-the-art tools and provenance systems, think through a more robust architecture for the next steps, and say how we pull it off.

**Builds on, does not repeat:**
- [`2026-11-05-sota-and-cross-domain.md`](2026-11-05-sota-and-cross-domain.md) (loss handling in the tools, tamper-evident logs in principle);
- [`2026-11-06-fileless-and-dataflow-capture.md`](2026-11-06-fileless-and-dataflow-capture.md) (the io_uring blind spot, ARMO's Curing);
- [`2026-11-12-full-capture-graph-duckdb.md`](2026-11-12-full-capture-graph-duckdb.md) (DuckDB, BackTracker in one query);
- [`2026-11-12-userspace-pipelines.md`](2026-11-12-userspace-pipelines.md) (how the tools read, batch and write);
- the register, [`papers.csv`](papers.csv), rows R-001 to R-052.

**Grades:** every claim is SRC (our code or Linux v7.0, file:line), DOC, PDF, MEAS, INF or OPEN. Sources new to the register (R-053 to R-059) were read at abstract or summary depth only and are marked unverified there. They can motivate a question, not decide one.

---

## 1. What the research found

### F1. One kernel checkpoint sees every read and write path (SRC)

The flow programs hook `vfs_read`, `vfs_write`, `vfs_readv` and `vfs_writev` (PR #90). Several data paths never call those functions. But each of them, the vfs functions included, first calls `rw_verify_area()`, which calls `security_file_permission()` (`fs/read_write.c:475`):

| Path | Reaches `vfs_read`/`vfs_write`? | Calls `rw_verify_area` | Gives the bytes moved |
|---|---|---|---|
| read, write, pread, pwrite | yes | `vfs_read` `fs/read_write.c:565`, `vfs_write` `:679` | our vfs return |
| readv, writev | yes (`vfs_readv`/`vfs_writev`) | `fs/read_write.c:1015`, `:1053` | our vfs return |
| io_uring READ, WRITE | **no**: `f_op->read_iter`/`write_iter` directly (`io_uring/rw.c:835`, `:1174`) | `io_uring/rw.c:947`, `:1165` | `io_uring_complete`'s `res` (`io_uring/io_uring.h:314`) |
| splice | no | `fs/splice.c:1004`, `:1341`, `:1367` | the splice's return (not hooked) |
| sendfile | no | `fs/read_write.c:1329`, `:1369` | the syscall's return (not hooked) |
| copy_file_range | no | `fs/read_write.c:1570`, `:1574` | the syscall's return (not hooked) |
| kernel_read, kernel_write (exec, module load, core dumps) | no | `fs/read_write.c:547`, `:657` | their return |
| vfs_iter_read/write, vfs_iocb_iter_read/write (overlayfs's real file under an overlay file, nfsd, loop) | no | `fs/read_write.c:886`, `:914`, `:946`, `:978` | their return; the overlay file's own read is captured |
| mmap'd writes | no: checked once, at `security_mmap_file` (`mm/util.c:575`, `mm/mmap.c:1142`) | no | none per write |
| sockets, io_uring's included | the vfs hook defers to the socket (owned_by_sock) | not needed | `sock_send_length`/`sock_recv_length`: io_uring's send and receive reach `sock_sendmsg`, `sock_recvmsg` and `__sys_sendmsg_sock` (`io_uring/net.c:570`, `:682`, `:977`, `:1495`) |

So `security_file_permission` is a point of complete mediation for every file transfer except mapped memory. It sees the requested count, not the bytes moved; the bytes come from the hooks in the right-hand column. The register's Houssel et al. (R-003, R-027) reach the same conclusion in general, LSM points over syscalls, and leave completeness of LSM coverage open. This table is that check for transfers on 7.0.

### F2. io_uring's workers are attributed to the right process (SRC)

io_uring runs blocking requests on worker threads made by `create_io_thread()` with `CLONE_THREAD` (`kernel/fork.c:2591`). They get `PF_IO_WORKER | PF_USER_WORKER`, never `PF_KTHREAD` (`kernel/fork.c:2052` to `:2065`). Our kernel-thread exclusion (`kthread()`, `bpf/progs/file.bpf.c:182`, tests `PF_KTHREAD`) therefore keeps them, and their tgid is the submitting process's. When io_uring is captured, its transfers land on the right node.

### F3. The tamper window is a known attack, with three known defences (PDF, abstracts)

- **The attack:** Paccagnella et al. (CCS 2020, R-056) race an audit framework between an event and its log commit: an attacker who gains root inside that window can edit the log before it is protected.
- **Defence 1, a device:** HARDLOG (IEEE S&P 2022, R-055) sends log entries to a separate audit device within a tiny, bounded delay. It holds a security-critical event until its log entry is on the device.
- **Defence 2, in the kernel:** Nitro (CCS 2025, R-011, already in the register) seals logs forward-securely inside eBPF, so a sealed entry can't be rewritten undetected.
- **p15d today:** CRC32C per batch (corruption, not tampering) and a 1 s `fdatasync` (ADR-0007 rule 6). Its window runs from the kernel record to the WAL's sync. It is unmeasured; STATE's decision waiting 5 asks for it.

ESE-P15 already plans an FPGA layer (the project's P2 charter). An FPGA audit device in HARDLOG's style is a natural place for that layer to meet capture (INF: an idea, not a design).

### F4. Detection needs node-level attribution and honest metrics (PDF, abstracts)

Bilot et al. (USENIX Security 2025, R-054) re-implemented eight state-of-the-art PIDSs in one framework; PIDSMaker (R-041) comes from the same authors. They found nine shortcomings that block practical use, and a simple neural network that achieves state-of-the-art detection on five of seven DARPA datasets. ORTHRUS (USENIX Security 2025, R-053) argues that the quality of attribution, how many nodes an analyst must inspect, is what keeps industry away, and reports orders of magnitude fewer such nodes.

What this asks of capture (INF from those abstracts):
- stable node identities (processes, files and sockets that are not split or merged by mistake);
- exact edges with exact times (data flow, not just opens);
- labelled attacks at node level, not "everything within two hops".

That is what the books, FLOW and the planned socket join are for.

### F5. Our hook points resist argument races (DOC, PDF)

Tools that hook syscalls read user-space arguments the program can change after the hook reads them. That is the "Phantom attack" (Guo and Zeng, DEF CON, R-058), and Houssel et al. count 69 % of 7.0-era syscalls taking a user pointer (R-027). Our programs read kernel objects at LSM and vfs points after the copy-in: the `struct file`, the inode, the dentry. This is a property to keep: no new hook should read a user-space argument as truth.

### F6. A privileged attacker blinds an eBPF tool by detaching it (DOC)

Elastic ships a detection rule for exactly this: `bpftool` detaching a program or link, or rewriting a map (R-057). p15d today would not notice another process detaching one of its links. Its programs would simply stop firing, and the books would still close, because nothing enters them. That is the one way a closed book can mislead (INF from the design; SRC: nothing in `daemon/` reads its own links' state after attach).

### F7. Storage: separate the graph's structure from its attributes (PDF, abstracts)

SEAL (USENIX Security 2021, R-059) and newer systems compress provenance losslessly by storing topology apart from attributes, and keep queries fast. DuckDB's columnar tables already separate them (ADR-0028). Nothing to change now. It is the direction if storage ever becomes the limit.

---

## 2. The architecture: five invariants to build towards

Each is a property we can test, not a component. Each gets an ADR when its work starts.

**I1. Every transfer is mediated and accounted** (from F1).
- A witness at `security_file_permission`: a kprobe.session, whose entry has the file and the mask and whose return has the verdict.
- Every mediated transfer must end as one of: a byte-exact FLOW (the vfs, socket or io_uring completion hooks), denied (the verdict), empty, or recorded as an intent with its requested count when no byte hook covers its path (splice, sendfile, copy_file_range until each gets its own).
- A new book closes over that: *mediated = flowed + denied + empty + intent*. That turns "no blind spot for file transfers" from a claim into an invariant checked every run.
- The cost is one more session per read and write: an estimated 80 to 150 ns (INF). It is measured with `bench/flow_cost` before anything is decided.
- A cheaper variant only counts at the witness and writes a record when no byte hook matched. Its cost is also unmeasured.

**I2. Every program has a quiescence protocol** (from E-0246, E-0247).
- At the end of a run: close a gate on new entries, let open calls drain, count what is still open, then detach.
- The detach fault is the first instance. Dragon's queue items 1 and 2 design it for the flow programs and audit the rest.

**I3. Nothing between the kernel and the WAL stays unsealed longer than a measured bound** (from F3).
1. Measure the window (decision waiting 5).
2. Seal batches with a forward-secure keyed chain: Nitro's approach, at the batch level we already have. This changes the WAL format (ADR-0007 v2).
3. Optionally, anchor the chain outside the host: the FPGA device.

**I4. The capture watches itself** (from F6).
- Each stats tick, p15d checks that each of its links is still attached and its programs still loaded. A missing one is a counted failure that makes the run INVALID.
- Every `bpf()` command by another process is recorded (the `security_bpf` LSM point), so the graph shows who detached what.
- A liveness signal leaves the host, so that killing p15d is itself visible.

**I5. Reduction keeps causality exact** (from F4 and the existing plan).
- Interval edges (PR #91) and folding by Xu's rule with in-progress marks (2c).
- Versioned nodes, a socket as one node (2e), and mapped writes as an interval from mmap to unmap (2d: there is no per-write hook, F1).
- The streaming builder (gate 10).

---

## 3. How we pull it off

**Who does what:**
- **Dragon** (Fable 5.2, time-limited): the design checks where a mistake costs most. That is phase 1's design review, then the detach design, then 2c's folding. The coverage audit of F1's table for every other kind of object is phase 1's first question.
- **This session:** implementation, harnesses, CI, evidence, STATE, and verifying every one of Dragon's findings against the code.
- **The maintainer:** the VM runs and the decisions.

**The order**, each step gated by its harness:

| Phase | Work | Gate that ends it |
|---|---|---|
| A, now | #90: the detach fix, then the `--flow` matrix, then `--flow` on by default. #91: the graph's FLOW edges. #93: stall detection | `--flow` matrix all PASS on the VM |
| B, coverage | I1's witness and its book; FLOW from io_uring completions; splice, sendfile and copy_file_range; 2d mmap intervals; the self-test gains one io_uring read and one splice (ARMO's lesson, R-035) | the coverage book closes under a workload that uses every path in F1's table |
| C, robustness | part 4: the ceiling at ≥ 10x the soak rate and skips under contention; a flood attributed to its process; the tamper window measured; the 24-hour soak | decision 46's criteria, each measured |
| D, integrity | I3's sealed WAL (ADR-0007 v2); I4's self-watch | a detached link or an edited batch is detected in a test |
| E, evaluation | graph v1 and the PIDSMaker export; DARPA data and our own labelled attack runs; the same workloads under Tetragon, Tracee and eAudit; Bilot et al.'s metrics at node level | the first detection number, with its comparison |

Phase B can start once A's gate passes. C and D can then run in parallel, because they touch different code. E needs B and C.

**What is publishable, and what it needs** (INF):
- **Capture whose books close, including a coverage book** that proves no file transfer path is unseen on a given kernel. No tool in the register claims that; most lose events without saying so (R-027).
- **Measured per-hook costs on 7.0.**

Both need phase E's same-workload comparisons. The register should be checked against this claim before anyone states it as new: Dragon's queue item 9.

---

## 4. Decisions this raises

1. **Adopt I1, the mediation witness and its coverage book, as phase B's design**, after a flow_cost arm measures the witness's cost. I recommend it. Evidence: F1's table (SRC); without the witness, every path in it except the vfs and socket ones is an unknown.
2. **Adopt I4's self-watch** (links checked each stats tick, others' `bpf()` commands recorded) as a phase D item. I recommend it. Evidence: F6. It is the one way the books can close while capture is blind.
3. **Put the FPGA audit device on the FPGA layer's agenda** as the out-of-host anchor for I3, to be studied, not built now. Evidence: F3; HARDLOG shows the pattern works with commodity parts (R-055, abstract only).
4. **Plan the evaluation around Bilot et al.'s metrics** (node-level, per attack) from the start, so capture logs what those metrics need. Evidence: F4 (abstracts; the papers to be read in full first).

## 5. Sources added to the register

R-053 ORTHRUS, R-054 Bilot et al., R-055 HARDLOG, R-056 Paccagnella et al. (race conditions on audit frameworks), R-057 Elastic's BPF tampering rule, R-058 the Phantom attack, R-059 SEAL. All are marked unverified (abstract or summary only). Already in the register and used here: R-003 and R-027 (Houssel et al.), R-011 (Nitro), R-035 (ARMO Curing), R-041 (PIDSMaker).
