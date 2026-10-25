---
status: proposed
date: 2026-10-25
owner: Ashish Rana
consulted: [research note 2026-10-25-measurement-and-design-inputs (B1, B6), NoDrop USENIX Sec'23, Mao et al. arXiv 2510.08479, auditd.conf(5), LTTng lost-event accounting, rb_size probe, maintainer's questions of 2026-10-26]
supersedes: ADR-0006 rules 1 and 4 only (the spine's sizing basis, and "one C drain thread"); every other rule of ADR-0006 stands
---

# 0017: Spine flood resilience: exact-size records, a drain that never waits on disk, a raised drain priority, located loss, and a measured headroom

## Context and problem statement

ADR-0006 keeps the spine (process lifecycle) on its own ring, so a flood of file or network events (Mao's `find` super producer, v3.7's G3 loss) **cannot** push lifecycle records out. That part of the defence was designed in.

ADR-0006 also says a failed spine reservation makes the run invalid. That is honest, but it leaves three gaps that the research pass found (note B6):

1. **The spine's own headroom was sized from average census rates (INF), not from an adversary.** Worse, the EXEC record reserves its maximum, 1,344 B, whatever its real length. A short command line therefore takes about 15× the ring space it needs (MEAS, `rb_size`).
2. **The drain can be starved.**
   - One thread both drains the rings and writes the WAL. Every `fdatasync` (ADR-0007, each second) stops the draining for as long as the disk takes. That stall is not measured on the VM (OPEN).
   - A CPU-heavy attacker can also keep the drain off the CPU. Mao et al. show that consumer scheduling alone decides loss: Sysdig lost 39 % on `find` under the default scheduler and 98.5 % under others.
3. **A loss is counted but not located.** A global counter says *that* lifecycle records were lost, not *when*. A reader can't tell which part of the process tree to distrust.

Together these let an attacker *cause* an invalid run (a fork/exec storm while the drain is busy) and hide inside it.

**Question:** how does the spine stay complete under a flood, and when it can't, how is the damage bounded and located?

## Decision drivers

1. **No silent spine loss, ever** (ADR-0006 driver 1, kept).
2. **Make spine loss as hard to cause as possible**, with defences we can measure on the VM.
3. **When loss does happen, locate it in the record stream**, so the process tree can mark exactly what it can't trust.
4. **Don't trade the host's availability for capture by default.** That trade is the deployer's policy (NoDrop's "PADoS"), not ours.
5. Mechanisms available in BPF on 7.0 without BPF-LSM (E-0003: no `bpf` in the LSM list).

## Considered options

1. **Five layers:**
   - exact-size spine records;
   - a drain that never waits on disk;
   - a raised drain priority;
   - located loss;
   - a ring size set from a measured flood.
2. Option 1 plus **admission control:** `fmod_ret` on the fork/exec syscalls returns `-EAGAIN` when the spine ring is nearly full, so the flooder pays (NoDrop's principle).
3. **Per-thread buffers drained in the producing thread's context** (NoDrop itself).
4. **A scheduler for the consumer** (Mao et al.'s Aegis, `sched_ext`).
5. Keep ADR-0006 as it is and declare the limit.

## Decision outcome

**Chosen option:** option 1, because each layer is measurable here and none costs the host's availability (drivers 2, 4, 5). Option 2 is designed and documented as a **deployer policy** for ADR-0013, off by default; it is not built in v1.

### The five layers

1. **Exact-size spine records.**
   - Every variable-length spine record (EXEC today) takes only its own `len` in the ring: `bpf_ringbuf_reserve_dynptr()` of the exact length, else `bpf_ringbuf_output()` from a per-CPU scratch buffer.
   - Both pass the verifier and deliver exact sizes (MEAS, `rb_size`; dev container now, VM via `make smoke`).
   - Fixed-size records (FORK, EXIT, RENAME) already reserve exactly.
   - Expected effect: about 4.2× more processes buffered per MiB of spine ring (INF, sizes below).
2. **The drain never waits on disk.**
   - Two threads:
     - the **drain** thread polls both rings, copies records into batches and stamps the sequence numbers (ADR-0006 rule 4's three duties, unchanged);
     - the **writer** thread owns the WAL: `writev`, rotation and `fdatasync` (ADR-0007).
   - Between them: a bounded single-producer/single-consumer queue of full batches, preallocated at start, no locks on the hot path.
   - If the queue is full, the drain stops copying and the rings absorb the backlog. The disk's stall then costs ring headroom, not a lost record.
   - The queue depth and its high-water mark are counted.
3. **A raised drain priority.**
   - The drain thread runs at a raised priority so that busy user processes cannot starve it. The writer stays at normal priority.
   - **Default: `SCHED_FIFO` priority 1**, safe because the drain blocks in `epoll_wait` whenever the rings are empty, and the kernel's real-time throttling (`sched_rt_runtime_us`) bounds any runaway.
   - If `SCHED_FIFO` is refused, it falls back to `nice -10` (auditd's `priority_boost` precedent). The fallback is **counted and written in the WAL header**, never silent.
4. **Located loss.**
   - Each poll, the drain reads the spine's per-type `reserve_failed` counters (one per-CPU map lookup per type).
   - If any rose, the drain writes a **GAP** record into the daemon ring (ADR-0006: daemon records) carrying:
     - the per-type counts lost since the last poll;
     - the boot-clock time window they fell in.
   - The process tree marks every process alive in that window as **possibly incomplete**, rather than distrusting the whole run.
   - The run is still invalid for completeness claims (ADR-0006 rule 6 stands). The GAP record says where.
   - Precedent: LTTng numbers every packet so a reader can see exactly where packets went missing.
5. **A ring size set from a measured flood.**
   - Phase 1 measures the spine's byte rate under a fork/exec storm on the VM: shbm-style `/bin/true` loops, one per vCPU, plus a fork bomb capped by `RLIMIT_NPROC`.
   - It also measures the worst drain stall, the time between polls, from the drain's own histogram.
   - **The spine ring is sized to at least 4× (worst storm byte rate × worst stall)**, rounded up to a power of 2, and recorded in the WAL header.
   - The 4 MiB of ADR-0006 stays the starting value until then.

### Sizes behind layer 1 (INF, arithmetic)

| Record | Fixed reservation (B) | Exact size (B) |
|---|---|---|
| FORK | 72 | 72 |
| RENAME | 72 | 72 |
| EXEC with 100 B of filename and argv | 1,352 | 176 |
| EXIT | 48 | 48 |
| **One process's lifecycle** | **1,544** | **368** |

Each figure includes the ring's 8-byte header. A 4 MiB spine ring therefore buffers about 2,700 process lifecycles today and about 11,400 with exact sizes, about 4.2× more.

### Consequences

- Good: the common super-producer attack (an I/O flood) already can't touch the spine (ADR-0006). The remaining one, a lifecycle flood or drain starvation, now needs the ring to overflow:
  - by a measured margin;
  - against a drain that disk stalls can't block and busy processes can't starve.
- Good: when loss happens anyway, the GAP record bounds the damage in time. The analysis tier distrusts minutes, not the whole run.
- Good: the writer thread isolates the slowest operation, `fdatasync`, from the fastest, draining.
- Bad: two threads instead of one. The queue between them is the only shared state, and it is tested under ThreadSanitizer (ADR-0019).
- Bad: a real-time thread in a security daemon. Mitigated by blocking in `epoll_wait` and by kernel RT throttling; the priority and any fallback are recorded.
- Bad: exact sizes cost one extra copy (the `output` way) or the dynptr API (the `dynptr` way). The cost is measured with `bpf_stats` before choosing between them.
- Bad: an attacker with enough CPU and processes can still overflow any finite ring. This is **declared** in ADR-0013, with the measured storm rate at which it starts.

### Confirmation

- **`rb_size`** runs in `make smoke` (CI and VM): both exact ways must deliver exact sizes.
- **L4 forced-overflow test** (ADR-0006, kept): a tiny spine ring plus an exec storm. The run must be marked invalid **and** contain a GAP record whose window covers the lost records.
- **Drain-stall test:** a writer made to sleep 2 s inside `fdatasync` (injected through the writer's `writev`/sync hooks, as in `test_wal.c`) loses no spine record with a ring sized by layer 5.
- **Priority:** the WAL header records the drain's scheduling policy and priority, and any fallback. A test checks the fallback path is counted.
- **L6 row:** loss on the spine under the storm workloads of layer 5, reported per type, with the storm rate at which `reserve_failed` first rises.

### Falsifier

Reopen if:
- `reserve_failed` rises on the VM under a storm below the layer-5 sizing;
- the drain at `SCHED_FIFO` measurably delays other real-time work (a regression in an L7 latency workload);
- the GAP window, checked against a ground-truth exec log, fails to contain the lost records.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | A fixed reservation always takes 1,344 B; `bpf_ringbuf_output` and `bpf_ringbuf_reserve_dynptr` take the exact run-time length (88 / 264 / 1,064 / 1,088 B) | MEAS (dev container; VM pending) | [rb-size probe](../evidence/probes/2026-10-25-rb-size-container/README.md) |
| 2 | Every ring record carries an 8-byte header; size must be a power of 2 | DOC | `Documentation/bpf/ringbuf.rst` (ADR-0006 evidence 4) |
| 3 | Consumer scheduling decides loss: Sysdig on `find` 39.34 % under EEVDF, 98.53 % under LAVD; eAudit 0 % / 15.11 % | PDF | Mao, Ujcich & Ma, arXiv 2510.08479 (R-004) |
| 4 | NoDrop: per-thread buffers consumed in the producer's context give zero loss, at lmbench +35 % OS overhead; the integrity-vs-availability dilemma (PDoS/PADoS) | PDF | Jiang et al., USENIX Security 2023 (R-012) |
| 5 | auditd takes a priority boost by default (`priority_boost = 4`), and lets the operator choose `suspend`/`single`/`halt` on overflow or a full disk | DOC | [auditd.conf(5)](https://man7.org/linux/man-pages/man5/auditd.conf.5.html) |
| 6 | LTTng numbers packets (`packet_seq_num`) so readers see where whole packets were lost, and counts discarded events per channel | DOC | [lttng-dev, 2015-08](https://lists.lttng.org/pipermail/lttng-dev/2015-August/024811.html) |
| 7 | Ring reservations are serialised under a spinlock; commits are lockless | DOC | R-021 |
| 8 | No BPF-LSM on the target (no `bpf` in the LSM list), so admission control would need `fmod_ret` on error-injectable syscalls | MEAS / OPEN | E-0003; `CONFIG_FUNCTION_ERROR_INJECTION` on 7.0.0-38 not yet checked |
| 9 | `fdatasync` stall on the VM's disk | OPEN | to measure (writer stats: sync latency max) |

## Pros and cons of the options

### 1. Five layers
- Good: every layer measurable here; no availability cost; loss bounded and located.
- Bad: a second thread; an RT thread.

### 2. Plus admission control
- Good: the flooder pays; the spine can't overflow from fork/exec.
- Bad: the capture layer makes `fork` fail. That is enforcement, and a DoS lever if misconfigured. Needs error-injection support (OPEN on 7.0). Kept as a documented deployer policy (ADR-0013), off by default.

### 3. NoDrop's per-thread buffers
- Good: zero loss, proven.
- Bad: needs a kernel module and blocking in the producer; BPF can't block. +35 % lmbench.

### 4. A consumer scheduler (`sched_ext`)
- Good: attacks the root cause Mao found.
- Bad: `sched_ext` replaces the system scheduler, far beyond a capture layer's remit; not enabled on our kernel config (OPEN on 7.0.0-38).

### 5. Declare only
- Bad: leaves an attacker a cheap way to invalidate runs, and leaves loss unlocated.
