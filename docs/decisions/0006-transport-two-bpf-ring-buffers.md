---
status: accepted
date: 2026-10-25
owner: Ashish Rana
consulted: [capture blueprint v1 §0.4, §5.1–5.2, §5.6 (2026-10-21), Linux v7.0 Documentation/bpf/ringbuf.rst, census E-0025, v3.7 G3 loss study]
supersedes: none
---

# 0006: Two BPF ring buffers (spine never shed, bulk counted), self-paced wakeups, one C drain thread

## Context and problem statement

v3.7 sent every record through one per-CPU perf buffer into Python. When the reader fell behind, records were lost, and the loss came at the same knee whatever the buffer size (G3: about 9,400 records/s). Process-lifecycle records were lost along with everything else, which breaks every later attribution.

The kernel offers two transports:
- **perf buffers:** per CPU;
- **BPF ring buffers:** one buffer shared by all CPUs, ordered.

**Question:** which transport carries records from BPF to the daemon, how are lifecycle records protected from bulk floods, how is the consumer woken, and how is every loss counted?

## Decision drivers

1. **Lifecycle records are never lost silently.** Without them nothing else can be attributed.
2. **Order:** a process's fork → exec → exit must arrive in order across CPUs.
3. **Every lost record is counted, by cause** (blueprint L3, §5.6).
4. Throughput far above v3.7's ceiling (ADR-0002).
5. The simplest wakeup scheme that measurements don't contradict.

## Considered options

1. **Two `BPF_MAP_TYPE_RINGBUF` maps:** *spine* (process lifecycle, capability flags, markers) and *bulk* (data flow), with default self-paced wakeups
2. One ring buffer for everything
3. Per-CPU perf buffers (v3.7)
4. Two ring buffers with `BPF_RB_NO_WAKEUP` and a forced wakeup at a byte watermark (the blueprint's §5.2 proposal)

## Decision outcome

**Chosen option:** option 1.
- **Ring buffers over perf buffers:** they keep order across CPUs and share memory (drivers 2 and 4; kernel docs below).
- **Two rings rather than one:** a flood of data-flow records can't push out lifecycle records (driver 1).
- **Default wakeups rather than option 4:** the kernel already notifies only when the consumer has caught up, which the kernel docs say reaches very high throughput without "notify every Nth" tricks (driver 5). Option 4 stays the documented fallback if L7 measurements show wakeups cost.

### Rules

1. **Spine ring:** fork, exec, exit, rename (Phase 1); later capability flags, markers, clock-sync and drop summaries.
   - **Never shed.** BPF can't block, so a failed reserve on the spine increments `spine_reserve_failed`.
   - **Any non-zero value makes the run invalid** (the accounting invariant below doesn't close).
   - The spine ring is sized so this doesn't happen: initial size **4 MiB**, configurable and recorded in the WAL header.
   - Basis for the size (INF): the light census's exec-heavy load emitted about 2,500 records/s on average, 4,274 at p99, all classes; spine records are a fraction of that. 4 MiB holds over a second of that at a few hundred bytes per record. Phase 1 measures the real fill level and resizes if the high-water mark exceeds half.
2. **Bulk ring** (Phase 2 onward): data flow. A failed reserve **is counted per record class** (`bulk_reserve_failed[class]`) and appears in the run's accounting. Bulk loss is reported, never silent. The initial size is decided with the Phase-2 sizing (audit A5).
3. **Wakeups:** commit with flags `0` (the kernel's self-paced notification). No `BPF_RB_NO_WAKEUP` until an L7 measurement shows the wakeup path matters.
4. **Drain:** one C thread in `p15d`, `ring_buffer__poll` over both rings through one libbpf `ring_buffer` manager. Per record it does exactly three things:
   - copy into the current batch buffer;
   - count it;
   - stamp a **per-ring sequence number** (u64, assigned by the daemon, written in the WAL framing; ADR-0007).
   It never calls Python and never blocks on a reader.
5. **Order:**
   - within one ring, records arrive in reservation order (kernel docs);
   - across rings, readers merge by `ts_ns` (ADR-0008), then ring, then sequence;
   - a Phase-1 property test checks per-process order (fork before exec before exit) on the spine.
6. **Accounting invariant** (blueprint §5.6, normative). For every class, at quiescence:
   - `attempted = emitted + excluded_by_policy + reserve_failed + read_failed + …`, with one counter per early-return site in BPF;
   - `emitted = written_to_WAL + drain_lost`.

   Counters live in a per-CPU array map, are read every stats tick, and are written as stats records. A run whose invariant doesn't close is invalid.

### Consequences

- Good: lifecycle records are isolated from data-flow floods. If they are ever lost, the run says so and is invalid.
- Good: in-order delivery per ring without a global sequence counter in BPF (blueprint §2.4).
- Good: the simplest wakeup path first; a measured reason is needed before adding complexity.
- Bad: two rings means a cross-ring merge in the reader. Records from different rings can arrive out of timestamp order and must be merged.
- Bad: a ring buffer is shared by all CPUs, so heavy producers on many CPUs contend on its reservation lock. To be measured in L6/L7.

### Confirmation

- **Phase 1:** a forced-overflow L4 test (tiny spine ring, exec storm) must show a non-zero `spine_reserve_failed` and a run marked invalid. It is the gate that the "never silent" rule is real.
- **Phase 1:** the per-process order property test above.
- **Phase 1 / L6:** the zero-loss knee on the spine is at least 10× v3.7's 9.4 k records/s (blueprint Phase-1 gate).

### Falsifier

Reopen if:
- spine reserve failures occur under any in-scope workload at the configured size;
- the L6 knee is limited by wakeups (profiling shows the consumer woken per record), which points to option 4;
- the reservation lock limits throughput on 4 vCPUs, which points to per-CPU rings.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | Ring buffer: MPSC, shared across CPUs, preserves the order of events that happen sequentially, even across CPUs | DOC | [`Documentation/bpf/ringbuf.rst` lines 14–27, v7.0](https://github.com/torvalds/linux/blob/v7.0/Documentation/bpf/ringbuf.rst) |
| 2 | Reservations are strictly ordered; records become visible in reservation order after all earlier ones commit | DOC | same file, lines 178–183 |
| 3 | Commit notifies only if the consumer has caught up; benchmarks show very high throughput without "notify every Nth"; `BPF_RB_NO_WAKEUP`/`FORCE_WAKEUP` give manual control | DOC | same file, lines 196–206 |
| 4 | Ring size must be a power of 2 | DOC | same file, line 70 |
| 5 | v3.7 lost records at about 9.4 k records/s with 64 and 256 pages per CPU alike | MEAS | v3.7 project `G3_loss_under_load_2026-10-19.md` (old repo) |
| 6 | Light census, exec-storm: 2,481 records/s mean, 4,274 p99, all classes, 0 lost | MEAS | [census light](../evidence/census/2026-10-24T221732Z-light/README.md); E-0025 (absolute rates on this host are drift-prone: E-0044) |
| 7 | Ring buffers are available on the target | MEAS | [`03-p2-feature-probe.txt`](../evidence/phase0/03-p2-feature-probe.txt); E-0007 |

## Pros and cons of the options

### 1. Two ring buffers, default wakeups
- Good: isolation, order, counted loss, simplest wakeups.
- Bad: a reader-side merge across rings.

### 2. One ring buffer
- Good: one total order.
- Bad: a data-flow flood can starve lifecycle records (driver 1).

### 3. Per-CPU perf buffers
- Bad: no cross-CPU order; memory per CPU; v3.7's loss behaviour.

### 4. Two rings + `NO_WAKEUP` and a watermark
- Good: fewer wakeups under load.
- Bad: needs a watermark tuned by measurement; a stuck partial batch needs a timer. Complexity without a measured reason yet.
