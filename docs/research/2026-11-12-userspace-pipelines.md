# How the tools' user-space side reads, batches, wakes and writes, against p15d's code (2026-11-12)

The maintainer asked for the study the earlier research left out: the tools' user-space pipelines. That gap is where p15d's two largest costs were (the byte-at-a-time CRC, E-0215, and a wake of the writer per batch, E-0219). This note reads each pipeline's code at a pinned commit, sets it beside p15d's code, and lists what to take and what not to take. Every candidate is INF until measured on the VM. **No design change is taken here.** Grades as in `CONTRIBUTING.md` §5. Code read, never built or executed (CLAUDE.md): R-052 in `papers.csv`.

| Code | Commit | Files read |
|---|---|---|
| Falco libs (modern_bpf engine) | 0815626 | `userspace/libpman/src/ringbuffer.c`, `userspace/libscap/engine/modern_bpf/scap_modern_bpf.c`, `userspace/libscap/ringbuffer/devset.h`, `driver/modern_bpf/helpers/store/ringbuf_store_params.h` |
| Tetragon | 63332a1 | `pkg/observer/observer_linux.go`, `pkg/observer/observer.go`, `pkg/option/flags.go`, `pkg/exporter/exporter.go`, `bpf/lib/process.h` |
| Tracee | 2f9dc40 | `pkg/ebpf/tracee.go`, `pkg/ebpf/events_pipeline.go`, `pkg/ebpf/c/common/buffer.h` |
| eAudit | c4e5e50 (github.com/seclab-stonybrook/eaudit) | `eauditd.C`, `eauditd.py`, `eauditk.c`, `eauditk.h` |
| libbpf (ours, vendored) | f5dcbae | `src/ringbuf.c` `ringbuf_process_ring` |

## 1. What each one does (SRC)

### Falco: one thread, records read where they lie, no wake-ups
- **The kernel never wakes the reader.** Every record is submitted with `BPF_RB_NO_WAKEUP` (`ringbuf_store_params.h` L179).
- **The reader polls with a back-off instead.** When no ring has a record, `scap_modern_bpf__next` sleeps 500 µs, doubling to 30 ms while empty, and resets once it finds one (`scap_modern_bpf.c` L54-71; `devset.h` L34-35).
- **Records are read in place, never copied out.** `ringbuf__consume_first_event` looks at the first record of every ring and returns a pointer to the oldest by timestamp: a k-way merge across per-CPU rings (`ringbuffer.c` L291-332). The record is processed by the same thread (rules, state) straight from the mapped ring.
- **The consumer position moves once per record, lazily:** at the next call, after the caller is done with the record (L298-303).
- There is no hand-off thread, no checksum, and no copy before processing.

### Tetragon: a reader goroutine per ring, a record per channel send, drop when full
- **The kernel wakes on its default rule.** `ringbuf_output(..., 0)` (`bpf/lib/process.h` L664) wakes the reader only when it has caught up.
- **Each record is copied once, into a pooled buffer.** `ReadInto` blocks on the ring (`observer_linux.go` L118-150, L155-185).
- **One record per channel send.** The channel holds 65,535 records by default (`flags.go` L622).
- **A full channel drops the record, counted** (`queueLost`, L135-139). That is load shedding, not back-pressure.
- **One processing goroutine** decodes every record into Go structures (`HandlePerfData`, `observer.go` L88-117), enriches it from the process cache, and hands it to listeners. The exporter encodes each event as JSON (`exporter.go` L155-162).

### Tracee: perf buffers, a 300 ms poll, a chain of goroutines
- **Per-CPU perf buffers:** `bpf_perf_event_output` (`buffer.h` L729), polled with a 300 ms timeout (`tracee.go` L1831, L1854).
- **Each sample is copied into a channel of 1,000** (`tracee.go` L1759-1769).
- **A pipeline of goroutines follows,** each stage a channel hand-off per event: decode, sort, process, enrich, derive, detect, sink (`events_pipeline.go` L35-80).

### eAudit: batching at both ends, one write per poll
- **Kernel side:** each CPU keeps a cache of records (16 KiB, `eauditk.h` L9) and flushes it with one `ringbuf_output`. It forces a wake only for high-weight events. Otherwise it wakes at random, once per `RINGBUF_PUSH_INTERVAL` flushes on average (`eauditk.c` L419-431).
- **User side:** the callbacks of one `ring_buffer_poll` copy records into a 1 MiB buffer, and **one `write` follows at the end of each poll**. Nothing is kept across polls, so batching never widens the window in which an attacker could alter buffered data (`eauditd.C` L76-160, its own comment L77-88).
- No hand-off thread and no checksum.

### libbpf's ring reader, which p15d's drain uses
- `ringbuf_process_ring` calls the callback per record and **stores the consumer position after every record** (`ringbuf.c` L270), with a release store.
- Every BPF program that reserves space reads that position. So each store can move its cache line between the drain's CPU and the producers' CPUs once per record (INF: not measured).

## 2. p15d's pipeline beside them (SRC, today's main plus #83)

| Step | p15d | Falco | Tetragon | Tracee | eAudit |
|---|---|---|---|---|---|
| Kernel wakes the reader | only above a high-water mark (`file.bpf.c` L177-178, ADR-0020) | never (`NO_WAKEUP`) | default rule (flags 0) | perf buffer (its wake setting not read) | forced for important events, else at random |
| Reader waits | `epoll` with an adaptive timer, 10 to 200 ms (ADR-0030) | `usleep` back-off, 0.5 to 30 ms | blocking read | 300 ms poll | `ring_buffer_poll` |
| Per record | `p15_rec_check`, `memcpy` into a batch, an atomic counter (`drain.c` L60-128) | read in place | copy, channel send | copy, channel sends per stage | callback, `memcpy` into 1 MiB |
| Consumer position | stored per record (libbpf `ringbuf.c` L270) | per record, lazily (L298-303) | not read (cilium/ebpf) | not read (libbpfgo) | libbpf through BCC: per record (INF) |
| Hand-off | batches to a writer thread through an SPSC queue and an **eventfd kick per batch** (`queue.c` L69-83) | none | channel per record | channels per stage | none |
| When the reader's own queue is full | back-pressure: the record stays in the kernel ring (ADR-0017) | no queue: the kernel ring drops, counted (`auxmap_store_params.h` L387-390) | **drop, counted** (`queueLost`) | not read | no queue: the kernel ring |
| Integrity | **CRC32C per batch**, payload and header (`wal.c` L329-330) | none | none | none | none |
| Write | `writev` per batch (`p15w_append`) | scap dump if asked | JSON per event | per printer | one `write` per poll |

What p15d already does as the best of them do:
- It doesn't wake on every record. ADR-0020's high-water mark plus an adaptive timer is Falco's `NO_WAKEUP` plus back-off, with a bound.
- It reads in batches and writes in batches, as eAudit does.

Where p15d paid more than any of them:
- **The kick per batch, now mostly fixed.** At 256 KiB, p15d published about 144 batches per arm, each with a wake costing about 200 µs on this VM (E-0219). 1 MiB batches cut p15d's CPU per open+close from 413 to 204 ns (E-0220). eAudit pays at most one write per poll, and Falco pays no hand-off at all.
- **The checksum.** None of the four checksums its output. Ours now costs about 6.5 % of p15d's samples (E-0218). We keep it: the WAL's integrity is a requirement (ADR-0006).

What p15d pays on purpose:
- The writer thread, so a slow disk cannot stall the drain (ADR-0017).
- Back-pressure instead of dropping.
- A check on every record.
- A checksum on every batch.

## 3. Candidates (each INF until measured; none decided)

| # | Change | Taken from | Expected (INF) | Cost or risk | Harness |
|---|---|---|---|---|---|
| U1 | **Default `--batch-kb 1024` and `--queue-batches 16`** (the same 16 MiB) | eAudit's 1 MiB buffer | measured: p15d 413 to 204 ns per open+close (E-0220) | a full batch holds 4 times more records before it is written; batches still close at every poll (`after_poll`), so the time a record waits is bounded by the poll interval, not the batch size | done (`open_cost`) |
| U2 | One wake of the writer per drain poll, not per batch; at once when the queue is full | eAudit's write per poll | small after U1 (0.4 switches per 1,000 open+close remain) | adds at most one poll's reading time before the writer sees a batch | `open_cost` switches and p15d CPU |
| U3 | **The drain reads the ring itself and stores the consumer position once per batch**, not once per record | Falco reads the mapped ring itself | fewer cache-line moves between the drain and every producing CPU; may lower the BPF side's reserve and copy time, not only p15d's | owning a reader that libbpf owns today: its ordering rules (busy bit, discard bit, acquire and release) are copied from `ringbuf.c` and tested | `prog_stats` (the programs' bodies) and `open_cost`, paired against libbpf's reader |
| U4 | Per-record atomic counters in `on_bulk` and `on_spine` summed locally and added once per take | — | a few ns per record | none to the books, which are read after a take | `open_cost` |
| U5 | **Smaller records** (C3 in the open-cost note): a timestamp delta from a batch base, no `start_ns` in bulk headers, varints | eAudit's 17-byte records (R-042 §3.4) | in proportion to bytes everywhere: the BPF copy (37.6 ns of an OPEN), the drain's copy, the CRC, the write, the disk | a schema version and decoder change; bulk records would lean on the spine for the process key | needs an ADR first |

**Not taken**, and why:
- A channel send per record, and decoding to objects on the hot path (Tetragon, Tracee). That is per-event work we don't need before the WAL, and Tetragon and Tracee lose about 90 % of events on postmark (eAudit's Fig. 16, R-042).
- Dropping when the reader's queue is full (Tetragon). We keep back-pressure to the kernel ring, where losses are counted per record (ADR-0017).
- One thread for reading and writing (Falco, eAudit). A disk stall would stop the drain. With U1, the hand-off costs little (E-0220).
- No checksum (all four). WAL integrity is ADR-0006's.

## 4. Order

1. U1: by a STATE decision. Measured, cheap, no code.
2. U3: the largest unmeasured lever on both sides of the ring. A harness first: a reader that stores the position once per take, as a p15d option, measured against libbpf's on `prog_stats` and `open_cost`.
3. U4 with U3: the same loop.
4. U2: only if switches still show after U1 under the soak.
5. U5: an ADR, after U3's numbers, because it changes the schema.
