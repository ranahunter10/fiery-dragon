---
status: proposed
date: 2026-10-25          # proposed; set to the merge date on acceptance
owner: Ashish Rana
consulted: [capture blueprint v1 §0.4, §1 (L5), §5.3 (2026-10-21), P5 disk evidence, ADR-0006/0008/0009 (proposed)]
supersedes: none
---

# 0007: Write-ahead log P15W v1: segment files with a self-describing header, a process snapshot, CRC-checked batches, and fdatasync every second

## Context and problem statement

v3.7 kept events in memory and in recordings (P15R) whose timestamps were boot-relative with no anchor (blueprint L5). A crash lost the tail silently. A slow graph meant lost events.

The new design makes the WAL the boundary: the C daemon appends, everything downstream reads. A slow reader then means **lag, not loss**, and any run can be replayed.

**Question:** what is the on-disk format, how is a torn write detected, how often is it flushed, and what makes a segment readable on its own years later?

## Decision drivers

1. **Self-describing:** a segment alone says what kernel, schema, hooks and clocks produced it (L5).
2. **Crash-safe:** a torn tail is detected and cut, never decoded as garbage; the power-loss window is stated.
3. **Replayable alone:** each segment carries enough state to rebuild the process table without earlier segments.
4. **Cheap on the drain:** one `write()` per batch; nothing per record beyond the record itself.
5. Fits the measured disk bandwidth with headroom.

## Considered options

1. **P15W v1:** segment files; a header with metadata; a `bpf_iter` process snapshot as the first block; records grouped in per-ring batches with a CRC32C each; `fdatasync` on rotate and every 1 s
2. One growing file, flushed on exit (v3.7 P15R style)
3. An embedded database (SQLite/DuckDB) as the write target
4. Option 1 plus a shared-memory ring for live readers (the blueprint's §5.1)

## Decision outcome

**Chosen option:** option 1. It meets drivers 1–4 with plain files and one append per batch.
- Option 3 puts a database engine on the event path.
- Option 4's shared-memory ring is deferred: in v1, live readers tail the WAL. A slow reader then lags rather than losing data, which is the property the shm ring was meant to give. It returns only if L7 shows tailing the WAL is too slow for the analysis tier.

### Format (P15W v1.0)

1. **Directory:** one run per directory, `<wal-root>/<run-id>/`. Segments are named `seg-<index:08>.p15w` and rotate at **64 MiB or 60 s**, whichever comes first (both configurable and recorded).
2. **Segment header** (fixed prefix, then length-prefixed key/value metadata):
   - magic `P15W`, format version 1.0, byte order;
   - run id, segment index;
   - **`boot_id`** (scopes process identity, ADR-0009), hostname, kernel release;
   - schema hash (ADR-0008), daemon git commit, libbpf and bpftool versions (ADR-0002);
   - the **attached-hook manifest** and the **self-test result** (ADR-0003);
   - ring sizes (ADR-0006);
   - **clock anchors:** `CLOCK_BOOTTIME`, `CLOCK_MONOTONIC` and `CLOCK_REALTIME` read back to back, with the read spread; the timezone. Periodic clock-sync records repeat the anchors in the spine (L5).
   - the first sequence number of each ring.
3. **First block: process snapshot.** At segment open, a `bpf_iter/task` program dumps every live thread group: identity `(tgid, start_ns)` (ADR-0009), parent identity, comm, executable identity, argv (bounded, as in ADR-0003).
   - This is kernel-consistent, unlike `/proc` scraping, and makes the segment replayable alone. `bpf_d_path` is allowed in iterators (`kernel/trace/bpf_trace.c` line 949, v7.0), so the snapshot can carry resolved executable paths.
4. **Batches:** each `write()` is one batch, holding records from **one ring** only.
   - The batch header carries ring id, first sequence number, record count, payload length, CRC32C of the payload, and its own CRC.
   - Records inside are exactly as defined by ADR-0008: their own `len`, padded to 8 bytes.
   - A record's per-ring sequence number = the batch's first sequence + its index, so no per-record framing is added.
5. **Torn tail:** readers and the writer (on restart) walk the batches and stop at the first one whose length or CRC doesn't check. The writer truncates there, and **the number of bytes cut is counted** and written in the next segment's header.
6. **Durability:** `fdatasync` at every rotation and **every 1,000 ms** (configurable). The power-loss window is therefore about 1 s of records, and it is stated in the header.
7. **No compression** in v1. Reopened only if the Phase-2 sizing exceeds the disk budget.

**Disk budget:** P5 measured a minimum of 63.7 MB/s sequential writes on the VM. One third of that, the blueprint's headroom rule, is about **21 MB/s** sustained (E-0008). The spine is far below it. Data flow is sized in Phase 2 (audit A5).

### Consequences

- Good: any segment answers "what produced this" without outside notes (L5). A torn tail can't be mistaken for data.
- Good: readers can't slow the drain. They read files at their own pace, so lag is visible and loss is not possible past the WAL.
- Good: the snapshot means a reader can start from any segment, and pre-existing processes have exact identities.
- Bad: up to about 1 s of records can be lost on power failure. This is stated, not hidden; the blueprint found no comparable tool that fsyncs per record.
- Bad: a snapshot per segment costs a task iteration at each rotation. It is small at desktop process counts, to be measured.
- Bad: per-ring batches mean the reader merges rings (ADR-0006).

### Confirmation

- **L2 tests** (daemon): framing round trip; CRC failure detection; truncate-at-tail on a file cut at every byte offset of its last batch; rotation by size and by time; header fields present.
- **L2 fuzz:** the Python WAL reader is fuzzed (blueprint L1, Atheris) and must never read past a batch or record length.
- **L4 test:** a segment opened mid-run replays to the same process table as the live run at that point.
- `tools/wal-inspect` (Phase 1) prints a segment's header and batch summary. A run report quotes it.

### Falsifier

Reopen if:
- the measured WAL bandwidth on an in-scope workload exceeds the ≈ 21 MB/s budget, which leads to compression or in-kernel reduction (ADR-0005);
- the 1 s durability window is judged too large for the threat model (ADR-0013);
- tailing the WAL can't keep the analysis tier's lag bounded, which brings back the shm ring (option 4).

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | VM sequential write: 63.7 / 105 / 92.3 MB/s (direct 1 MiB); min ≈ 64 MB/s, so ≈ 21 MB/s at 3× headroom | MEAS | [`05-p5-disk.txt`](../evidence/phase0/05-p5-disk.txt); E-0008 (absolute disk rates drift on this host: E-0040, E-0044) |
| 2 | `bpf_d_path` is allowed in BPF iterator programs | SRC | `kernel/trace/bpf_trace.c` lines 947–951 at [v7.0](https://github.com/torvalds/linux/blob/v7.0/kernel/trace/bpf_trace.c#L947) |
| 3 | v3.7 timestamps had no wall-clock anchor; eAudit records clock-sync markers | DOC/PDF | blueprint v1 §1 L5 |
| 4 | No comparable tool fsyncs per record | SRC (grep) | blueprint v1 §5.3 |
| 5 | Snapshot-at-start as in Falco's `.scap` files | SRC | blueprint v1 §5.3 |

## Pros and cons of the options

### 1. P15W segments + snapshot + CRC batches
- Good: everything in the drivers.
- Bad: our own format to maintain (versioned, with readers kept forever, ADR-0008).

### 2. One file, flush on exit
- Bad: unbounded loss on a crash; no torn-tail detection; v3.7's L5.

### 3. Embedded database
- Bad: a database engine on the event path; harder to make the "one write per batch" guarantee.

### 4. Plus a shared-memory ring
- Good: lower latency for live readers.
- Bad: a second delivery path to test; the WAL tail already gives lag-not-loss. Deferred until measured.
