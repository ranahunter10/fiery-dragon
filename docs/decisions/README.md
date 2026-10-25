# Decision records (ADRs)

This directory is the **decision journal** of Fiery Dragon. Each file records one decision: why it was made, which options were weighed, the evidence behind it, and what would reopen it. How the process works is itself a decision, in [ADR-0000](0000-record-architecture-decisions.md).

To write a new one:
1. Copy [`adr-template.md`](adr-template.md) to `NNNN-title-with-dashes.md`.
2. Open a PR from an `adr/NNNN-<topic>` branch.
3. Add a row to the index below in the same PR.

## Index

| ADR | Title | Status | Date |
|---|---|---|---|
| [0000](0000-record-architecture-decisions.md) | Record architecture decisions as ADRs in the repository | accepted | 2026-10-25 |
| [0001](0001-platform-ubuntu-26-04-kernel-7-0-pinned.md) | Develop and measure on Ubuntu 26.04 LTS with the GA kernel 7.0.0-38, held | accepted | 2026-10-25 |
| [0002](0002-toolchain-libbpf-co-re-c-daemon.md) | Build with libbpf v1.7.0 + CO-RE skeletons and a C daemon; Python only after the WAL | accepted | 2026-10-25 |
| [0003](0003-hook-policy-btf-checked-attach-points-self-test.md) | Hook policy: BTF-checked attach points, the spine on `tp_btf` sched tracepoints, argv from the kernel's copy, and a per-pid load-time self-test | accepted | 2026-10-25 |
| [0006](0006-transport-two-bpf-ring-buffers.md) | Two BPF ring buffers (spine never shed, bulk counted), self-paced wakeups, one C drain thread | accepted | 2026-10-25 |
| [0007](0007-wal-segmented-crc-batches-snapshot.md) | Write-ahead log P15W v1: segment files with a self-describing header, a process snapshot, CRC-checked batches, and fdatasync every second | accepted | 2026-10-25 |
| [0008](0008-schema-single-source-generated-layouts.md) | One schema file generates every record layout; per-type versions; a 32-byte common header on the boot clock | accepted | 2026-10-25 |
| [0009](0009-process-identity-tgid-leader-start-time.md) | Identify a process by (boot id, tgid, the thread-group leader's start_boottime) | accepted | 2026-10-25 |
| [0012](0012-quantification-protocol.md) | Quantification protocol: host-independent metrics first; relative timing only, by paired rounds with an A/A control | accepted | 2026-10-25 |

## Planned (from capture blueprint v1, §8.3)

These numbers are reserved. Each becomes a PR when its evidence is ready.

| ADR | Topic | Evidence needed first |
|---|---|---|
| 0004 | Connect/accept hook layer | P7 |
| 0005 | In-kernel filtering: who/what-kind only, no in-kernel dedup in v1 | **P10 census**, P5 |
| 0010 | Record classes; PERMIT optional | — |
| 0011 | Test strategy and adequacy (coverage matrix + evasion catalogue) | — |
| 0013 | Threat model: declared limits | — |
| 0014 | Cut line: "capture v1 is enough for Layer 3" | 0001–0013 |
