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
| [0001](0001-platform-ubuntu-26-04-kernel-7-0-pinned.md) | Develop and measure on Ubuntu 26.04 LTS with the GA kernel 7.0.0-38, held | accepted; VM row superseded by 0021 | 2026-10-25 |
| [0002](0002-toolchain-libbpf-co-re-c-daemon.md) | Build with libbpf v1.7.0 + CO-RE skeletons and a C daemon; Python only after the WAL | accepted | 2026-10-25 |
| [0003](0003-hook-policy-btf-checked-attach-points-self-test.md) | Hook policy: BTF-checked attach points, the spine on `tp_btf` sched tracepoints, argv from the kernel's copy, and a per-pid load-time self-test | accepted; rule 1 superseded for exec, exit and rename by 0020 | 2026-10-25 |
| [0004](0004-network-intent-hooks.md) | Network intent: fexit on the IPv4/IPv6 proto_ops for connect, accept, listen and bind; one NET record on the bulk ring, keyed by socket cookie | accepted; rules 2 and 6 superseded in part by 0022 | 2026-11-05 |
| [0006](0006-transport-two-bpf-ring-buffers.md) | Two BPF ring buffers (spine never shed, bulk counted), self-paced wakeups, one C drain thread | accepted; rules 1 and 4 superseded by 0017, rule 3 by 0020 | 2026-10-25 |
| [0007](0007-wal-segmented-crc-batches-snapshot.md) | Write-ahead log P15W v1: segment files with a self-describing header, a process snapshot, CRC-checked batches, and fdatasync every second | accepted | 2026-10-25 |
| [0008](0008-schema-single-source-generated-layouts.md) | One schema file generates every record layout; per-type versions; a 32-byte common header on the boot clock | accepted | 2026-10-25 |
| [0009](0009-process-identity-tgid-leader-start-time.md) | Identify a process by (boot id, tgid, the thread-group leader's start_boottime) | accepted | 2026-10-25 |
| [0012](0012-quantification-protocol.md) | Quantification protocol: host-independent metrics first; relative timing only, by paired rounds with an A/A control | accepted; timing rules superseded by 0018 | 2026-10-25 |
| [0017](0017-spine-flood-resilience.md) | Spine flood resilience: exact-size records, a drain that never waits on disk, a raised drain priority, located loss, a measured headroom (supersedes ADR-0006 rules 1 and 4) | accepted | 2026-10-25 |
| [0018](0018-measurement-protocol-v2.md) | Measurement protocol v2: dimensionless headlines, rates against a same-host ceiling, paired timing reported with its raw costs, one shared workload set (supersedes ADR-0012's timing rules) | accepted | 2026-10-25 |
| [0019](0019-engineering-gates-daemon.md) | Engineering gates for the C daemon: typed boundaries, one error path, memory-safety checks, self-observability, module layout | accepted | 2026-10-25 |
| [0020](0020-kernel-skipped-events.md) | Events the kernel skips: spine exec/exit/rename on classic tracepoints, wake-ups only at a high-water mark, every skip (`recursion_misses`) counted and located (supersedes ADR-0003 rule 1 for those hooks, ADR-0006 rule 3; rule 6: daemon records in WAL ring 2) | accepted | 2026-11-05 |
| [0021](0021-vm-three-vcpus.md) | The VM runs with 3 vCPUs (supersedes ADR-0001's VM row) | accepted | 2026-11-05 |
| [0022](0022-exact-client-join-tcp-isn.md) | Join a TCP client to its accept by the client's initial sequence number (NET v2; supersedes ADR-0004 rules 2 and 6 in part) | accepted | 2026-11-05 |
| [0023](0023-lifecycle-reconciliation.md) | Reconcile the process tree against a closing snapshot | accepted | 2026-11-05 |
| [0024](0024-snapshot-taking-and-closing-window.md) | How the process snapshot is taken (the path from the pinned mapping, books that close, the closing snapshot on the writer thread, END v2) and the closing snapshot's window (supersedes ADR-0023 rule 2 in part) | accepted | 2026-11-06 |
| [0025](0025-code-provenance-exec-v2.md) | Code provenance on EXEC and PROC: the executable's own facts, credentials, `self_exec_id` and fds 0-2 (EXEC v2, PROC v2) | accepted | 2026-11-06 |

## Planned (from capture blueprint v1, §8.3)

These numbers are reserved. Each becomes a PR when its evidence is ready.

| ADR | Topic | Evidence needed first |
|---|---|---|
| 0005 | In-kernel filtering: who/what-kind only, no in-kernel dedup in v1 | **P10 census**, P5 |
| 0010 | Record classes; PERMIT optional | — |
| 0011 | Test strategy and adequacy (coverage matrix + evasion catalogue) | — |
| 0013 | Threat model: declared limits | — |
| 0014 | Cut line: "capture v1 is enough for Layer 3" | 0001–0013 |
| 0015 | File identity (device, inode, generation; kernel-resolved path) — split from 0009 | Phase 2 start |
| 0016 | Network-endpoint identity, transport included — split from 0009 | P7 rest, Phase 3 start |
