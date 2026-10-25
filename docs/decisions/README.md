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
| [0006](0006-transport-two-bpf-ring-buffers.md) | Two BPF ring buffers (spine never shed, bulk counted), self-paced wakeups, one C drain thread | proposed | 2026-10-25 |

## Planned (from capture blueprint v1, §8.3)

These numbers are reserved. Each becomes a PR when its evidence is ready.

| ADR | Topic | Evidence needed first |
|---|---|---|
| 0001 | Platform: Ubuntu 26.04, GA kernel 7.0, pinned | phase-0 evidence 00/01 imported |
| 0002 | Toolchain: libbpf + CO-RE, C daemon, no BCC; which libbpf to vendor | phase-0 evidence 01 |
| 0003 | Hook policy: BTF-checked attach points, tracepoints preferred, load-time self-test | P1, P2 |
| 0004 | Connect/accept hook layer | P7 |
| 0005 | In-kernel filtering: who/what-kind only, no in-kernel dedup in v1 | **P10 census**, P5 |
| 0007 | Write-ahead log format and durability | P5, P10 |
| 0008 | Schema and versioning | — |
| 0009 | Identity model (process, file, endpoint incl. transport) | — |
| 0010 | Record classes; PERMIT optional | — |
| 0011 | Test strategy and adequacy (coverage matrix + evasion catalogue) | — |
| 0012 | Quantification protocol (runs, conditions, swap, Hyper-V) | P5, P12 |
| 0013 | Threat model: declared limits | — |
| 0014 | Cut line: "capture v1 is enough for Layer 3" | 0001–0013 |
