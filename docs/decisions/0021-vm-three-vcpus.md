---
status: accepted
date: 2026-11-05
owner: Ashish Rana
consulted: [VM kernel logs of 2026-11-04 (E-0088), maintainer's change of the VM to 3 vCPUs on 2026-11-04, maintainer's acceptance of 2026-11-05]
supersedes: ADR-0001, the "VM" row of its platform table (4 vCPU → 3 vCPU) only
---

# 0021: The VM runs with 3 vCPUs

## Context and problem statement

The VM (VirtualBox 7.2.22) runs on a laptop with 4 cores and 8 threads (i5-1135G7), under Windows with Hyper-V on, which ADR-0012 keeps as the everyday state. With 4 vCPUs, the guest reported soft lockups in its idle tasks of 23–198 s, and clock readouts of up to 214 s. One such stall froze the guest until it was powered off (E-0088).

**Question:** how many vCPUs does the target VM have?

## Decision drivers

1. The host must keep a core for Windows and Hyper-V, or the guest stalls.
2. Results must say which CPU count they were measured on (ADR-0012, ADR-0018).

## Considered options

1. 4 vCPUs (ADR-0001)
2. 3 vCPUs
3. Hyper-V off (reverses an ADR-0012 condition)

## Decision outcome

**Chosen:** option 2, 3 vCPUs. It leaves one core to the host and keeps the rest of the platform unchanged. `tools/vm/create-vm.ps1` builds the VM this way.

### Consequences

- Good: one core is left for the host.
- Bad: stalls still happen on 3 vCPUs: a 68 s soft lockup during a step that loads no BPF (E-0088). `vm_verify.sh` marks any step a stall touched, so a result taken through a stall is flagged, never used silently.
- Bad: earlier measurements (on 4 vCPUs) aren't comparable with later ones; each run's conditions record the CPU count.

### Confirmation

`nproc` prints 3 on the VM, and the WAL header's hostname and kernel identify the run.

### Falsifier

Reopen if stalls mark a step whose result we rely on as evidence, which would point to option 3; or if the host changes.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | Soft lockups of 23–198 s and clock readouts of up to 214 s on 4 vCPUs; a 68 s lockup on 3 | MEAS | E-0088, `docs/evidence/probes/2026-11-04-recursion-misses/README.md` |
| 2 | The host has 4 cores and 8 threads; the VM had 4 vCPUs | MEAS | maintainer's PowerShell output, 2026-11-04 (session) |
