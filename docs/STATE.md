# State

> The single source of truth for where the project stands. It is updated at the end of every working session, in the same PR as the work.

**Last updated:** 2026-10-25, bootstrap commit
**Phase:** 0, ground truth (platform fixed and measured; decisions written as ADRs; no product code yet)

## Phase 0 gate

| Item | Status | Evidence |
|---|---|---|
| Target VM built from a script, kernel pinned | ✅ done | to be imported: `docs/evidence/phase0/00-vm-baseline.txt` |
| P1: attach points exist (BTF + ftrace) | ✅ done | `02-p1-attach-points.txt`, `04-p1b-fexit-check.txt` |
| P2: BPF features | ✅ done; `bpf_get_func_ret` to be confirmed by the first real load | `03-p2-feature-probe.txt` |
| P3: LSM / lockdown | ✅ done | `00-vm-baseline.txt` |
| P4: clocksource | ✅ done | `00-vm-baseline.txt` |
| P5: disk bandwidth | ✅ done: min ~64 MB/s, highly variable under Hyper-V | `05-p5-disk.txt` |
| P6: argv source at exec | ⏳ open | — |
| P7: connect/accept hook layer | ⏳ open | — |
| P8: 32-bit compat I/O visible to fexit | ⏳ open (needs `gcc-multilib`) | — |
| P9: io_uring completion path | ⏳ open (needs `liburing-dev`) | — |
| **P10: event-rate census** | ⏳ **next** | — |
| P11: Python wheels on 3.14 | ⏳ open | — |
| P12: untraced baselines | ⏳ open | — |
| ADR-0001…0013 written and reviewed | ⏳ open | `docs/decisions/` |
| ADR on the "capture v1 is enough for Layer 3" cut line | ⏳ open | — |

The phase-0 evidence files exist on the VM under `~/p15-evidence/` and in the ESE-P15 project notes (`EVIDENCE_00`, `EVIDENCE_01`). They will be imported into `docs/evidence/phase0/` by the first evidence PR.

## Next step

1. Merge the bootstrap. Then the maintainer protects `main` (see the bootstrap PR notes).
2. PR: ADR process (template, index, ADR-0000), plus the engineering log.
3. PR: import the phase-0 evidence, plus the VM creation script (`tools/vm/`) and its runbook.
4. PR: event-rate census harness (`bench/census/`). The maintainer runs it on the VM, and the results come back as evidence.

## Decisions waiting

1. **libbpf version to vendor:** 1.6.3 (the distro's) or 1.7.x (what bpftool uses). Goes into ADR-0002.
2. **Swap during benchmarks:** off or on. Goes into the quantification-protocol ADR.
3. **Hyper-V during measurement runs:** on (current) or off. Settled by a paired experiment later.
