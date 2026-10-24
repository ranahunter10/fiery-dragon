# State

> The single source of truth for where the project stands. It is updated at the end of every working session, in the same PR as the work.

**Last updated:** 2026-10-25, PR "docs: import phase-0 evidence"
**Phase:** 0, ground truth (platform fixed and measured; decisions written as ADRs; no product code yet)

## Phase 0 gate

| Item | Status | Evidence |
|---|---|---|
| Target VM built from a script, kernel pinned | ✅ done | [`00-vm-baseline.txt`](evidence/phase0/00-vm-baseline.txt) (script itself: next PR) |
| P1: attach points exist (BTF + ftrace) | ✅ done | [`02`](evidence/phase0/02-p1-attach-points.txt), [`04`](evidence/phase0/04-p1b-fexit-check.txt) |
| P2: BPF features | ✅ done; `bpf_get_func_ret` (INF) and `bpf_d_path` from fexit (OPEN) need a real load | [`03`](evidence/phase0/03-p2-feature-probe.txt), [notes](evidence/phase0/README.md) |
| P3: LSM / lockdown | ✅ done | [`00`](evidence/phase0/00-vm-baseline.txt) |
| P4: clocksource | ✅ done | [`00`](evidence/phase0/00-vm-baseline.txt) |
| P5: disk bandwidth | ✅ done: min 63.7 MB/s, ±25 % under Hyper-V | [`05`](evidence/phase0/05-p5-disk.txt) |
| P6: argv source at exec | ⏳ open | — |
| P7: connect/accept hook layer | ⏳ open | — |
| P8: 32-bit compat I/O visible to fexit | ⏳ open (needs `gcc-multilib`) | — |
| P9: io_uring completion path | ⏳ open (needs `liburing-dev`) | — |
| **P10: event-rate census** | ⏳ **next** | — |
| P11: Python wheels on 3.14 | ⏳ open | — |
| P12: untraced baselines | ⏳ open | — |
| ADR process (ADR-0000, template, index) | ✅ done | `docs/decisions/` |
| Fresh journals: engineering log, research register | ✅ started | `docs/journal/`, `docs/research/` |
| ADR-0001…0013 written and reviewed | ⏳ open | `docs/decisions/README.md` (planned list) |
| ADR-0014: "capture v1 is enough for Layer 3" cut line | ⏳ open | — |

Raw phase-0 evidence: [`docs/evidence/phase0/`](evidence/phase0/README.md), byte for byte with `SHA256SUMS`.

## Next step

1. ✅ Bootstrap merged (PR #1). The maintainer sets squash-only merging and protects `main` with a ruleset.
2. ✅ PR #2: ADR process and fresh journals.
3. ✅ This PR: phase-0 evidence imported.
4. PR: VM creation script (`tools/vm/create-vm.ps1`) and its runbook (`docs/runbooks/vm-setup.md`).
5. PR: event-rate census harness (`bench/census/`). The maintainer runs it on the VM, and the results come back as evidence.

## Decisions waiting

1. **libbpf version to vendor:** 1.6.3 (the distro's) or 1.7.x (what bpftool uses). Goes into ADR-0002.
2. **Swap during benchmarks:** off or on. Goes into the quantification-protocol ADR.
3. **Hyper-V during measurement runs:** on (current) or off. Settled by a paired experiment later.
