# State

> The single source of truth for where the project stands. It is updated at the end of every working session, in the same PR as the work.

**Last updated:** 2026-10-25, PR "tools: add VM creation script and runbook"
**Phase:** 0, ground truth (platform fixed and measured; decisions written as ADRs; no product code yet)

## Phase 0 gate

| Item | Status | Evidence |
|---|---|---|
| Target VM built from a script, kernel pinned | ✅ done | [`00-vm-baseline.txt`](evidence/phase0/00-vm-baseline.txt), [`create-vm.ps1`](../tools/vm/create-vm.ps1), [runbook](runbooks/vm-setup.md) |
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
3. ✅ Phase-0 evidence imported.
4. ✅ This PR: VM creation script and runbook.
5. PR: evidence-capture scripts under `tools/vm/` (closes the runbook's known gap).
6. PR: event-rate census harness (`bench/census/`). The maintainer runs it on the VM, and the results come back as evidence.

## Decisions taken, ADR still to write

1. **libbpf:** vendor the latest 1.7.x tag (matches bpftool 7.7, which generates our skeletons). Goes into ADR-0002. *(2026-10-25, E-0013)*
2. **Swap:** off only while measuring, recorded in each run's conditions. Goes into ADR-0012. *(2026-10-25)*
3. **Hyper-V:** stays on; a paired on/off experiment decides later. Goes into ADR-0012. *(2026-10-25)*
4. **Journals:** CSV in the repo. *(2026-10-25)*

## Decisions waiting

None open right now.
