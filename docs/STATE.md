# State

> The single source of truth for where the project stands. It is updated at the end of every working session, in the same PR as the work.

**Last updated:** 2026-10-25, PR "bench/census: v2 classes, known-ops self-check, attach pre-flight"
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
| **P10: event-rate census** | 🔧 v1 light set (E-0025/26); **v2: all 20 new hooks verified** (E-0032); rates are lower bounds because the probes slow the workloads (E-0033). Next: A/B bisection + untraced baseline, then projected rates = untraced syscalls × selectivity | [v1](evidence/census/2026-10-24T221732Z-light/README.md), [v2](evidence/census/2026-10-24T224617Z-v2/README.md) |
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
4. ✅ VM creation script and runbook.
5. PR: evidence-capture scripts under `tools/vm/` (closes the runbook's known gap).
6. ✅ Census probe + summarizer, validated on the VM.
7. ✅ Census workload runner + light workloads.
8. ✅ Light set run on the VM; results in `docs/evidence/census/2026-10-24T221732Z-light/`.
9. ✅ This PR: census v2 (META, NET intent, capability), known-ops self-check, attach pre-flight; VM run: all 20 hooks deliver (E-0032), and the probe set slows workloads 1.4-6x (E-0033).
9a. PR: probe-overhead A/B bisection (untraced / v1 / v2 / v2 minus each family) on fixed work, which is also P12's untraced baseline.
10. PR: service workloads (Nginx, Redis, kernel build).
11. P12 untraced baselines + Hyper-V on/off paired run (E-0029).

## Decisions taken, ADR still to write

1. **libbpf:** vendor the latest 1.7.x tag (matches bpftool 7.7, which generates our skeletons). Goes into ADR-0002. *(2026-10-25, E-0013)*
2. **Swap:** off only while measuring, recorded in each run's conditions. Goes into ADR-0012. *(2026-10-25)*
3. **Hyper-V:** stays on; a paired on/off experiment decides later. Goes into ADR-0012. *(2026-10-25)*
4. **Journals:** CSV in the repo. *(2026-10-25)*

## Decisions waiting

None open right now.
