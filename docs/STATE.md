# State

> The single source of truth for where the project stands. It is updated at the end of every working session, in the same PR as the work.

**Last updated:** 2026-10-25, PR #27 "bpf: the process spine and its load-time self-test" (VM run added)
**Phase:** 1, spine (starting). Phase 0 is closed for what the spine needs; its remaining items are scheduled before the phases that need them (audit §4).

## Phase 0 gate

| Item | Status | Evidence |
|---|---|---|
| Target VM built from a script, kernel pinned | ✅ done | [`00-vm-baseline.txt`](evidence/phase0/00-vm-baseline.txt), [`create-vm.ps1`](../tools/vm/create-vm.ps1), [runbook](runbooks/vm-setup.md) |
| P1: attach points exist (BTF + ftrace) | ✅ done | [`02`](evidence/phase0/02-p1-attach-points.txt), [`04`](evidence/phase0/04-p1b-fexit-check.txt) |
| P2: BPF features | ✅ done; `bpf_get_func_ret` (INF) and `bpf_d_path` from fexit (OPEN) need a real load | [`03`](evidence/phase0/03-p2-feature-probe.txt), [notes](evidence/phase0/README.md) |
| P3: LSM / lockdown | ✅ done | [`00`](evidence/phase0/00-vm-baseline.txt) |
| P4: clocksource | ✅ done | [`00`](evidence/phase0/00-vm-baseline.txt) |
| P5: disk bandwidth | ✅ done: min 63.7 MB/s, ±25 % under Hyper-V | [`05`](evidence/phase0/05-p5-disk.txt) |
| P6: argv source at exec | ✅ done: under a race, syscall-entry argv matched what ran 45/1000; `sched_process_exec` 1000/1000 (E-0049) | [P6/P8 runs](evidence/probes/2026-10-25-p6-p8/README.md) |
| P7: connect/accept hook layer | 🔧 partial: 64-bit connect/accept seen at `__sys_connect_file`/`do_accept` (E-0032). Not tested: 32-bit `socketcall`, io_uring connect/accept. Needed before Phase 3 (audit A1, E-0055) | [v2](evidence/census/2026-10-24T224617Z-v2/README.md) |
| P8: 32-bit compat I/O visible to fexit | ✅ done: both `int $0x80` and a real i386 program (vDSO entry) pass all 12 checks; `raw_syscalls` reports i386 ids with TS_COMPAT set (E-0050, E-0052) | [P6/P8 runs](evidence/probes/2026-10-25-p6-p8/README.md), [32-bit run](evidence/probes/2026-10-25-p8-32bit/README.md) |
| P9: io_uring completion path | 🔧 partial: io_uring bypasses vfs_read/write; `io_uring_complete` fires for fio (E-0027). Not tested: `CQE_SKIP`, `SQPOLL`. Needed before Phase 4 (audit A1, E-0055) | [v1](evidence/census/2026-10-24T221732Z-light/README.md) |
| **P10: event-rate census** | 🔧 v1 light set (E-0025/26); **v2: all 20 new hooks verified** (E-0032); rates varied 0.17-0.70x between runs from **host drift**, not from the hooks or concurrency (A/B serial E-0035, parallel E-0036). Tracing cost on fixed work: +13-30 %. Next: Hyper-V on/off + interleaved untraced baselines, then projected rates = untraced syscalls × selectivity | [v1](evidence/census/2026-10-24T221732Z-light/README.md), [v2](evidence/census/2026-10-24T224617Z-v2/README.md) |
| P11: Python wheels on 3.14 | ✅ done: every analysis package and its whole closure installs as binaries on 3.14.4; 33 packages with the CPU torch index, 52 (19 GPU) without (E-0053) | [P11 run](evidence/probes/2026-10-25-p11/README.md) |
| P12: untraced baselines | 🔧 Hyper-V A-B-A done (E-0038..41). Warm-up re-run (E-0043..45): warm-up fix works, but every row CV 12-29 %; same-state exec runs differ up to 3.3x, so the Hyper-V attribution is withdrawn (E-0044 corrects E-0038). Census probe slows `find` in every pair, size not measurable. **Overhead protocol decided (E-0046); to implement** | [A-B-A](evidence/baseline/2026-10-25-hyperv-ABA/README.md), [warm re-run](evidence/baseline/2026-10-25-hyperv-on-warm/README.md) |
| ADR process (ADR-0000, template, index) | ✅ done | `docs/decisions/` |
| Fresh journals: engineering log, research register | ✅ started | `docs/journal/`, `docs/research/` |
| ADRs the spine needs | ✅ accepted 2026-10-25: 0001 platform, 0002 toolchain, 0003 hook policy, 0006 transport, 0007 WAL, 0008 schema, 0009 process identity, 0012 quantification (E-0058) | [`docs/decisions/`](decisions/README.md) |
| Remaining ADRs: 0004 connect/accept, 0005 filtering, 0010 record classes, 0011 test adequacy, 0013 threat model, 0015 file identity, 0016 endpoint identity | ⏳ planned, each before the phase that needs it | [planned list](decisions/README.md) |
| ADR-0014: "capture v1 is enough for Layer 3" cut line | ⏳ open | — |
| CI skeleton | ✅ PR #15: ruff, all unit tests, evidence checksums, clang build + libbpf verifier load of an empty tp_btf/syscall program. veristat comes with the vendored libbpf (Phase 1) | [`ci.yml`](../.github/workflows/ci.yml) |
| Phase 0 audit | ✅ done: ready for the Phase-1 spine after its ADRs + CI; full gate not met | [audit](audits/2026-10-25-phase0.md) |

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
9. ✅ This PR: census v2 (META, NET intent, capability), known-ops self-check, attach pre-flight; VM run: all 20 hooks deliver (E-0032); the rate drop vs v1 is not caused by the v2 hooks (E-0035, correcting E-0033).
9a. ✅ Serial and parallel A/B: no large probe effect (+13-30 %); the census-to-census gap is host drift (E-0035, E-0036). Per-family bisection not needed now.
10. PR: service workloads (Nginx, Redis, kernel build).
11. ✅ Hyper-V A-B-A (P12) with `bench/baseline/`; results and warm-up fix in this PR.
12. ✅ Host state decided: Hyper-V on, relative numbers only (E-0042).
13. ✅ Warm-up re-run (this PR): no quotable overhead on this host with 3 rounds; new protocol decided (E-0046).
14. ✅ P6 done; P8 done for both `int $0x80` and a real i386 program (E-0050, E-0052); P11 done (E-0053).
14a. Optional: take VM snapshot `02-multilib` (the `gcc-multilib` install was not snapshotted).
15. ✅ Phase 0 audit ([audit](audits/2026-10-25-phase0.md)).
16. ✅ The spine's ADRs accepted (PRs #16–#23) and the CI skeleton merged (PR #15).
17. Before later phases: sizing projection and OPEN record size (Phase 2), P7 rest (Phase 3), P9 rest (Phase 4), overhead protocol implemented (Phase 6); re-capture the E-0022 diagnostic as a script (E-0056).
18. **Next, Phase 1 in single-purpose PRs:**
    1. ✅ build scaffolding: libbpf v1.7.0 and bpftool v7.7.0 submodules, `vmlinux.h` from the VM's BTF, Makefile; builds and attaches on the VM (E-0059..E-0062, PR #25);
    2. ✅ schema generator and the spine record types FORK/EXEC/EXIT/RENAME (ADR-0008, E-0063). The Python decoder with no defaults and the length checks comes with the WAL reader (step 5);
    3. ✅ spine BPF programs and the load-time self-test (ADR-0003, ADR-0009): pass in the dev container (E-0064) and **on the target VM**: 4 programs attached, self-test 21/21 twice, `reserve_failed` 0, `seen == emitted` (E-0065); other processes captured, EXEC inode matches `stat`, process end = EXIT with `group_dead=1`, which may be a non-leader thread (E-0066). [VM runs](evidence/build/2026-10-25-spine-vm/README.md). PR #26 + #27;
    4. `p15d` drain and WAL writer (ADR-0006, ADR-0007);
    5. Python WAL reader and process tree (process end = the EXIT with `group_dead=1`, E-0066; the device number needs converting from the kernel's encoding);
    6. L0–L4 tests and the Phase-1 gate run on the VM (knee ≥ 10× v3.7, oracle diff).

## Decisions taken (now recorded in ADRs where noted)

1. **libbpf:** vendor the latest 1.7.x tag (matches bpftool 7.7, which generates our skeletons). → ADR-0002 (v1.7.0). *(2026-10-25, E-0013)*
2. **Swap:** off only while measuring, recorded in each run's conditions. → ADR-0012. *(2026-10-25)*
3. **Hyper-V:** stays on; a paired on/off experiment decides later. → ADR-0012. *(2026-10-25)*
4. **Journals:** CSV in the repo. *(2026-10-25)*
5. **Measurement host state:** Hyper-V on (everyday safe state). Quote relative results only (overhead %, selectivity, loss, class mix, interleaved in one session); no absolute rates from this laptop. → ADR-0012. *(2026-10-25, E-0042)*
6. **Overhead protocol:** each round runs traced and untraced back to back, plus an A/A control arm (a second untraced run). Report the median and range of the per-round paired ratios, use at least 7 rounds, and claim an effect only above that run's own A/A noise floor. CV stays as a drift indicator only. → ADR-0012. *(2026-10-25, E-0046)*
7. **Census-probe overhead is no longer measured.** The next overhead number comes from the Phase-1 probe. → ADR-0012. *(2026-10-25, E-0047)*
8. **`gcc-multilib` is installed on the VM** after a snapshot, for P8's 32-bit variant. *(2026-10-25, E-0048)*
9. **Analysis-tier Python (Q-D3):** the VM's own Python 3.14 in a project venv, torch from the PyTorch CPU index; no 3.12 environment. Reopens if the first analysis code fails to import or run on 3.14. → ADR-0002. *(2026-10-25, E-0054)*
10. **ADRs 0001, 0002, 0003, 0006, 0007, 0008, 0009, 0012 accepted**, including the choices inside them: C daemon (Q-D2), revising D2 (Q-A2), TOML schema, CLOCK_BOOTTIME timestamps, kernel-native process identity, default ring-buffer wakeups, deferred shm ring, 1 s durability window, the timing quote rule. *(2026-10-25, E-0058)*
11. **PR #26 (schema) and PR #27 (spine) merged**; #27 accepted as one PR at 1,110 lines (the programs, their self-test and its tests are one checkable unit). VM snapshot `02-dev-deps` to be taken by the maintainer. *(2026-10-26, "all decisions are good to go", E-0066)*

## Decisions waiting

None open right now.
