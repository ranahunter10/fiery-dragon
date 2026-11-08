# State

> The single source of truth for where the project stands. It is updated at the end of every working session, in the same PR as the work.

**Last updated:** 2026-11-05 (UTC), PR "snapshot: the process snapshot at every segment open, the closing snapshot and the reconciliation (step 4c, ADR-0023)"
**Phase:** 1, spine (starting). Phase 0 is closed for what the spine needs; its remaining items are scheduled before the phases that need them (audit §4).

## Resuming a session (read this first, then stop reading)

So that no session re-reads the repo to find its place (the maintainer's request, 2026-11-02; the idea borrowed from Graphify, without installing it):
1. This file: **Next step** (the demo track, §19) and **Decisions waiting**.
2. [`docs/CODEMAP.md`](CODEMAP.md): one row per source file (its job and public names). Open a file only when its row says it is the one.
3. The ADRs the task names, nothing else. The research notes are for decisions, not for every session.
4. Open PRs: `gh api 'repos/ranahunter10/fiery-dragon/pulls?state=open' --jq '.[]|"#\(.number) \(.head.ref) \(.title)"'`. Stacked PRs say "Stacked on #N" in their first line.
5. CI logs can be fetched: `gh api repos/ranahunter10/fiery-dragon/actions/jobs/<job id>/logs`.
6. Facts that cost a round trip to learn:
   - the dev container can't load fentry/fexit (E-0078); CI's runner (7.0.0-1017-azure) and the VM can;
   - CI runs on pull requests and on `main` only, so a pushed branch without a PR has no CI;
   - `pkill -f <pattern>` can match your own shell command: kill by PID;
   - the dev container's kernel never shows pid 1 to a task iterator (E-0105; the VM and CI do): run `it_p15d.sh` there with `P15_IT_PID1=0`;
   - the VM's `/tmp` is a tmpfs with a per-user quota: a test killed mid-write leaves its files there (E-0107);
   - measure on the VM with the host on its charger, in Best performance mode: on battery it ran about 2-4 times slower (E-0108).

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
    4. `p15d` drain and WAL writer (ADR-0006, ADR-0007), in three PRs:
       1. ✅ the P15W v1.0 format spec and the C writer: batches with CRC32C, rotation, `fdatasync` interval, torn-tail recovery (E-0068, PR #28);
       2. `p15d`: drain both rings into batches, header metadata (boot_id, hooks, self-test, versions), daemon records (clock sync, stats), the accounting invariant at shutdown. Per ADR-0017/0019, also: exact-size EXEC, the writer thread and queue, the drain priority, GAP records, STATS, canary, one error path. A stack of single-purpose PRs:
          1. 🔧 ADR-0019 G2/G3 on the existing code: `P15_MUST_CHECK` on every fallible function (an ignored result fails the build, gcc and clang), the hardening and warning flags (checked in the binary), `daemon/exitcodes.h`, the exit-call check (E-0074). In review;
          2. 🔧 exact-size EXEC records (ADR-0017 layer 1): built in per-CPU scratch, `bpf_ringbuf_output` of `len`; the self-test (now 22 checks) fails if any record's ring size is not its `len`; `p15_rec_check` refuses slack and stale bytes; `bpf_stats` harness for the three ways (E-0075, E-0076). In review;
          3. 🔧 the daemon records CLOCK_SYNC (32), STATS (33), GAP (34), END (35) in the schema, version 1, each field tied to an ADR line; the schema hash for the WAL header; `p15_rec_check` knows them and requires fixed-size records to have exactly their size (E-0077). In review;
          4. the bounded SPSC batch queue, under ThreadSanitizer;
          5. `p15d` itself: loader, drain, writer, stats, config, the run state machine, `p15_fail`, and the L4 tests (forced overflow, drain stall);
       3. 🔧 the process snapshot at each segment open, and the closing one at an orderly stop (ADR-0007 rule 3, ADR-0023; how it is taken: ADR-0024, accepted 2026-11-06). Built and verified on the VM (E-0107): 18 of 18 steps pass, every snapshot is complete with its books closed, every user process has its path, pid 1 included. Case 1 and a live run reconcile complete; case 3 locates 10 lost EXITs within the 320 counted. A snapshot takes 0.21–0.91 ms for about 165 tasks;
    5. Python WAL reader (generated, no defaults, `google-crc32c`), the P15R importer for v3.7 recordings, and the process tree (process end = the EXIT with `group_dead=1`, E-0066; the device number needs converting from the kernel's encoding);
    6. L0–L4 tests and the Phase-1 gate run on the VM (knee ≥ 10× v3.7, oracle diff).
19. **Demo track (maintainer, 2026-11-02): "given a port, show what happened".** It pulls a network-intent slice of Phase 3 forward. Nothing here is demo-only: each item is a Phase-1 or Phase-3 deliverable.
    1. ✅ ADR-0004 (accepted 2026-11-05): fexit on the IPv4/IPv6 proto_ops for connect, accept, listen and bind; a NET record on the bulk ring, keyed by socket cookie. The probe passes on the CI runner's 7.0.0-1017-azure (E-0079); the VM run is pending. PR #35;
    2. 🔧 `p15d` (step 4b PRs 4–5 in one): the SPSC queue, drain and writer threads, WAL header, STATS/CLOCK_SYNC/GAP/END, run state and invariant, textfile, strict config; `p15w-inspect`. The end-to-end test passes all 4 cases in the dev container, including the forced overflow (INVALID with GAP records, books closed); 17/17 planted bugs caught (E-0080). Not yet: the drain-stall test, the bulk ring (with item 3);
    3. 🔧 NET (type 5) and NET_STATS (36) in the schema; `bpf/progs/net.bpf.c` on the bulk ring; the network self-test at load (ADR-0004 rule 6); `p15d` drains both rings, NET loss makes the run DEGRADED, the invariant covers NET; `--no-net` for hosts without fentry/fexit, recorded in the header. Container: the end-to-end test passes with `--no-net`; the network case runs in CI (`P15_IT_NET=1`) and on the VM. Depends on ADR-0004 being accepted;
    4. the Python WAL reader (step 5) and process tree, then `p15-trace --port N`: listeners, accepted connections (joined by cookie), outbound connects, each with its process lineage; text output and a self-contained HTML report.
       1. 🔧 the reader: `python/p15/wal.py` and `records.py`, with packages pinned by hash. It decodes a C-written run of all 10 types field by field, and its counts equal p15w-inspect's on every end-to-end run. 31 unit tests pass and 71/71 planted bugs are caught (E-0084). PR #39;
       2. 🔧 `p15-trace --port N` (`tools/p15-trace`): the process tree (ADR-0009 keys, `group_dead`, pre-existing processes and GAP windows flagged, never guessed), listeners and accepts joined by cookie (exact), clients joined by endpoints (an inference, labelled), refused connects, a text report and a self-contained HTML one. 22 tests and 93/93 planted bugs on a synthetic run (E-0085); `it_p15d.sh` case 5 runs it on a real capture in CI and keeps the run as an artifact. PR #40. Next: the VM run, then the demo scenario (item 5);
    5. 🔧 a scripted demo scenario on the VM, with evidence, plus rehearsal notes. `tools/demo/run_demo.sh` plays the story on loopback: a catcher on 4444; a web app with a command-injection bug on 8080; ordinary requests; one injected `nc` to 4444; a scan of closed ports. It then runs p15-trace on 8080, 4444 and 4442. [Rehearsal notes](demo/README.md). The container dry run (spine only) captured the chain `nc ← sh ← python3 webapp` (E-0087). PR #41. Next: the VM run, with NET (maintainer).

20. **Events the kernel skips (E-0088 to E-0090; ADR-0020, accepted 2026-11-05).**
    - **Found on the VM:** on 7.0, the kernel's per-CPU recursion guard skips our `tp_btf` spine programs for other tasks, while our books still close. It skipped 3.3 % of EXEC and 3.9 % of EXIT in a 2,000-exec burst. The fix was chosen from 7 designs measured on the VM (PR #42).
    - 🔧 **ADR-0020** (PR #43) and its implementation (PR #44):
      - exec, exit and rename on classic tracepoints; fork stays on `tp_btf`;
      - records wake the drain only above a quarter of the ring, and the drain polls every 10 ms;
      - STATS, GAP and NET_STATS v2 carry `recursion_misses`; a spine skip makes the run INVALID with a GAP, a network skip makes it DEGRADED;
      - p15-trace's Trust block shows the skips;
      - the end-to-end test waits for `code=start` and counts exactly.
    - ✅ **ADR-0021** (accepted 2026-11-05): the VM has 3 vCPUs.
    - ✅ **ADR-0020 accepted 2026-11-05**, after its confirmation 5 on the VM (E-0101): the classic path costs +49.4 ns per event against `tp_btf` (9.8–72.4 ns), and nothing resolves per exec, where an exec costs about 4.85 ms of CPU.
    - **VM run of PR #44 (E-0092):** 16 of 17 steps pass.
      - The probe, rerun: classic tracepoints skip 0 of 2,000 in every round.
      - p15d: all 200 children's EXECs are in the WAL, with 0 kernel skips.
      - The demo passes.
      - Step 14 failed only in case 5, a p15-trace bug. On the VM an ACCEPT was stamped 12 µs before its own CONNECT, and the join took only earlier connects.
    - 🔧 **The join fix** (PR #45): the connect nearest in time on either side, within 5 s (a heuristic bound). Matches whose connect came after the accept are counted. Container: 100/100 planted bugs caught.
    - **VM rerun from step 14 on #45 (E-0093):** steps 14–17 pass, so every step of `vm_verify.sh` has now passed on the stack #32–#45.
    - **The failing run's segment** is in the evidence. Re-read by the fixed p15-trace on the VM, it gives 2 of 2 clients, 1 of them with its connect after the accept (E-0094). In the container, both the bug and the fix reproduce from the file (E-0095).
    - **Next:**
      - ✅ merged #32–#46 with merge commits, in order (2026-11-05); `main`'s tree is byte-identical to #46's head;
      - ✅ ADR-0018's statistics as code, the hook-cost harness and its VM run (#48, #49): ADR-0020 accepted;
      - ✅ ADR-0022 (PR #52; CI and the VM join both clients exactly, E-0104): NET v2 with the client ISN, and the exact join in p15-trace (CI case 5 and the VM confirm it);
      - ✅ step 4c, the opening snapshot (ADR-0007), with ADR-0023's closing snapshot and reconciliation: built (E-0106) and verified on the VM (E-0107);
      - 🔧 EXEC v2 and PROC v2, carrying `self_exec_id` (ADR-0020 rule 5) and the code-provenance facts of ADR-0025 (proposed): the load-time self-test checks every new fact against `stat`/`statfs`/`fstat` and found the ctime flag bit (E-0111); VM self-test and 14/14 planted bugs (E-0112, E-0115); the removed build ways' VM cost (E-0114); end-to-end case 6 in the container (E-0116), CI and the VM (E-0117). PR #56 (ADR-0025 accepted 2026-11-06);
      - 🔧 **ADR-0026** (proposed): the counters are an mmapable array, and p15d makes no map syscall once a program is attached; built and passing in the container, CI and on the VM (E-0119 to E-0121, E-0123); a guest kernel oops cut off the first VM sweep, INF host-side, open (E-0122). PR #57. Next: the maintainer's acceptance and the merge;
      - then slice B (STATE decisions taken 15.5);
      - then the demo.

21. **Hardening from the 2026-11-05 research** (state-of-the-art tools, the kernel source, other fields; [research note](research/2026-11-05-sota-and-cross-domain.md)):
    - ✅ **Atomic BPF counters** (PR #47, E-0097). The six network fexit programs shared per-CPU counter slots with a plain `*v += 1`, and on 7.0 they run preemptible with a per-program recursion guard, so a count could be lost silently. Found by checking our code against the pattern of CVE-2026-89580.
    - ✅ **ADR-0018's statistics as code** (PR #48, E-0098): `bench/quant/paired.py`, tested against enumeration, the textbook tables and scipy. The tool ADR-0020's confirmation 5 needs.
    - ✅ **The hook-cost harness** (PR #49, E-0099): `make bench-hook-cost`, the same trivial body on a classic tracepoint and on `tp_btf`, plus the shipped spine EXEC. Container (not the target): classic costs +13.9 ns per rename event against `tp_btf` (0.15 null syscalls); at exec level nothing resolves. **VM (E-0101): +49.4 ns per rename event (9.8–72.4 ns, p = 0.017); per exec, not resolved. `vm_verify.sh` passes all 18 steps on #47–#49.**
    - ✅ **ADR-0022 accepted 2026-11-05** — ✅ built in PR #52 (E-0103, VM E-0104): an exact client join by the TCP initial sequence number (NET v2), instead of the 5 s time window.
    - ✅ **ADR-0023 accepted 2026-11-05** — 🔧 built with step 4c (E-0106): reconcile the process tree against a closing snapshot, so each lost FORK or EXIT is located to its process, and a lost FORK repaired. p15-trace's Trust block shows the verdict.

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
11. **PR #26 (schema) and PR #27 (spine) merged**; #27 accepted as one PR at 1,110 lines (the programs, their self-test and its tests are one checkable unit). VM snapshot `02-dev-deps` to be taken by the maintainer. *(2026-10-25 UTC, "all decisions are good to go", E-0066)*
12. **ADR-0017, 0018 and 0019 accepted** (spine flood resilience; measurement protocol v2 with the Phase-1 gate at ≥ 50 % of the same-host ring-buffer ceiling if v3.7 can't run on 7.0; engineering gates). With them, also accepted:
    - the P15R importer joins Phase 1, and caps-minimal moves to Phase 4;
    - no self-hosted CI runner for now;
    - the two P15W spec refinements of PR #28;
    - `google-crc32c`, pinned, with no fallback, for the Python reader;
    - the research note's Phase-2 inputs go into ADR-0005, 0010 and 0013 as considered options.

    PRs #28–#30 merged. *(2026-10-25 UTC, "accepted and merged", E-0072)*

13. **The 2026-11-05 review** (maintainer: "do the recommended items"; merge method and branch clean-up chosen in the session):
    1. **Exit codes:** sysexits(3) values where one fits (USAGE 64, CONFIG 78, IO 74, OSERR 71, INTERNAL 70, LOAD 69, SELFTEST 65); DEGRADED 3 and INVALID 4; 0 only for a valid run. *(E-0074)*
    2. **Allowed exit sites** are marked in place with `exit-ok: <reason>`, every marked site printed in CI. *(E-0074)*
    3. **Hardening flags** apply to every userspace binary, the BPF test loaders and the C tests included.
    4. **EXEC takes its exact `len` by `output`** (per-CPU scratch, then `bpf_ringbuf_output`). The `fixed` and `dynptr` ways leave `spine.bpf.c` with EXEC v2 (ADR-0025 rule 8). The VM repeat holds the choice: `output` against `fixed` not resolved, `dynptr` dearer. *(E-0076, E-0114)*
    5. **Stricter EXEC checks** in `p15_rec_check`: exact padded `len` unless `READ_FAILED`, zero bytes after the fields. *(E-0075)*
    6. **Daemon-written records in WAL ring 2**, recorded as ADR-0020 rule 6.
    7. **STATS shape:** cumulative counters, four per-interval maxima with `interval_ns`; daemon record types from 32.
    8. **ADR-0004 accepted** (network intent).
    9. **Analysis-tier packages pinned by hash**, binary wheels only, for CPython 3.13 and 3.14 on x86-64; the list grows with the analysis tier.
    10. **The client join's time rule:** the connect nearest in time on either side of the accept, within 5 s; kept in code and here, no ADR. *(E-0092 to E-0095)*
    11. **ADR-0020:** accepted in principle; the status changes once its confirmation 5 is measured, as the ADR itself requires. Measured on the VM and accepted the same day (E-0101).
    12. **ADR-0021 accepted** (3 vCPUs; supersedes ADR-0001's VM row).
    13. **Merge #32–#46 with merge commits**, never squash: evidence cites commit hashes, and merge commits keep them in `main`. `CONTRIBUTING.md` now says so. Merged branches whose tips are in `main` are deleted.

14. **The second 2026-11-05 review** (maintainer: "all the recommended decisions are accepted"):
    1. **#47–#51 merged** with merge commits, in order.
    2. **ADR-0022 accepted:** join a TCP client to its accept by the client's ISN (NET v2). To build next.
    3. **ADR-0023 accepted:** reconcile the process tree against a closing snapshot. To build after step 4c.
    4. **The 7.0 recursion-miss finding goes upstream** (bpf@vger.kernel.org), drafted in the session; the maintainer sends it under his name.
    5. **From now on, a decision is asked in the message where it arises**, not collected into an end-of-session list.

15. **The 2026-11-06 review** (maintainer: "accepted recommended decisions"):
    1. **ADR-0025 accepted:** code provenance on EXEC v2 and PROC v2. *(E-0118)*
    2. **Socket → NET join deferred** to the data-flow slice, where `bpf_get_socket_cookie` is allowed. *(E-0118)*
    3. **Standard streams in PROC v2 deferred.** *(E-0118)*
    4. **#56 merged** with a merge commit at its tested head.
5. **Slice B's plan** (maintainer, 2026-11-06: "accept recommended"): first the counter fix (ADR-0026), then a VM probe that measures fexit, kprobe+kretprobe and kprobe.session on the read/write paths (skips against a known count, cost, workload slowdown) and the path hook at open; then ADR-0015 (file identity) and ADR-0005 (filtering, Xu et al.'s merge rule read in the paper first) with those numbers; then the code. Scope as recommended; how PIDSMaker sees the code-provenance edges is deferred to the graph phase. Research: [`research/2026-11-06-dataflow-slice-b/`](research/2026-11-06-dataflow-slice-b/README.md) (on its branch). *(E-0119)*

## Decisions waiting

None.
