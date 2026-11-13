# State

> The single source of truth for where the project stands. It is updated at the end of every working session, in the same PR as the work.

**Last updated:** 2026-11-13 (UTC), PR "bench: stall detection in the soak and the matrix" (decision waiting 26)
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
   - the VM's host can stop the guest for minutes (E-0088, E-0250): `summary.md`'s Stalls section names every matrix step a stall touched, and the soak's report says STALL; those steps' rates are not quotable (E-0252).

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
      - 🔧 **ADR-0026** (proposed): the counters are an mmapable array, and p15d makes no map syscall once a program is attached; built and passing in the container, CI and on the VM (E-0119 to E-0121, E-0123); a guest kernel oops cut off the first VM sweep, INF host-side, open and watched (E-0122). Accepted 2026-11-08, #57;
      - ✅ **slice B, step 1 (design):** ADR-0015 (file identity) and ADR-0005 (filtering and aggregation) accepted 2026-11-10, with the design checks they rest on ([note](research/2026-11-09-slice-b-design-checks.md), E-0126 to E-0140); 🔧 next, step 2a (item 22);
      - then the demo.

21. **Hardening from the 2026-11-05 research** (state-of-the-art tools, the kernel source, other fields; [research note](research/2026-11-05-sota-and-cross-domain.md)):
    - ✅ **Atomic BPF counters** (PR #47, E-0097). The six network fexit programs shared per-CPU counter slots with a plain `*v += 1`, and on 7.0 they run preemptible with a per-program recursion guard, so a count could be lost silently. Found by checking our code against the pattern of CVE-2026-89580.
    - ✅ **ADR-0018's statistics as code** (PR #48, E-0098): `bench/quant/paired.py`, tested against enumeration, the textbook tables and scipy. The tool ADR-0020's confirmation 5 needs.
    - ✅ **The hook-cost harness** (PR #49, E-0099): `make bench-hook-cost`, the same trivial body on a classic tracepoint and on `tp_btf`, plus the shipped spine EXEC. Container (not the target): classic costs +13.9 ns per rename event against `tp_btf` (0.15 null syscalls); at exec level nothing resolves. **VM (E-0101): +49.4 ns per rename event (9.8–72.4 ns, p = 0.017); per exec, not resolved. `vm_verify.sh` passes all 18 steps on #47–#49.**
    - ✅ **ADR-0022 accepted 2026-11-05** — ✅ built in PR #52 (E-0103, VM E-0104): an exact client join by the TCP initial sequence number (NET v2), instead of the 5 s time window.
    - ✅ **ADR-0023 accepted 2026-11-05** — 🔧 built with step 4c (E-0106): reconcile the process tree against a closing snapshot, so each lost FORK or EXIT is located to its process, and a lost FORK repaired. p15-trace's Trust block shows the verdict.

22. **Completing the capture layer, then the graph (maintainer, 2026-11-09).** One PR per step, in order; research before each design; each decision raised when it arises:
    1. ✅ slice B design: ADR-0015 and ADR-0005 accepted (PR #59; E-0139, E-0140); the read-path hook costs measured (PR #60, merged 2026-11-10, E-0138);
    2. slice B code, in five PRs (N2, E-0139), each with schema records, BPF programs, loader wiring, daemon checks and formatters, the Python decoder and report, load-time self-test checks, an `it_p15d.sh` case and mutation sweep entries:
       1. 🔧 2a identity: OPEN, OPEN_VERDICT, FD (the snapshot's pass), BACKING, CLOSE (FILE moves to 2b, decision 19.5); kprobe.session + fentry on `security_file_open`, kprobe.multi on `security_file_free` and `security_inode_free`. ✅ dry run on the VM (PR #61, E-0146); ✅ part 1, the records and ADR-0027 (PR #62, E-0148); ✅ part 2, `bpf/progs/file.bpf.c` with the loader, `p15_rec_check`, the self-test, FILE_STATS and `it_p15d.sh` case 8 (PR #63; on the VM every case passes and the p15d sweep kills 42/42, E-0156 to E-0159); ✅ part 3: the snapshot's FD pass (`iter/task_file` in `file.bpf.c`), SNAP_DONE v2 with its books, a facts epoch per segment, `it_p15d.sh` case 9 (PR #64; on the VM every case passes and the p15d sweep kills 45/45, E-0160, E-0161). **Step 2a done.**
       2. 2b transfers, unfolded, and FILE: read/write/readv/writev (kprobe.session) and the socket tracepoints, one FLOW per call, the books and FLOW_STATS; **gate:** the pipeline's zero-loss ceiling on the VM (N3) and skips under contention (decision 17);
          🔧 part 1, the records: FLOW (type 10) and FILE (type 11), their checks in `p15_rec_check` and the Python decoder, `[[enum]]` in the generator (PR #88, E-0226; its matrix passed on the VM, E-0234); the design checks for the programs ([note](research/2026-11-12-step-2b-design-checks.md), E-0227). 🔧 part 2, the dry run: `bench/flow_cost` measures decision waiting 13's options on the VM (PR #89, E-0235; the note's §4 items 2 and 3); the coverage probe (§4 item 1) and the contention run (item 4) follow it. Then part 3, the programs with FLOW_STATS, the self-test and an `it_p15d.sh` case, then part 4, the ceiling and contention gate.
       3. 2c folding (ADR-0005 rules 4-12) and `python/p15/cpr.py`; its default from 2b's number (N7);
       4. 2d splice, sendfile, copy_file_range, tee, vmsplice (the system call for the pipe-to-user side), mmap at map time, rename/unlink/link/truncate;
       5. 2e io_uring completions (with the overflow and skip counts) and NET v3 with the socket's object id;
       the kernel's internal I/O and per-access mapped I/O are declared out of scope;
    3. slice C: memory made executable (ADR, records, tests);
    4. slice D: writes into another process's memory;
    5. slice E: new kernel code and carriers (module and BPF program loads, setxattr);
    6. the overhead of the full capture on ordinary workloads, on the VM (ADR-0018);
    7. the graph: a DuckDB star schema and builder (with the reader's trust table of ADR-0015 and the table of devices that carry no data flow, terminals split per session, N4), FD on a copy as REO + RNO with the cycle collapse and SD as options (N6; the WAL is never reduced), an offline one-page HTML view of a run, then the PIDSMaker export (where PIDSMaker runs is the maintainer's decision).

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

16. **The 2026-11-08 review** (maintainer: "recommended decisions are accepted"):
    1. **ADR-0026 accepted** (counters read through a mapping, no map syscall after attach), and #57 merged. *(E-0125)*
    2. **#58 merged:** the slice B research note.
    3. **The guest kernel oops of E-0122 stays open and is watched** (kdump stays on); no control run and no host change for now. *(E-0125)*

17. **The 2026-11-09 session brief** (maintainer): slice B hooks the read/write paths with kprobe.multi + kretprobe.multi (preemption off, not skipped for another task through nesting; fexit can be, E-0089/E-0090); their skips (`recursion_misses`, the link's `kprobe_multi.missed`) and cost are measured in slice B's own tests, which replaces 15.5's separate VM probe; Xu's rule is read in the paper before ADR-0005 states it. Deferred: the stdio socket → NET join, stdio in PROC v2, and how PIDSMaker sees code-provenance edges. The branch `probe/rw-hooks` is unused. *(E-0126)*
18. **Slice B design decisions (maintainer, 2026-11-09, "accept all recommendations").** kprobe.session for every entry/return pair; keep decision 17 although a session costs 118 ns per call more than fexit on the VM (E-0138), and measure skips under contention in 2b; NET v3 in 2e; the reader's trust table; `SUBVOL_UNKNOWN`; one record per open (N1); the closing sweep on the fdatasync tick with the slot emptied and the stop order stated; conservative folding near mappings; the run-state rule; no offsets in FLOW; failed and empty transfers counted; step 2 in five PRs (N2); the ceiling gate at 2b (N3); the device table in the graph step (N4); FD downstream on a copy (N6); the folding default set after 2b (N7). Recorded in ADR-0015 and ADR-0005's decision sections. *(E-0139)*

19. **Step 2a implementation decisions (maintainer, 2026-11-10, "all recommendation accepted"; E-0143).**
    1. Record numbers: OPEN 6, OPEN_VERDICT 7, BACKING 8, CLOSE 9, FILE 10; FD 39 (MARKER), FILE_STATS 40 (STATS).
    2. Object facts: an optional fixed-size tail (a generator-checked schema `part`) on OPEN and BACKING, present only with `OBJ_NEW`; fixed fields on FD.
    3. Slice B flags in a record field (`fflags`); opens are not filtered; a kernel thread's OPEN carries KTHREAD.
    4. One bulk ring for NET and slice B, owned by `bpf/progs/file.bpf.c` and reused by NET; `--no-files`; a test-only switch leaving the path fentry unattached; the identity counters in a map of their own (ADR-0026 rows, named slots).
    5. FILE moves to 2b; in 2a an unregistered free is counted `free_unregistered`.
    6. Maps preallocated: objects 131,072, open files 65,536, configurable and in the WAL header; FILE_STATS reports live entries and high-water (E-0142).
    7. An object's facts are marked written only after the record carrying them is submitted; a race may write them twice, counted `facts_dup`, never zero times (E-0141).

20. **The 2026-11-10 review** (maintainer: "recommendation and decision passed"; E-0147): merge #60, then #59, then #61, with merge commits; **ADR-0027:** on the anonymous-inode filesystem (magic `0x09041934`) the graph node is the open file (`fid`), not the object, superseding ADR-0015 rule 3 for that filesystem only; written in 2a's PR.

21. **The 2026-11-10 review, second motion** (maintainer: "motion passed"; E-0149): PR #62 merged; step 2a in three PRs (part 1 records, part 2 programs, part 3 the FD pass).

22a. **Standing acceptance (maintainer, 2026-11-10, E-0153):** "recommended decisions are accepted in advance ... I will review them once everything is stitched". Each decision is still recorded here with its evidence when it is taken, for that review. Not covered, and still asked first: anything that cannot be undone, GPL-2.0-only code, and where PIDSMaker runs. Taken under it:
    1. Kernel threads' opens are kept, flagged KTHREAD; their share is measured in step 6 (E-0150).
    2. **Facts epoch** (E-0151): an object's facts are written once per epoch; p15d starts a new epoch after its load-time self-tests, whose reader discards what it takes.
    3. **Graph v0 before 2b** (E-0153): after 2a part 3, the DuckDB schema, builder and PIDSMaker export are built on the records that exist (FORK, EXEC, EXIT, OPEN with its access mode, CLOSE, FD, NET), so the path from capture to a detection number runs end to end early; 2b-2e then replace open-level file edges with measured transfers. The step 7 options (FD on a copy, the HTML view) stay in step 7.
    4. **The cost of an open under capture is measured next to part 3** (a paired open/close microbenchmark with p15d on and off, ADR-0012's protocol), the first whole-pipeline number.

23. **Taken under 22a for step 2a part 3** (E-0160):
    1. The FD pass's iterator lives in `file.bpf.c` (it shares the open-file and object maps, so an FD row and a later OPEN name one id); its books go in SNAP_DONE v2, as ADR-0015 rule 7 says; a lost or invalid FD row makes the snapshot incomplete and the run INVALID, as for PROC.
    2. The FD pass runs in every snapshot, opening and closing; each opening snapshot starts a new facts epoch first, so every segment carries the facts of each object it names, an OPEN's as much as an FD row's (ADR-0007's self-describing segments).

24. **The bounded stop, taken under 22a** (E-0162): the stop gives up when the writer makes no progress (its beat counter does not move) for `--stop-stall-s`, default 30 s, counted in observations at least 100 ms apart so a host freeze of the guest is one observation; p15d then detaches, logs `code=stuck` with the phase, and exits 75 (STUCK, new in `daemon/exitcodes.h`) without END. Defaults: 30 s (a WAL fdatasync on a slow disk under load fits), the snapshot's batches count as progress.

25. **Graph v0, taken under 22a** (E-0165, ADR-0028): raw tables generated from `schema/records.toml` into DuckDB 2.0.0 (pinned); the graph built in SQL over them (`python/p15/graph/graph.sql`) with processes from `p15/proctree.py`; file nodes by ADR-0015's trust table and ADR-0027; sockets paired only by the exact ISN rule; an open is one OPEN edge with its access mode, never a READ or WRITE; the PIDSMaker export writes its four tables as CSV plus a manifest of everything not exported. State: 29 tests, 98 mutants killed in the dev container; the first real run graphed on the VM (E-0168): 136 process, 652 file and 7 socket nodes from a 60 s capture, the three must-be-zero counts at zero. PIDSMaker has not read the export yet.

26. **The maintainer, 2026-11-11** (E-0171): #66 merged; the PIDS evaluation harness (where PIDSMaker runs, what the first detection number is measured on) is decided once capture is strong; until then the order of decision 22 holds, with every number of the system measured as it is built.

27. **A full queue loses nothing, taken under 22a** (E-0173, E-0174): the VM's first open-cost run showed the drain dropping one record at every queue-full moment (libbpf consumes a record its callback refuses). The drain now asks for room before it reads a ring. No ADR: ADR-0017 layer 2 already says the ring absorbs the backlog; the code did not do it.

28. **The open-cost harness, taken under 22a** (E-0172): `bench/open_cost`, p15d on against off, paired; the primary metric is the workload thread's CPU time per open+close, declared in its README before any run. The VM run on the fixed daemon (E-0176): 1,396.3 ns of thread CPU added per open+close of a known file (95 % interval 1,367.6 to 1,440.6), 2 records and 171.6 bytes in the WAL, p15d 552.1 ns per open+close above 14.65 ms/s idle; [evidence](evidence/vm/2026-11-11-open-cost/README.md).

29. **The cost split is measured before any redesign, taken under 22a** (E-0177): `bench/prim_cost` times each kernel-side building block alone (a ring record three ways, a hash lookup, an insert and delete, an atomic counter, a per-CPU copy, a clock read) and `prog_stats.py` reads each of p15d's programs' `run_cnt` and `run_time_ns` around a command. No VM number yet; no change to ADR-0006 or ADR-0015 is proposed before the VM's output is read.

30. **A cost run must show its host's speed, taken under 22a** (E-0180, E-0181): the first VM run of the cost-breakdown harnesses was on a host four to five times slower than the open-cost run and is not quotable ([evidence](evidence/vm/2026-11-11-prim-cost-slow-host/README.md)). Both harnesses now record a null syscall's cost every round; a run is not quotable when rounds differ by more than 1.5 times or the median is more than 1.5 times E-0176's reference. No design change is proposed from the slow run.

31. **The maintainer, 2026-11-11** (E-0182): "do the recommended steps": #68 and #67 merged with merge commits on green CI; #69 merges once the VM's run with the host-speed control is in it.

32. **Where a capture program's time goes, taken under 22a** (E-0184, [evidence](evidence/vm/2026-11-11-prim-cost-ac/README.md)): the first clean run (host on AC, Best performance). Program bodies 1,139 ns per open+close: the path program 561, the session program 289, the close program 289. A ring record costs 25-36 ns alone, about 6 % of the bodies: **per-CPU batching is not built now** (decision waiting 5 stands). No design change yet: the two unknowns below come first.

33. **Section timing in a separate build, taken under 22a** (E-0185): brackets in `file.bpf.c` that compile to nothing in p15d's build (checked instruction for instruction) and a profiled object only `bench/open_sections` loads. Chosen over a copy of the programs (it would drift from the shipped code) and over `bpf_stats` (whole programs only). #69 merged (E-0186).

34. **What the section timing and the contention run show** (E-0187 to E-0189, [evidence](evidence/vm/2026-11-11-open-sections/README.md)): `bpf_d_path` costs 87 ns, not the 400 ns inferred (E-0188 corrects E-0184); and under contention (12 processes, 3 vCPUs) the path fentry is skipped for 10.2 % of opens, each counted and written as an OPEN with `PATH_MISSING`, while the kprobe programs are never skipped. The session program is therefore not removable: it is what keeps those opens. No design change is taken here.

28. **The plan to a complete capture layer, taken under 22a** (2026-11-12, after the maintainer's "complete capture layer plus DuckDB and graph, tested on real workloads, before the PIDSMaker export"): gates in order. (1) open path v2: direct loads, one owner per open (E-0190); (2) names that survive a skipped path program: a bounded dentry walk in the session's return, checked against bpf_d_path (decision waiting 1); (3) idle cost; (4) a real-workload harness and a one-hour soak with the graph of that run; (5) step 2b with the ceiling gate; (6) 2c folding by Xu's rule; (7) 2d and 2e; (8) steps 3-5; (9) step 6 against the published tools, tamper window included; (10) graph v1: a streaming builder, reduction, backtracking queries, the demo; then the PIDSMaker export. Cost budgets proposed for the maintainer: program bodies under 0.5 us per open+close, p15d idle under 2 ms of CPU per second.

29. **Accepted, 2026-11-12** (E-0193): the cost budgets (file programs' bodies under 0.5 us per open+close; p15d idle under 2 ms of CPU per second); #71 merged; gate 2 begins with the walk-against-bpf_d_path harness. v2 stands at 897.3 ns per open+close (E-0192).

30. **Gate 2's harness, taken under 29** (E-0194): `bench/path_walk` checks a bounded, sequence-checked dentry walk (`bpf/include/p15_dpath.h`) against `bpf_d_path` on the same opens (16 cases, a rename race) and times it in the fentry and in a kprobe.session. It fails on any path that differs without a flag. CI's runner is the first load; the VM run decides decision waiting 1 by ADR.

31. **Gate 2 decided and built, taken under 22a and 29** (E-0196, E-0197): [ADR-0029](decisions/0029-path-walked-when-the-fentry-is-skipped.md), option (a). A skipped open's OPEN carries the walked path (PATH_WALKED); an overlay's real file gets BACKING from the return. Confirmed on the VM (E-0198, [evidence](evidence/vm/2026-11-12-path-walk-fallback/README.md)): 192,715 of 2,400,000 opens skipped under contention, all 192,715 walked with the right path, books ok. Next: gate 3, idle cost.

32. **Gate 3 begins, taken under 22a and 29** (E-0199): idle cost is a price per wake-up times 100 wake-ups a second (the 10 ms drain timer of ADR-0020 rule 2). `--poll-max-ms` makes the drain's timeout adaptive (10 ms after work, doubling when idle) and the writer sleeps until its next deadline; `bench/idle_cost` measures the arms on the VM. On the VM (E-0200, [evidence](evidence/vm/2026-11-12-idle-cost/README.md)): 10.4 ms/s at 10 ms, 1.14 ms/s at 200 ms, the smallest maximum under the budget in median and dearest round; [ADR-0030](decisions/0030-adaptive-drain-poll.md) makes 200 ms the default. Gate 3 met by the default; confirmed when the VM's it_p15d passes on it. Next: gate 4, a real-workload harness and a one-hour soak with the graph of that run.

33. **Gate 4's harness, taken under 22a and 29** (E-0201): `bench/soak` runs real programs (compiler, git, tar, http, shell, memfd) under p15d and checks every operation they logged against the WAL (by time window) and the graph (the dropper chain, ISN pairing, memfd executions), with CPU, memory and WAL growth sampled each minute. CI runs 45 s on every PR. The VM's hour (E-0202, [evidence](evidence/vm/2026-11-12-soak-1h/README.md)): 38,363 of 38,363 operations in the WAL, nothing lost, END clean, dropper chains and memfd executions all in the graph; the pairing check had a bug (ports reused), fixed; the recheck passes, so **gate 4 is met** (E-0203). Memory flattens at 27.65 MiB. The graph took 782 s, of which 626 s was one slow insert, fixed (E-0203); the rest is Python reading and row building (about 95 s), gate 10's streaming builder.

34. **The graph's build-time target, taken under 22a** (E-0204): an hour's graph in under 60 s. The soak reports it; `--strict-graph-time` makes it fail the run, the default once gate 10's streaming builder lands. The hour now builds in about 80 s (782 before; the same books). Gates 1 to 4 are merged (#72 to #75). Next: gate 5, reads and writes (step 2b) at their ceiling.

35. **Research for the full capture layer, the graph and DuckDB** (E-0205, [note](research/2026-11-12-full-capture-graph-duckdb.md)): writes have no edge from the writer until 2b, so 2b is the prerequisite of investigation; the graph labels events with a process's last image; DuckDB loads by column with no indexes, ordered by time; BackTracker's rule runs as one `USING KEY` query (checked in the dev container, [evidence](evidence/research/2026-11-12-backtrack-prototype/output.txt); on the VM's soak graph 0.055 to 0.113 s, stopping at every file because no edge points into one, E-0206, [evidence](evidence/vm/2026-11-12-backtrack-soak/README.md)). No design change is taken here: its five recommendations are decision waiting 8.

36. **The research recommendations accepted** (maintainer 2026-11-12, "recommendations accepted"; E-0208): decision waiting 8's order (R5, R2 alongside, R1 before 2b, R3 and R4 in gate 10), decision waiting 9's fix, and R2 widened to `sock_pair` and `file_backing`. R1 and the fix are ADR-0031 (#79): `proc_image` with each edge's program by ASOF JOIN, and names from the leader only. #77 and #78 merged.

37. **Tracking, R2, taken under decision 36** (E-0209): `python3 -m p15.graph.track` runs BackTracker's rule backward and its mirror forward as one `USING KEY` query each. It follows the edges that happened; the TCP pairs (client to server) and the overlay links as relations with no time; and, for a process from the opening snapshot, its parent at its start. On 40 random graphs it equals a plain-Python reference exactly. Timed on the soak graph when the VM runs it.

38. **The open path's cost against the published tools** (E-0210, [note](research/2026-11-12-open-cost-against-the-tools.md)): of the 897 ns profiled, the open-file map costs about 178 ns and two programs sit on one function. No tool keeps a map entry per open file: Falco, Tracee and Tetragon keep identity in user space. The largest gap against a published number is user space, p15d's 552 ns per open+close against eAudit's median 48 ns per syscall. Kept on purpose: the kernel's object and path at the LSM point, the fallback, the books. No design change is taken here: decision waiting 10.

39. **First VM numbers for decisions 36 to 38** (E-0211, E-0212, [evidence](evidence/vm/2026-11-12-graph3-and-costs/README.md)):
    - ADR-0031 confirmed on the hour's graph: no exec image without its edge, and p15d is named `p15d`.
    - Tracking takes under 0.5 s either way, whole command.
    - The shipped programs cost 741.4 ns per open+close unprofiled (7 rounds, E-0213). Capture adds 1,140.5 ns to a known file's open+close end to end (E-0176: 1,396.3), and p15d's idle rate is 1.83 ms per second.
    - 38.2 % of file frees are of files capture never opened.
    - Reads and writes run at about 317 per second under the soak's workload.
    - The graph build summed to 107.8 s. Its WAL read took 37.0 s on main and 45.6 s on the branch, one build each; the branch adds only one comparison per RENAME there, so this is most likely the host (INF, E-0213).

40. **The recommended order taken** (maintainer 2026-11-12, "do recommended"; E-0214): #79, #80 and #81 merged. Then p15d's profile first (C4, `bench/open_cost --perf`, #82), and the kernel-side variants after it. **C1 needs no new code:** p15d's `--test-no-path-fentry` (ADR-0015 confirmation 1) leaves the fentry unattached, so the session's return writes every OPEN by the walk (`daemon/loader.c` L56, `bpf/progs/file.bpf.c` L719). It is measured with the existing `prog_stats.py` and `open_cost`, at a 3-component path and a 10-component one, because the walk's cost grows with depth (E-0196). C1b and C2 need code, written after these numbers.

41. **C1 measured and not taken; p15d profiled** (E-0215, [evidence](evidence/vm/2026-11-12-c1-and-p15d-profile/README.md)): the session alone costs the open 35 to 51 ns more in its bodies and the same end to end, so the two programs stay. p15d's samples: about a third the byte-at-a-time CRC32C, about a third switching between its threads. The next work is in p15d (decision waiting 10).

42. **p15d's CRC32C by the CPU's instruction: p15d's CPU per open+close down 35 %** (E-0218, [evidence](evidence/vm/2026-11-12-crc32c-hw/README.md)): 455.1 ns against 699.4, and the agent overhead by eAudit's definition 28.6 % against 43.6 %. p15d's threads switch only 3.1 times per 1,000 open+close, so decision 41's "a third thread switching" was a misreading: the kernel samples are time with interrupts off, credited where they come back on, to be attributed from the call graphs.

43. **The tools' user-space pipelines studied** (E-0220, E-0221, [note](research/2026-11-12-userspace-pipelines.md)): 1 MiB batches cut p15d's CPU per open+close from 413 to 204 ns (E-0220), and today's two fixes together from 699 to 204. Against Falco, Tetragon, Tracee and eAudit: p15d matches the best on kernel wake-ups and batching. It keeps on purpose its writer thread, back-pressure, record checks and checksums. Its remaining levers are the ring reader (libbpf stores the consumer position per record) and record size. No design change is taken here: decision waiting 11.

44. **The capture layer reviewed** (E-0222, [audit](audits/2026-11-12-capture-review.md)): sound for what it captures, incomplete without data flow (step 2b: PIDSMaker gets 4 of 10 edge types), not yet deployable (cost over budget, seven deployment measures missing). Root causes: the pipeline was built before it was measured as a whole. From now on every capture PR runs the standing matrix on the VM before it merges (`tools/vm/measure_capture.sh`). The plan runs in phases A to F, with function (2b) before more cost work. Criteria and thresholds: decision waiting 12.

45. **The matrix's first runs** (E-0223, [evidence](evidence/vm/2026-11-12-matrix-defaults-vs-b1024/README.md)): with 1 MiB batches, p15d costs 201 ns per open+close against 420, the soak passes with nothing lost, and the calling program may pay less too (INF). The matrix's own it_p15d step was broken by the Python under sudo; fixed. Next in the matrix: how often the skip counters must be read.

46. **Decisions waiting 11.1 and 12 accepted** (maintainer 2026-11-12, "recommended decisions are accepted"; E-0224, E-0225):
    1. **1 MiB batches by default:** `--batch-kb 1024 --queue-batches 16`, the same 16 MiB as before. The sweep: 256, 1024 and 4096 KiB (E-0220), and the matrix with and without it (E-0223).
    2. **The capture layer's acceptance criteria** (audit §5), with their thresholds: zero-loss ceiling at least 10 times the soak's record rate (F5); overhead under 5 % on ordinary workloads (P1); bodies under 500 ns per open+close (P2); p15d under 100 ns per record (P3); tamper window under 1 s (S1); an hour's graph under 60 s (G1, decision 34).
    3. **The matrix is the merge rule for capture PRs** (CONTRIBUTING.md §5), with sweeps before defaults and estimates that never decide.
    4. **The order:** step 2b next (Phase B), then 2c, 2d and 2e, the deployment evidence, graph v1, then the export. No further open-path work before 2b.
    5. #82 to #86 merged.
    6. **#87's own matrix passed** on the VM (all 12 steps, soak PASS, books closed; E-0230, [evidence](evidence/vm/2026-11-12-matrix-pr87/README.md)): the first PR merged under rule 3.

## Decisions waiting

1. ~~**An open's path must survive a skipped fentry**~~ decided by ADR-0029 (decision 31): walked in the session's return when skipped. Open within it: whether walking every open in one program (option b) costs less once the fentry's own cost is saved (ADR-0029 falsifier 3; not measured).
2. **The same exposure in the network fexit programs** (ADR-0004): measure their skips under contention before 2e. Recommendation: add a network arm to `open_sections contend`'s pattern in the 2e PR.
3. **Spine batches behind bulk batches** (E-0174). The queue is one FIFO: under a bulk flood every slot can hold bulk records, and the spine waits in its ring. ADR-0017 says the spine is never shed. Recommendation: measure first in step 2b's ceiling gate (spine reserve failures while the bulk ring is saturated); if any, reserve queue slots for the spine by a new ADR.
4. ~~**A soak run before step 2b.**~~ Done: gate 4's hour (decisions 33 and 34, E-0202 to E-0204).
5. **A tamper-window metric for step 6** (R-042; E-0170). Recommendation: add it to step 6's protocol by a new ADR and measure before changing any design.
6. **Per-CPU batching as the fallback for step 2b** (R-042 §3.5; E-0170). Recommendation: keep ADR-0005's plan and let 2b's ceiling gate decide.
7. **Parked until capture is strong** (decision 26): where PIDSMaker runs; what the first detection number is measured on.
8. ~~**The research note's recommendations**~~ Accepted (decision 36): R1 done by ADR-0031, R2 by decision 37; R5, then R3 and R4 to come in that order.
9. ~~**A process's name is any of its threads' names**~~ Fixed by ADR-0031 (decision 36); confirmed on the soak graph when the VM rebuilds it.
10. **The open path's cost** (decision 38). Recommendation, in this order:
   1. Measure the shipped object unprofiled (`bench/prim_cost/prog_stats.py`) and the whole pipeline (`bench/open_cost`) on today's main, and read `free_unregistered` from the soak's FILE_STATS. These say how far the 500 ns budget is missed and how large C2's extra CLOSEs would be.
   2. Then a harness, `bench/open_variants`: C1 (the session alone, walking every path), C1b (kprobe.multi entry only), C2 (open-file ids paired in user space), built from `file.bpf.c` by -D flags, the shipped object unchanged.
   3. Then choose by a new ADR on its numbers. Profile p15d (C4) beside it.
   Results (decision 39, E-0213): item 1 gives 741.4 ns per open+close, so the budget is missed by 241 ns. 38.2 % of frees are unregistered. Capture adds 1,140.5 ns end to end, of which p15d's CPU is 699.4 ns per open+close, about as large as all the programs' bodies together.
   Then (decision 41, E-0215): C1 is not cheaper. Recommendation now: (a) p15d's CRC32C by the SSE4.2 `crc32` instruction, with the table kept for CPUs without it and for the tests; (b) then the thread switching, by measuring the drain's and writer's wake-ups per batch; (c) C1b and C2 only after (a) and (b), re-measured end to end. Then (decision 42): (a) done, −244 ns. (b) is withdrawn: switches are few. Next: attribute the kernel samples by their call graphs, then decide. Then (E-0219): the kernel samples are the drain's eventfd kick of the writer at each published batch, about 200 µs each on this VM (INF). Next: `--batch-kb` 1024 and 4096 measured with no code; then one wake per poll by code, if the wakes prove to be the cost.
11. **User-space pipeline** (decision 43). Recommendation, in this order:
   1. ~~U1~~ done by decision 46.
   2. U3, with U4: a drain reader that stores the ring's consumer position once per take, not per record, with its counters added once per take. Built as a p15d option and measured against libbpf's reader on `prog_stats` and `open_cost`, because it may lower the BPF programs' cost as well as p15d's.
   3. U2 only if the soak still shows switches after U1.
   4. U5 (smaller records) by an ADR after U3's numbers.
12. ~~**The capture layer's acceptance criteria and plan**~~ Accepted: decision 46.
13. **Where FLOW's start time comes from** (E-0227, [design checks](research/2026-11-12-step-2b-design-checks.md) §2). A kprobe.session's cookie is 8 bytes (SRC), so on `vfs_read` it cannot keep both the file and the entry time. Recommendation: option A. The cookie keeps the file pointer, and task storage keeps {file, entry time}; a failed creation or a nested transfer is flagged `START_UNKNOWN` and counted. Measured in the 2b dry run against end time only (option D), whose use would need an ADR superseding ADR-0005 rule 8. **Measured (E-0237, [evidence](evidence/vm/2026-11-12-flow-cost/README.md)):** with the record, A against D is +19.6 ns per read (95 % interval −55.9 to +99.3 ns), below what the VM resolves; 20,000 of 20,000 start times fell inside their reads. The record itself costs 113.9 ns per read over the bare session, and the bare session 281.0 ns over an untraced read (1.91 null syscalls).
14. **FLOW's size** (E-0226). 96 bytes as ADR-0005 rule 8 asks, against 88 if the rare unregistered transfer went as a FILE before its FLOW (an ADR superseding rule 8). Recommendation: keep 96 and let step 2b's ceiling decide, with bytes per second reported beside records per second.
15. **Padding of the records before FLOW and FILE is not checked** by `p15_rec_check` or the reader (E-0226). A program that builds a record in reused memory could carry old bytes in `_pad`. Recommendation: check every type's padding, after a matrix run on the VM shows that no program writes non-zero padding today.
16. **The socket tracepoints' edges in 2b** (E-0227, design checks §3). Recommendation: a send or receive on a socket without a file (kernel code using a kernel socket from a user task) is counted `no_file` and not written (ADR-0005 rule 11). Sends inside splice and sendfile are written as SEND until step 2d's SPLICE records exist; then they follow rule 11's `inside_splice`.

### Decisions waiting from Dragon's design review (2026-11-13; numbered from 101)

Each is set out with its options and evidence in [the review](audits/2026-11-13-design-review-dragon.md) §8; none is confirmed by a run (E-0300, E-0301).

101. **The shared bulk ring under a flood** (F-01). Recommendation: run V-1; if confirmed, a design note for FLOW on its own ring and a per-process loss count.
102. **A full disk ends capture** (F-02). Recommendation: a free-space reserve that sheds FLOW first, and a supervisor; a new ADR beside ADR-0007.
103. **The open-file map can be filled by one process** (F-04). Recommendation: size it from the host; `file_map_full` makes the run DEGRADED.
104. **The canary of ADR-0019 G4.4 is not built** (F-05). Recommendation: build it, extended to an open and a transfer.
105. **A coverage table in an ADR** (F-06): each data path planned in a step or declared out of scope. AIO and the reflink ioctls are in neither today.
106. **The read path's cost on the shipped program** (F-07), by `prog_stats.py`, before criterion P2's per-read figure is set.
107. **Processes that share an address space** (F-09): FORK version 2 says so; the graph adds the child → parent edge.
108. **ADR-0013, the threat model, before the ceiling gate** (F-10).
109. **The order:** the detach fault first, then runs V-1 to V-3, then 101 to 104 by what they show.
