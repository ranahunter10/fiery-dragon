---
status: accepted; the timing protocol's rules 1, 3, 4 and the knee-quoting rule superseded by ADR-0018
date: 2026-10-25
owner: Ashish Rana
consulted: [capture blueprint v1 §6 (2026-10-21), research note quantification.md (Houssel et al., eAudit, ProvMark, Mao et al., Falco, Tetragon), E-0013, E-0039, E-0042..E-0047, E-0057, Phase 0 audit]
supersedes: none
---

# 0012: Quantification protocol: host-independent metrics first; relative timing only, by paired rounds with an A/A control

## Context and problem statement

Phase 0 showed that this laptop can't produce trustworthy absolute timings:
- same-state runs differed by up to 3.3× (E-0044);
- back-to-back runs of one job differed by 1.6× (E-0043);
- three rounds gave CVs of 12–29 % on every job (E-0043);
- the guest has no hardware performance counters (E-0057).

Two claims made along the way were wrong and had to be corrected (E-0033 by E-0035; E-0038 by E-0044).

The project still has to show measured progress, against v3.7 and later against Falco, Tetragon and Tracee.

**Question:** what is measured, with which instrument, under which conditions, and when may a number be quoted?

## Decision drivers

1. **No number without a harness and raw output** (CLAUDE.md); no quoted effect smaller than the run's own noise.
2. **Progress metrics that don't depend on host speed** wherever possible.
3. Methods reviewers recognise, from the literature and from comparable tools.
4. Honest about this host: relative results only.
5. Cheap enough to run on every phase gate.

## Considered options

1. **Six metric axes from the literature, host-independent ones first; timing only as paired ratios with an A/A control arm, on the everyday host state**
2. Make the laptop a quiet benchmark host (Hyper-V and Memory integrity off, pinning) and quote absolute numbers
3. Move all measurement to separate hardware now

## Decision outcome

**Chosen option:** option 1. It produces quotable numbers on this host (drivers 2 and 4) with published methods (driver 3).
- **Option 2 was tried:** the Hyper-V A-B-A runs. It didn't make runs repeatable (E-0044), and it lowers the laptop's security while measuring (E-0042).
- **Option 3** stays open for thesis-grade absolute overhead numbers later. It isn't needed for any Phase-1 decision.

### What is measured (the six axes)

| Axis | Metric | Instrument | Depends on host speed? |
|---|---|---|---|
| **Completeness** | per operation in the coverage matrix and evasion catalogue: captured correctly / missed / declared limit; recall = matched ÷ ground truth | L4 per-row tests and the load-time self-test (ADR-0003); ProvMark-style foreground/background differencing for the tool comparison (L8) | **No**: the primary progress metric |
| **Loss** | `1 − traced/expected` with a known-count witness (Houssel); per-cause counters closing the accounting invariant (ADR-0006) | the daemon's counters; witness workloads | Partly: compared within one session |
| **Zero-loss knee** | highest offered rate with zero loss for 60 s (doubling, then bisecting) | Falco-style ramp (bench, Phase 1) | Yes, but quoted only **relative to v3.7 or to a baseline in the same session**; the Phase-1 gate is ≥ 10× v3.7's 9.4 k records/s |
| **Per-event BPF cost** | `run_time_ns / run_cnt` per program | `kernel.bpf_stats_enabled=1` **only while measuring**, read via `bpftool prog show` or libbpf | Less than wall-clock timing: it times our programs only. How much less is OPEN (E-0057), and enabling stats has its own cost, so it is never on in normal runs |
| **Wall-clock overhead** | slowdown of fixed work, traced vs untraced | `bench/baseline/` with the protocol below; lmbench-style microbenchmarks per syscall class (to add) | **Yes**: relative only, with the A/A floor |
| **Volume** | bytes per record, records per operation, WAL bytes/s | WAL statistics (ADR-0007) | No (bytes); rates relative only |

**Not available here:** hardware cycle and instruction counts (`perf stat`), because the VM has no PMU counters (E-0057).

### Timing protocol (decision E-0046)

1. **Rounds:** at least 7. Each round runs, back to back:
   - the traced configuration;
   - the untraced configuration;
   - a **second untraced configuration (A/A control)**.

   The order is counterbalanced across rounds.
2. **Warm-up:** each timed job is preceded by an untimed run of the same job in the same configuration (E-0039).
3. **Report:**
   - the per-round paired ratio traced ÷ untraced, as median and range;
   - the A/A ratio untraced-B ÷ untraced-A, as median and range, which is **the run's own noise floor**;
   - CV per configuration, as a drift indicator only.
4. **Quote an effect only if:**
   - its median is outside the A/A range in the same run; **and**
   - its sign is the same in at least 7 of 7 rounds (two-sided sign test p = 0.016), or at least 9 of 10 rounds (p = 0.021).

   Otherwise write "not resolved on this host" with the floor.

### Conditions (decisions E-0013, E-0042)

- **Host:** the laptop in its everyday safe state (Hyper-V on, Memory integrity on). Plugged in, Best performance, no other applications. Recorded as a host note, because the guest can't see these.
- **Guest:** swap off during the measurement, restored afterwards. Kernel, git commit (and dirty flag), probe and tool hashes, snapshot and load average are recorded in `conditions.json` for every run.
- **Absolute rates** (execs/s, MB/s, records/s) from this laptop are **never quoted as properties of the capture**. They are quoted only as the same-session baseline that a relative result is built on.
- **Census-probe overhead is not measured** (E-0047). Overhead is measured on the product's own programs, from Phase 1.

### Consequences

- Good: the headline "better than v3.7" is a completeness table plus a relative knee. Neither depends on this laptop being quiet.
- Good: every quoted timing carries its own noise floor, so a reviewer sees what the run could resolve.
- Bad: small overheads (a few percent) may stay "not resolved on this host". That is reported as such, not as zero.
- Bad: at least 7 rounds × 3 arms makes timing runs long. Run them at phase gates, not on every change.

### Confirmation

- `bench/baseline/` gains the A/A arm, the paired-ratio report and the quote rule (Phase-1 task). Its tests include a synthetic case where the effect is inside the floor and must not be quoted.
- Every number in `docs/` links to raw output under `docs/evidence/` (existing rule; the CI check for it is a follow-up).
- The Phase-1 gate report states the knee relative to v3.7 and its witness-count loss.

### Falsifier

Reopen if:
- the A/A floor on this host is so wide (e.g. > 20 %) that no Phase-1 overhead question can be answered; that points to option 3;
- `bpf_stats` turns out unusable on the VM or too costly to enable;
- a reviewer or advisor requires absolute overhead numbers for the thesis; that is option 3 for those numbers only.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | Same-state exec runs: 10.1–12.8 s vs 37.8 s and 28.1 s; back-to-back runs 7.80 s and 12.80 s; CV 11.8–28.7 % in all rows with 3 rounds | MEAS | [warm re-run](../evidence/baseline/2026-10-25-hyperv-on-warm/README.md); E-0043, E-0044 |
| 2 | Untimed warm-up removes page-cache contamination between jobs | MEAS | same; E-0039, E-0043 |
| 3 | No hardware performance counters in the guest; `bpf_stats_enabled` = 0 by default | MEAS | [perf counters](../evidence/platform/2026-10-25-perf-counters/README.md); E-0057 |
| 4 | Maintainer decisions: host state and relative-only (E-0042); paired + A/A + ≥ 7 rounds (E-0046); no census-probe overhead (E-0047); swap off while measuring (E-0013) | decision | engineering log |
| 5 | Loss as `1 − n_traced/n_expected` with a known-count witness | PDF | Houssel et al., arXiv 2608.11418 (via `quantification.md`; venue not stated) |
| 6 | Completeness as a per-syscall recorded/not-recorded differential | PDF | Chan et al., ProvMark, Middleware 2019 |
| 7 | Agent cost reported as median ns per syscall (48 ns) | PDF | Sekar et al., eAudit, IEEE S&P 2024 |
| 8 | Robustness as loss under an adversarial high-rate producer (5-thread `find /usr`) | PDF | Mao, Ujcich & Ma, arXiv 2510.08479 |
| 9 | Falco: doubling-rate ramp for the knee; drop counters per cause; CPU as % of one core | DOC/BLOG | Falco performance docs and blog (via `quantification.md`) |
| 10 | Tetragon's bench harness reads `run_time_ns`/`run_cnt` with BPF stats enabled, and wraps workloads in `perf stat` | SRC | `pkg/bench/bpfstats.go`, `contrib/bench/bench.sh` @6a10ef1 (via `testing_ci_process.md`) |
| 11 | Falco dropped its 1 % performance gate in CI as unstable | SRC | falcosecurity/libs workflow @30ef48d (via `testing_ci_process.md`) |
| 12 | Two-sided sign test: 7 of 7 gives p = 2/128 ≈ 0.016; 9 of 10 gives p = 22/1024 ≈ 0.021 | INF (arithmetic) | binomial(n, ½) |

## Pros and cons of the options

### 1. Host-independent metrics + paired timing with an A/A floor
- Good: quotable results on the everyday host; methods from the literature.
- Bad: small timing effects may stay unresolved.

### 2. Quiet the laptop
- Bad: tried, and runs still varied up to 3.3× (E-0044); lowers security while measuring.

### 3. Separate hardware now
- Good: absolute numbers.
- Bad: not needed for Phase-1 decisions; kept open for the thesis.
