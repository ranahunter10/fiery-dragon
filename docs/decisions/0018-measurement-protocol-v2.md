---
status: proposed
date: 2026-10-25
owner: Ashish Rana
consulted: [research note 2026-10-25-measurement-and-design-inputs (A1–A7), Hoefler & Belli SC'15 (R-013), NoDrop (R-012), Nitro (R-011), Gebai & Dagenais (R-014), Kahle (R-016), Piotrowski (R-017), ADR-0012, maintainer's questions of 2026-10-26]
supersedes: ADR-0012's "Timing protocol" (rules 1, 3 and 4) and its knee-quoting rule; ADR-0012's six axes, conditions and instruments stand
---

# 0018: Measurement protocol v2: dimensionless headlines, rates against a same-host ceiling, paired timing reported with its raw costs, and one workload set shared with the literature

## Context and problem statement

ADR-0012 made timing on this noisy host quotable: paired rounds, an A/A control and a sign test. Three things were missing, and the research pass found them:

1. **Reporting.** ADR-0012 reports only the median of per-round ratios. Hoefler and Belli's rule 4: *"Avoid summarizing ratios; summarize the costs or rates that the ratios base on instead."* Rule 5 asks for confidence intervals, rule 11 for upper performance bounds. A reviewer would rightly ask for the raw costs behind every ratio.
2. **Portability.** Absolute rates from one machine don't transfer. Piotrowski concluded a DTrace-vs-bpftrace comparison was "unfair and misinformed" even on two identical servers. The knee gate ("≥ 10× v3.7's 9.4 k records/s") compares numbers from two platforms.
3. **Workloads.** None was fixed, so our results could not be laid next to published ones.

**Question:** what does a quotable Fiery Dragon number look like, so that it holds on another machine and survives review?

## Decision drivers

1. Every quoted number is reproducible from raw output and states what it depends on (CLAUDE.md).
2. Methods a systems or security reviewer recognises, with no rule of the field broken.
3. Numbers that carry over to another machine wherever possible; the rest labelled "this host".
4. Robust on this host's drift (E-0044): the pairing that ADR-0012 introduced stays.
5. Comparable, row for row, with the papers we will be judged against.

## Considered options

1. **Keep the pairing; report it the way the rules ask:**
   - raw costs per arm with intervals;
   - the paired effect as a Hodges–Lehmann estimate with its Wilcoxon interval;
   - dimensionless headlines;
   - rates as a fraction of a same-host ceiling;
   - one shared workload set.
2. Drop the pairing; report only means of raw costs, as most papers do.
3. Keep ADR-0012 unchanged and argue the exception.

## Decision outcome

**Chosen option:** option 1. It keeps what makes timing work on this host (the pairing, driver 4) and reports it in the form the rules ask for (driver 2).
- **Option 2** fails on this host: drift of up to 3.3× between same-state runs (E-0044) swamps unpaired means.
- **Option 3** is the "breaking a rule" position. With option 1 nothing is broken: ratios are never reported without the costs they come from.

### Rule 1: two tables, never mixed

- **Headline table: dimensionless only.**
  - completeness (captured / missed / declared limit, per coverage row);
  - loss % (witness count, Houssel; per ring and per cause, ADR-0006);
  - overhead % (below);
  - bytes per record and records per witness operation;
  - knee as a % of the same-host ceiling (rule 3).
- **"This host" table: absolute values,** each with the session id and the conditions file (ADR-0012): ns, records/s, MB/s, CPU-seconds.

### Rule 2: timing (supersedes ADR-0012 timing rules 1, 3 and 4)

1. **Rounds: at least 10** (was 7). The counterbalanced triple (traced, untraced, A/A untraced) and the untimed warm-up of ADR-0012 stay.
2. **Per round *i*:**
   - traced time T*ᵢ*, untraced U*ᵢ*, A/A U′*ᵢ*;
   - effect d*ᵢ* = ln(T*ᵢ* / U*ᵢ*);
   - A/A a*ᵢ* = ln(U′*ᵢ* / U*ᵢ*).
3. **Report all of the following** (each is computed by code with tests, never by hand):
   - **raw costs per arm:** median of T, of U and of U′, each with a distribution-free 95 % interval from order statistics, plus n (rules 4, 5, 6);
   - **the ratio of the medians,** median T ÷ median U (what rule 4 asks for);
   - **the paired effect:** the Hodges–Lehmann estimate of d (the median of the Walsh averages), reported as overhead = e^HL − 1, with the exact Wilcoxon signed-rank 95 % interval and the exact two-sided p-value. NoDrop compares with the same test;
   - **the A/A floor:** the same estimate and interval for *a*;
   - **a drift flag:** if the ratio of medians and e^HL differ by more than the A/A interval's width, the report says the host drifted during the run. The paired effect is the one quoted; the flag explains why the two differ.
4. **Quote an overhead only if:**
   - Wilcoxon p < 0.05; and
   - the HL estimate lies outside the A/A interval.

   Otherwise the result is "not resolved on this host", with the A/A interval.
5. **Means:** costs that are sums, such as total agent CPU-seconds, are summarised with the arithmetic mean, and rates with the harmonic mean (rule 3), alongside the medians. Rule 8: the report says which one a conclusion rests on.

### Rule 3: rates and per-event costs against a same-host bound (rule 11)

1. **The knee is quoted as a fraction of this host's ring-buffer ceiling,** measured in the same session with the kernel's own benchmark (`tools/testing/selftests/bpf/benchs`, `bench ringbuf`) at 1 to N producers, N = vCPUs.
   - It is also given as a curve over vCPUs (1, 2, 4), using the VM's CPU count.
   - **This replaces the Phase-1 gate's "≥ 10× v3.7's 9.4 k records/s"**, which compared two platforms.
   - The new gate:
     - zero loss at **≥ 10 × the v3.7 knee measured in the same session** if v3.7 runs on 7.0 (a probe decides);
     - otherwise, **≥ 50 % of the same-host ring-buffer ceiling** for spine-sized records, with v3.7's 9.4 k shown as a labelled historical figure.

     The 50 % is the maintainer's to confirm.
2. **Per-event BPF cost:** `run_time_ns ÷ run_cnt` from `bpf_stats`, **minus nothing and labelled**. Kahle measured that stats collection itself adds about 20 ns per run, so it is reported next to the number. The cost is also given as a multiple of this host's null-syscall time, measured in the same session (Gebai and Dagenais' baseline method).

### Rule 4: one workload set, three uses

| Use | When | Workloads | Measured |
|---|---|---|---|
| **Functional** (correctness, no timing) | from Phase 1 step 6 (L4) | PostgreSQL + pgbench (a fork per connection); Nginx master/workers + wrk; Redis (threads) + redis-benchmark; a kernel build (short-lived processes); multithreaded exec and non-leader exit (E-0066) | process tree and lifecycle against the application's known structure and a witness count; 0 invalid records; invariant closes |
| **Performance** (L7) | Phase 6 | eAudit's seven stress tests (postmark, shbm, find, tar, rdwr, httperf, kernel build) at 1–4 threads; Nginx, Redis, OpenSSL, 7-Zip, lmbench, pgbench, at the parameters published by Nitro, NoDrop and eAudit | overhead % (rule 2), loss %, records per operation; each row next to the published row for the same workload |
| **Adversarial** (L6) | Phase 1 (spine), Phase 6 (all) | NoDrop's super producer (one write loop per vCPU, 30 s, rising rates); Mao's `find /usr` × 5 threads; the spine storm of ADR-0017 | loss % per ring and cause; the rate at which loss starts |

A published row next to ours compares **methods on the same workload**, not machines. The report says so.

### Rule 5: limitations travel with the numbers

Every report carries a fixed limitations block:
- no PMU counters in the guest;
- the host runs under Hyper-V;
- one machine with N vCPUs;
- vendor figures are not independently measured;
- pinned versions of the kernel, compiler, libbpf and every workload tool.

### Consequences

- Good: no reporting rule of the field is broken. Every ratio comes with its costs, its interval and its noise floor.
- Good: headline numbers carry over to another machine; absolute numbers are labelled as this host's.
- Good: the Phase-1 gate no longer compares two platforms.
- Good: the functional workloads test the spine against real process models (PostgreSQL's fork per connection, Nginx's workers, Redis's threads) long before any performance claim.
- Bad: 10 rounds × 3 arms; timing runs stay a gate activity.
- Bad: building the kernel's `bench` needs the 7.0 selftests source on the VM.

### Confirmation

- `bench/stats.py`, pure Python, no SciPy:
  - Hodges–Lehmann, the exact Wilcoxon signed-rank p and interval, and order-statistic intervals for medians;
  - tested against published Wilcoxon critical values and hand-checked small cases;
  - a synthetic drifting run must raise the drift flag; an effect inside the A/A interval must not be quoted.
- The Phase-1 gate report follows rules 1–5. CI checks the report's sections are present.
- `bench/ceiling/`: the script that builds and runs `bench ringbuf` on the VM, with its raw output under `docs/evidence/`.

### Falsifier

Reopen if:
- 10 rounds still leave every Phase-1 question "not resolved on this host" (the A/A interval > 20 %), which points to dedicated hardware (ADR-0012 option 3);
- `bench` can't be built for 7.0.0-38;
- a reviewer requires a protocol this one can't express.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | Rules 3, 4, 5, 6, 8, 9, 11, quoted from the slides | DOC | Hoefler & Belli, SC'15 (R-013) |
| 2 | Same-state runs differ by up to 3.3×; CV 12–29 % | MEAS | E-0043, E-0044 |
| 3 | 10 runs and the Wilcoxon signed-rank test for paired comparisons | PDF | NoDrop (R-012) |
| 4 | 30 runs with RSD 3.91–14.05 %; overhead = (T_total − T_bench) / T_bench; loss = discarded / total | PDF | Nitro (R-011) |
| 5 | Per-event cost against a no-tracer baseline (17 ns) on one machine | PDF | Gebai & Dagenais (R-014) |
| 6 | `bpf_stats` adds about 20 ns per run | DOC | Kahle (R-016) |
| 7 | Cross-platform comparisons judged unfair even on identical servers | PDF | Piotrowski (R-017) |
| 8 | `bench ringbuf` multi-producer results, e.g. 13.218 M/s at 1 producer and 1.070 M/s at 52 on EPYC 9654 | DOC | R-015 |
| 9 | Workload sets of Nitro, NoDrop, eAudit and Houssel | PDF | R-011, R-012, R-002, R-003 |
| 10 | Hodges–Lehmann and the Wilcoxon interval are the standard estimate and interval for a paired shift | INF (textbook statistics; to cite a textbook when `bench/stats.py` lands) | — |

## Pros and cons of the options

### 1. Pairing, reported per the rules
- Good: robust on this host and compliant with the rules.
- Bad: a longer report.

### 2. Unpaired means
- Good: the most common form in papers.
- Bad: swamped by drift on this host (E-0044).

### 3. Keep ADR-0012 and argue
- Bad: reports ratios without their costs; leaves the cross-platform gate.
