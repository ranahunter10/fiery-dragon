# Hyper-V on, with warm-up: fixed-work baselines re-run (2026-10-25)

**What:** `bench/baseline/baseline.py` at `main` `cb94564`, which includes the warm-up fix (E-0039). It ran 3 rounds, comparing untraced runs with the census v2 probe (sha256 `716bf951…`).

**Why:** the [A-B-A runs](../2026-10-25-hyperv-ABA/README.md) could not say what tracing costs on `find` and `churn`, because their jobs contaminated each other through the page cache. This run repeats them with an untimed warm-up before every timed job, on the decided host state (E-0042).

**Conditions:**
- Started 2026-10-25 00:56:53 UTC, about 30 minutes after A2 started.
- Host state as noted by the operator: "Hyper-V ON (everyday safe state), warm-up on, plugged in, Best performance, no other apps".
- **The VM had been freshly booted:** the PID counter in `loadavg_before` was 1573. Whether the laptop also restarted after A2 is not known: the operator thinks it may have, but is not sure.
- Swap was off during the run.

**Integrity:**
- Tarball `baseline-warm.tgz`, sha256 `d9f195e870867a0baef37767e6202ba30e2a74a4298f9b5ce57ce1837a04196c`. That hash was printed on the VM and matched on receipt.
- The files are copied byte for byte (`SHA256SUMS`, 68 files). The empty `work/` directory is not kept.
- **The warm-up logs are included.** Their values are real timings, recorded but not used by the tool.

## Values in run order (timed run, preceded by its warm-up)

| Round | Config | find-serial s | find-parallel s | exec s | churn ops/s | disk MB/s |
|---|---|---|---|---|---|---|
| 1 | none | *13.82* → 0.31 | 0.22 → 0.22 | 7.80 → 12.80 | 25,768 → 30,493 | 95.7 → 91.3 |
| 1 | traced | 1.21 → 0.86 | 0.52 → 0.58 | 10.86 → 13.04 | 24,062 → 29,613 | 87.2 → 107.3 |
| 2 | traced | 0.66 → 0.64 | 0.43 → 0.49 | 10.51 → 13.15 | 19,990 → 39,417 | 105.6 → 108.6 |
| 2 | none | 0.46 → 0.54 | 0.37 → 0.33 | 10.55 → 11.85 | 22,328 → 21,924 | 72.9 → 89.4 |
| 3 | none | 0.51 → 0.53 | 0.34 → 0.35 | 11.66 → 10.12 | 21,574 → 33,879 | 134.2 → 144.1 |
| 3 | traced | 1.04 → 0.93 | 0.62 → 0.74 | 13.01 → 7.81 | 32,558 → 34,236 | 157.1 → 171.5 |

**Paired ratio per round** (traced vs untraced in the same round; > 1 means tracing made the job slower):

| Job | Round 1 | Round 2 | Round 3 |
|---|---|---|---|
| find-serial | 2.79 | 1.19 | 1.76 |
| find-parallel | 2.64 | 1.48 | 2.12 |
| exec | 1.02 | 1.11 | 0.77 |
| churn | 1.03 | 0.56 | 0.99 |
| disk | 0.85 | 0.82 | 0.84 |

## Findings

1. **The warm-up fix worked for the defect it was meant to fix** (MEAS). After the fresh boot, the cold-cache `find-serial` (13.82 s) landed in round 1's *untimed* warm-up, and the timed run took 0.31 s. In A2, that cold run (17.6 s) had gone into the mean.
2. **Every row is still above 10 % CV (11.8–28.7 %), so no mean from this run is quotable** (MEAS). The noise is fast, not just slow drift:
   - two back-to-back untraced `exec` runs took 7.80 s and 12.80 s, 13 s apart;
   - `churn` ranged from 19,990 to 39,417 ops/s;
   - `disk` ranged from 72.9 to 171.5 MB/s.

   Three rounds with a CV gate cannot resolve effects of a few percent on this host.
3. **Correction to E-0038: the A-B-A runs did not show that Hyper-V causes the slow exec** (MEAS; it corrects a causal claim graded too strongly).
   - With the hypervisor on, as in A1 and A2, untraced `exec` took **10.1–12.8 s** here, or 7.8–11.7 s counting warm-ups.
   - A1 took **37.8 s** and A2 **28.1 s**.
   - Runs in the same stated host state therefore differ by up to **3.3×**, nearly as much as the on/off ratio (4–5.5×) that E-0038 attributed to Hyper-V. Something else changes between boots, and A-B-A did not control for it.
   - **What still holds:**
     - B (hypervisor off) is the fastest run measured (6.9 s);
     - absolute rates on this laptop are unreliable, which is exactly what decision E-0042 assumes. The decision is unaffected.
4. **The census probe slows `find`, but the size is not measurable here** (direction MEAS, magnitude OPEN).
   - Tracing made `find` slower in every timed pair (ratios 1.19–2.79), and in every warm-up pair not hit by the cold cache.
   - **Likely mechanism (INF on 7.0):** the census attaches `raw_syscalls:sys_enter`/`sys_exit`, which makes *every* syscall leave the fast path. The v3.5 measurement on kernel 5.4 priced that at ≈16 ns per syscall plus per-event handling, and `find` is a syscall flood.
   - **The census probe is not the product probe.** It counts every syscall; the capture design hooks `vfs_*`, LSM-named functions and sched tracepoints. So the product's overhead has to be measured on the product's own probe, in Phase 1.
5. **No consistent tracing effect on `exec` or `churn`** at this noise level (ratios on both sides of 1).
   - **`disk` was faster when traced in all three rounds** (0.82–0.85). Three of three has a 25 % chance of happening by luck (two-sided sign test), so this is recorded and not interpreted.

## What this means

- **The overhead method needs to change** before any overhead number is quoted. This is a decision for ADR-0012 (the measurement protocol). The proposal:
  - Keep traced and untraced runs adjacent in each round (as now), and **report the per-round paired ratio**: median and range.
  - Add an **A/A control arm**, a second untraced configuration in every round. That way the run measures its own noise floor, as the v3.5 tracepoint-tax study did with baselines read as configurations.
  - Claim an effect only when it exceeds that floor in the same run, and only with **≥ 7 rounds**. At 7 of 7 the two-sided sign test gives p = 0.016.
  - Keep CV as a drift indicator, not as the quotability gate.
- Census-probe overhead is not a decision input. The overhead that matters is the Phase-1 probe's.
