# Hyper-V on / off / on: fixed-work baselines (2026-10-24/25)

**What:** `bench/baseline/baseline.py` at commit `d3d55c7`, run three times, 3 rounds each, untraced vs the census v2 probe (sha256 `716bf951…`). This version had **no warm-up**.

**The A-B-A sequence:**

| Run | Host state, as verified by the operator | VM | UTC start |
|---|---|---|---|
| **A1** `hyperv-on-A1` | Hyper-V on (default laptop state) | running for hours | 2026-10-24 23:33 |
| **B** `hyperv-off-B` | `bcdedit hypervisorlaunchtype off` **and Memory integrity off**, then restart. Verified: HypervisorPresent=False, VBS=0; VBox.log "HM: Using VT-x implementation 3.0" | **fresh boot** | 2026-10-25 00:11 |
| **A2** `hyperv-on-A2` | settings restored (Memory integrity on, launchtype auto), restart | **fresh boot** | 2026-10-25 00:27 |

**Integrity:**
- Tarball `baseline-hyperv.tgz` sha256 `a364ba5deff01ad704eca3c192ebfe917a955c67b4764e8119ce9f88ed209b5a`, as printed on the VM.
- Files here are byte for byte (`SHA256SUMS`). Each run directory holds its `conditions.json`, `results.json`, `index.md`, and every job's log.

## Per-round values

| Job | Config | A1 (on) | B (off) | A2 (on) |
|---|---|---|---|---|
| exec, s | none | 34.62 · 39.29 · 39.60 | **6.37 · 7.24 · 6.94** | 28.89 · 28.58 · 26.72 |
| exec, s | traced | 36.38 · 38.87 · 38.92 | **7.45 · 8.16 · 7.13** | 31.29 · 29.98 · 29.77 |
| disk, MB/s | none | 71.45 · 66.86 · 79.89 | **138.30 · 156.90 · 167.62** | 117.86 · 116.58 · 121.71 |
| disk, MB/s | traced | 75.91 · 97.72 · 83.17 | 131.98 · 159.13 · 169.90 | 111.00 · 111.54 · 152.47 |
| find-serial, s | none | 2.65 · 2.18 · 2.67 | *6.24* · 1.82 · 1.56 | *17.61* · 1.62 · 1.53 |
| find-parallel, s | none | 1.08 · 0.96 · 1.30 | *0.27* · 0.72 · 0.79 | *0.25* · 0.99 · 0.92 |
| churn, ops/s | none | 5,352 · 4,957 · 4,770 | *24,060* · 8,685 · 9,812 | 10,904 · 13,098 · 14,133 |

*Italics:* the round-1 artefacts explained in finding 3.

## Findings

> **Correction (2026-10-25, E-0044).** Finding 1 claimed a cause too strongly. The [warm-up re-run](../2026-10-25-hyperv-on-warm/README.md), with Hyper-V on as in A1 and A2, took **10.1–12.8 s** for the same 2,000 execs. So runs in the same stated host state differ by up to 3.3×, almost as much as the on/off ratio. The per-run numbers below stand. "Hyper-V **makes** process creation 4–5.5× slower" does **not**: A-B-A did not control for whatever else changes between boots. B is still the fastest run measured. The original text is kept so the history stays honest.

1. **Hyper-V makes process creation 4–5.5× slower** (MEAS, stable: exec CV ≤ 7.4 % in every configuration).
   - Untraced, 2,000 execs: A1 37.8 s, **B 6.9 s**, A2 28.1 s. That's 53 → 292 → 71 execs/s.
   - This explains E-0029: the low exec rate is the platform, not the probes.
2. **Tracing is cheap on process creation** (MEAS): exec slowdown +1 % (A1), +11 % (B), +8 % (A2). Quotable: CV < 10 % on both sides in every run.
3. **The baseline tool's jobs contaminated each other** (MEAS, a defect in the tool, now fixed):
   - Untraced `find-parallel` took 0.25–0.27 s in round 1 of B and A2, right after `find-serial` loaded `/usr` into the page cache. It took 0.72–0.99 s in later rounds, after `churn` had pushed 1–2 GB through the cache.
   - After a fresh boot, `find-serial` round 1 took 6.2 s (B) and **17.6 s** (A2): cold cache.
   - So the `find` and `churn` means, and every slowdown built on them, partly measure *what ran before*. The ⚠ flags in all three runs mark exactly these rows.
   - **Fix:** commit "bench/baseline: untimed warm-up before each timed job", in the same PR.
4. **The VM drifts even with Hyper-V unchanged** (MEAS): A1 and A2, both "on", differ by **−26 % on exec** and **+63 % on disk**. A1 had been up for hours; A2 was a fresh boot.
5. **Hyper-V off is faster; whether it is also more *stable* is not shown** (OPEN). B was one run; its in-run CVs on the clean jobs (exec 6.4 %, disk 9.6 %) are similar to A1/A2.

## What this means for measuring Fiery Dragon

- **Relative measurements are trustworthy; absolute ones are not, on this laptop.** "Tracing costs +1–11 % on exec" held across all three host states, and selectivity held across census runs. Absolute rates (execs/s, MB/s) moved 26–63 % with no configuration change.
- **Sizing (ADR-0005/6/7) must use worst-case or interleaved rates, never a single run's absolute rate.** The formula "untraced syscall rate × selectivity" stands, with the untraced rate measured **in the same session**.
- **Measurement protocol (ADR-0012), to decide:**
  - which host state counts as authoritative;
  - whether security settings may be relaxed for a measurement session;
  - whether to use a second machine.
- **Runbook addition:** on Windows 11, `bcdedit /set hypervisorlaunchtype off` is **not enough while Memory integrity (HVCI) is on**: `VirtualizationBasedSecurityStatus` stays 2 and the hypervisor still loads. Both must be off, and both must be restored afterwards.

## Not concluded here

- The size of tracing overhead on `find` and `churn`: contaminated, re-measure with warm-up.
- Whether Hyper-V off reduces drift: needs repeated "off" runs.
