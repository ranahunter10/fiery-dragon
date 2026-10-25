# A/B, 5 parallel `find`: tracing cost under contention (2026-10-25)

**Question:** the serial A/B ([`../2026-10-25-ab-find-serial/`](../2026-10-25-ab-find-serial/README.md)) ruled out "the v2 hooks are slow" for one process at a time. Does the cost blow up when 5 `find`s run at once on 4 vCPUs, which is the census super-producer's shape?

**Method:**
- Wall time of 5 concurrent `find /usr` processes, under no tracing, the v1 probe and the v2 probe.
- Interleaved over 3 rounds. Same VM, kernel 7.0.0-38, bpftrace 0.25, swap off, warm cache.
- Raw output: [`ab-find-parallel.txt`](ab-find-parallel.txt).

| Round | none | v1 | v2 |
|---|---:|---:|---:|
| 1 | 1.57 s | 1.94 s | 1.93 s |
| 2 | 1.60 s | 1.59 s | 2.08 s |
| 3 | 1.59 s | 2.03 s | 2.17 s |
| mean | 1.59 s | 1.85 s | 2.06 s |
| vs none | — | +17 % | +30 % |

**Result (MEAS, n = 3 per configuration):**
1. **Contention does not make the probes several times more expensive.** Tracing costs +17 % (v1) and +30 % (v2) on this job, close to the serial result (+28 % / +13 %).
2. **v2 costs somewhat more than v1 under parallel load** (+13 % relative, 3 of 3 rounds ≥ v1's mean). That's plausible for 20 extra hooks, and far from the 6× in the census runs.
3. **The untraced runs are tight** (1.57–1.60 s). The traced runs vary more (v1: 1.59–2.03 s).

**Conclusion:**
- Neither the v2 hooks nor concurrency explains the 0.17×–0.70× rate drop between the two census runs.
- The remaining explanation is **host drift**: the two runs were 29 minutes apart on a laptop under Hyper-V (INF, by elimination).
- **Consequence for method:** on this host, **a single census run cannot be trusted for absolute rates**. Rates must come from interleaved, repeated measurements. The census stays reliable for **selectivity** and for **which classes dominate**. This raises the priority of the Hyper-V on/off experiment.

**Corrects nothing further:** E-0035 already withdrew the v2-hooks explanation. This rules out the concurrency alternative.
