# A/B, serial `find`: tracing cost on fixed work (2026-10-25)

**Question:** census v2 saw syscall rates 0.17×–0.70× those of the v1 run 29 minutes earlier (E-0033). Was that caused by the extra v2 hooks, or by something else?

**Method:**
- A fixed job (`find /usr` × 3, in sequence) is timed under three configurations: no tracing, the v1 census probe, and the v2 census probe.
- The configurations are interleaved over two rounds, so host drift hits all of them equally.
- Same VM, kernel 7.0.0-38, bpftrace 0.25, swap off, page cache warmed first.
- Exact commands: the session record of 2026-10-25. Raw output: [`ab-find-serial.txt`](ab-find-serial.txt).

| Round | none | v1 | v2 |
|---|---:|---:|---:|
| 1 | 2.62 s | 3.41 s | 2.82 s |
| 2 | 2.51 s | 3.15 s | 2.96 s |
| mean | 2.57 s | 3.28 s | 2.89 s |
| vs none | — | +28 % | +13 % |

**Result (MEAS, n = 2 per configuration, so treat it as indicative):**
- On this single-process job, **v2 is not slower than v1**.
- Tracing costs about +10–35 %, nowhere near a 6× slowdown.
- **The claim in E-0033 that the extra v2 hooks caused the rate drop is not supported. This corrects E-0033** (log row E-0035).

**Still open:**
- **Concurrency:** the census super-producer runs 5 `find`s in parallel on 4 vCPUs, and this A/B ran them in sequence. The next A/B repeats it with 5 parallel finds.
- **Host drift:** the two census runs were 29 minutes apart under Hyper-V.

**Unchanged:** selectivity was identical across the two census runs, so "untraced syscall rate × census selectivity" remains the sizing method.
