# Baseline: hyperv-on-A1

- UTC start 2026-10-24T23:33:39+00:00; kernel 7.0.0-38-generic; bpftrace v0.25.0; git d3d55c78e5b4
- 4 CPUs, 7582972 kB; hypervisor seen by guest: KVM (oracle); swap before: /swap.img file 4G 0B -1
- host note: Hyper-V ON, plugged in, Best performance, no other apps; snapshot: 01-toolchain

| job | config | n | mean | sd | CV % | min | max | tracing slowdown |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| find-serial | none | 3 | 2.50 s | 0.28 | 11.0 ⚠ | 2.18 | 2.67 |  |
| find-serial | traced | 3 | 3.55 s | 0.26 | 7.4 | 3.25 | 3.70 | +42 % ⚠ not quotable |
| find-parallel | none | 3 | 1.11 s | 0.17 | 15.7 ⚠ | 0.96 | 1.30 |  |
| find-parallel | traced | 3 | 2.09 s | 0.03 | 1.4 | 2.06 | 2.12 | +88 % ⚠ not quotable |
| exec | none | 3 | 37.83 s | 2.79 | 7.4 | 34.62 | 39.60 |  |
| exec | traced | 3 | 38.05 s | 1.45 | 3.8 | 36.38 | 38.92 | +1 % |
| churn | none | 3 | 5026.03 ops/s | 297.07 | 5.9 | 4769.90 | 5351.70 |  |
| churn | traced | 3 | 4518.57 ops/s | 47.28 | 1.0 | 4464.20 | 4550.10 | +11 % |
| disk | none | 3 | 72.73 MB/s | 6.61 | 9.1 | 66.86 | 79.89 |  |
| disk | traced | 3 | 85.60 MB/s | 11.11 | 13.0 ⚠ | 75.91 | 97.72 | -15 % ⚠ not quotable |

CV % = standard deviation / mean over rounds: the drift indicator. ⚠ marks CV > 10 %: that mean, and any slowdown computed from it, is not quotable. Slowdown > 0 means tracing made the job slower.
