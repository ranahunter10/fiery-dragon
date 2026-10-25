# Baseline: hyperv-on-A2

- UTC start 2026-10-25T00:27:24+00:00; kernel 7.0.0-38-generic; bpftrace v0.25.0; git d3d55c78e5b4
- 4 CPUs, 7582980 kB; hypervisor seen by guest: KVM (oracle); swap before: /swap.img file 4G 0B -1
- host note: Hyper-V ON again (VBS=2, Memory integrity on), fresh boot, plugged in, Best performance, no other apps; snapshot: 01-toolchain

| job | config | n | mean | sd | CV % | min | max | tracing slowdown |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| find-serial | none | 3 | 6.92 s | 9.26 | 133.8 ⚠ | 1.53 | 17.61 |  |
| find-serial | traced | 3 | 2.03 s | 0.23 | 11.5 ⚠ | 1.78 | 2.24 | -71 % ⚠ not quotable |
| find-parallel | none | 3 | 0.72 s | 0.41 | 56.4 ⚠ | 0.25 | 0.99 |  |
| find-parallel | traced | 3 | 1.56 s | 0.05 | 3.0 | 1.52 | 1.61 | +117 % ⚠ not quotable |
| exec | none | 3 | 28.06 s | 1.17 | 4.2 | 26.72 | 28.89 |  |
| exec | traced | 3 | 30.35 s | 0.83 | 2.7 | 29.77 | 31.29 | +8 % |
| churn | none | 3 | 12711.87 ops/s | 1648.70 | 13.0 ⚠ | 10904.40 | 14133.30 |  |
| churn | traced | 3 | 8628.77 ops/s | 2043.41 | 23.7 ⚠ | 7362.00 | 10986.10 | +47 % ⚠ not quotable |
| disk | none | 3 | 118.72 MB/s | 2.67 | 2.2 | 116.58 | 121.71 |  |
| disk | traced | 3 | 125.00 MB/s | 23.79 | 19.0 ⚠ | 111.00 | 152.47 | -5 % ⚠ not quotable |

CV % = standard deviation / mean over rounds: the drift indicator. ⚠ marks CV > 10 %: that mean, and any slowdown computed from it, is not quotable. Slowdown > 0 means tracing made the job slower.
