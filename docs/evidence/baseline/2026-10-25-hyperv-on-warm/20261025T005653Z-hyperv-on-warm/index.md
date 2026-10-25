# Baseline: hyperv-on-warm

- UTC start 2026-10-25T00:56:53+00:00; kernel 7.0.0-38-generic; bpftrace v0.25.0; git cb945642c0ac
- 4 CPUs, 7582980 kB; hypervisor seen by guest: KVM (oracle); swap before: /swap.img file 4G 0B -1
- host note: Hyper-V ON (everyday safe state), warm-up on, plugged in, Best performance, no other apps; snapshot: 01-toolchain; warm-up before each job: yes

| job | config | n | mean | sd | CV % | min | max | tracing slowdown |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| find-serial | none | 3 | 0.46 s | 0.13 | 28.7 ⚠ | 0.31 | 0.54 |  |
| find-serial | traced | 3 | 0.81 s | 0.15 | 18.5 ⚠ | 0.64 | 0.93 | +76 % ⚠ not quotable |
| find-parallel | none | 3 | 0.30 s | 0.07 | 23.2 ⚠ | 0.22 | 0.35 |  |
| find-parallel | traced | 3 | 0.60 s | 0.12 | 20.4 ⚠ | 0.49 | 0.74 | +101 % ⚠ not quotable |
| exec | none | 3 | 11.59 s | 1.36 | 11.8 ⚠ | 10.12 | 12.80 |  |
| exec | traced | 3 | 11.33 s | 3.05 | 26.9 ⚠ | 7.81 | 13.15 | -2 % ⚠ not quotable |
| churn | none | 3 | 28765.37 ops/s | 6161.62 | 21.4 ⚠ | 21924.40 | 33878.90 |  |
| churn | traced | 3 | 34421.90 ops/s | 4904.53 | 14.2 ⚠ | 29612.80 | 39416.60 | -16 % ⚠ not quotable |
| disk | none | 3 | 108.25 MB/s | 31.05 | 28.7 ⚠ | 89.35 | 144.08 |  |
| disk | traced | 3 | 129.12 MB/s | 36.69 | 28.4 ⚠ | 107.31 | 171.48 | -16 % ⚠ not quotable |

CV % = standard deviation / mean over rounds: the drift indicator. ⚠ marks CV > 10 %: that mean, and any slowdown computed from it, is not quotable. Slowdown > 0 means tracing made the job slower.
