# Baseline: hyperv-off-B

- UTC start 2026-10-25T00:11:50+00:00; kernel 7.0.0-38-generic; bpftrace v0.25.0; git d3d55c78e5b4
- 4 CPUs, 7582980 kB; hypervisor seen by guest: KVM (oracle); swap before: /swap.img file 4G 0B -1
- host note: Hyper-V OFF (HypervisorPresent=False, VBS=0, Memory integrity off, VBox VT-x), plugged in, Best performance, no other apps; snapshot: 01-toolchain

| job | config | n | mean | sd | CV % | min | max | tracing slowdown |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| find-serial | none | 3 | 3.21 s | 2.63 | 82.0 ⚠ | 1.56 | 6.24 |  |
| find-serial | traced | 3 | 2.54 s | 0.22 | 8.8 | 2.30 | 2.74 | -21 % ⚠ not quotable |
| find-parallel | none | 3 | 0.59 s | 0.29 | 48.0 ⚠ | 0.27 | 0.79 |  |
| find-parallel | traced | 3 | 1.12 s | 0.16 | 14.0 ⚠ | 0.96 | 1.27 | +89 % ⚠ not quotable |
| exec | none | 3 | 6.85 s | 0.44 | 6.4 | 6.37 | 7.24 |  |
| exec | traced | 3 | 7.58 s | 0.53 | 6.9 | 7.13 | 8.16 | +11 % |
| churn | none | 3 | 14185.40 ops/s | 8569.94 | 60.4 ⚠ | 8684.80 | 24059.70 |  |
| churn | traced | 3 | 7572.80 ops/s | 605.14 | 8.0 | 7149.40 | 8265.90 | +87 % ⚠ not quotable |
| disk | none | 3 | 154.27 MB/s | 14.83 | 9.6 | 138.30 | 167.62 |  |
| disk | traced | 3 | 153.67 MB/s | 19.54 | 12.7 ⚠ | 131.98 | 169.90 | +0 % ⚠ not quotable |

CV % = standard deviation / mean over rounds: the drift indicator. ⚠ marks CV > 10 %: that mean, and any slowdown computed from it, is not quotable. Slowdown > 0 means tracing made the job slower.
