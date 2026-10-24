# Census run

- UTC start: 2026-10-24T22:17:32+00:00; kernel 7.0.0-38-generic; bpftrace v0.25.0
- git 8594df0f314e; probe sha256 fbd415242d96
- 4 CPUs, 7582980 kB RAM; hypervisor KVM (oracle); swap before: /swap.img file 4G 0B -1; swapoff during runs: True
- duration per workload: 60 s; workloads run as: ashu; snapshot: 01-toolchain; host: plugged in, Best performance, Hyper-V on, no other apps

| workload | status | records/s mean | p99 | max | log MB/s p99 | verdict |
|---|---|---:|---:|---:|---:|---|
| idle | ok | 6 | 0 | 2,381 | 0.00 | WITHIN BUDGET |
| exec-storm | ok | 2,481 | 4,274 | 4,753 | 0.41 | WITHIN BUDGET |
| file-churn | ok | 38,320 | 79,951 | 90,990 | 6.69 | WITHIN BUDGET |
| super-producer | ok | 105,731 | 221,670 | 353,461 | 28.36 | EXCEEDS BUDGET |
| xfer | ok | 261 | 2,236 | 2,527 | 0.18 | WITHIN BUDGET |
| io-uring | ok | 3,483 | 23,099 | 234,106 | 1.48 | WITHIN BUDGET |

Per-workload detail: `<workload>.md`. Raw: `<workload>.jsonl`. Conditions: `conditions.json`.
