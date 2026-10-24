# Census run

- UTC start: 2026-10-24T22:46:17+00:00; kernel 7.0.0-38-generic; bpftrace v0.25.0
- git a812d1b1aaf7; probe sha256 716bf951ae9f
- 4 CPUs, 7582972 kB RAM; hypervisor KVM (oracle); swap before: /swap.img file 4G 0B -1; swapoff during runs: True
- duration per workload: 60 s; workloads run as: ashu; snapshot: 01-toolchain; host: plugged in, Best performance, Hyper-V on, no other apps

| workload | status | records/s mean | p99 | max | log MB/s p99 | verdict |
|---|---|---:|---:|---:|---:|---|
| known-ops | ok | 31 | 590 | 8,762 | 0.05 | WITHIN BUDGET |
| idle | ok | 5 | 51 | 1,918 | 0.00 | WITHIN BUDGET |
| exec-storm | ok | 856 | 1,332 | 3,062 | 0.13 | WITHIN BUDGET |
| file-churn | ok | 11,473 | 16,669 | 27,308 | 1.37 | WITHIN BUDGET |
| super-producer | ok | 17,843 | 64,032 | 71,470 | 8.20 | WITHIN BUDGET |
| xfer | ok | 192 | 1,940 | 2,109 | 0.15 | WITHIN BUDGET |
| io-uring | ok | 1,823 | 1,809 | 34,474 | 0.12 | WITHIN BUDGET |

**Self-check `known-ops`** (census count must be >= operations that succeeded):

| class | expected | counted | |
|---|---:|---:|---|
| accept | 50 | 51 | ✅ |
| bind | 1 | 2 | ✅ |
| chmod | 50 | 50 | ✅ |
| chown | 50 | 50 | ✅ |
| connect | 50 | 57 | ✅ |
| connect_fail | 50 | 56 | ✅ |
| io_uring_setup | 50 | 50 | ✅ |
| link | 50 | 50 | ✅ |
| listen | 1 | 1 | ✅ |
| memfd | 50 | 50 | ✅ |
| mkdir | 50 | 51 | ✅ |
| mmap_shared_w | 50 | 50 | ✅ |
| mprotect_exec | 50 | 50 | ✅ |
| process_vm_writev | 50 | 50 | ✅ |
| ptrace | 50 | 50 | ✅ |
| rename_file | 50 | 50 | ✅ |
| rmdir | 50 | 51 | ✅ |
| symlink | 50 | 50 | ✅ |
| truncate | 50 | 56 | ✅ |
| unlink | 150 | 151 | ✅ |

Per-workload detail: `<workload>.md`. Raw: `<workload>.jsonl`. Conditions: `conditions.json`.
