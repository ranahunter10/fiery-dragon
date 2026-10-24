# Census v2: hooks validated, and the probe set changes the rates (2026-10-24 22:46 UTC)

**What:** census v2 with `--workloads check,light`, 60 s each.

**Provenance:**
- Commit `a812d1b` (clean), probe sha256 `716bf951…`, which matches the committed `census.bt`.
- Same VM, snapshot and host note as the [light run](../2026-10-24T221732Z-light/README.md) 29 minutes earlier: kernel 7.0.0-38, bpftrace 0.25.0, Hyper-V on, swap off.
- Tarball sha256 `63c318c81b9662c9f764655c5808e6d7aa5e49b99d3b1c3f51e50eb1a1d29321`, as printed on the VM. Raw files are byte for byte (`SHA256SUMS`).

**Status:** the attach pre-flight found all 27 functions and 9 tracepoints (BTF and ftrace both checked). All seven runs are **ok**, with 0 lost events.

## 1. All 20 new hooks deliver on kernel 7.0 (MEAS)

`known-ops` performed exact numbers of each operation, and the census counted at least that many for **every** class:

| class | expected | counted | | class | expected | counted |
|---|---:|---:|---|---|---:|---:|
| mkdir | 50 | 51 | | connect | 50 | 57 |
| rmdir | 50 | 51 | | connect_fail | 50 | 56 |
| unlink | 150 | 151 | | accept | 50 | 51 |
| rename_file | 50 | 50 | | bind | 1 | 2 |
| link | 50 | 50 | | listen | 1 | 1 |
| symlink | 50 | 50 | | mmap_shared_w | 50 | 50 |
| chmod | 50 | 50 | | mprotect_exec | 50 | 50 |
| chown | 50 | 50 | | memfd | 50 | 50 |
| truncate | 50 | 56 | | ptrace | 50 | 50 |
| | | | | process_vm_writev | 50 | 50 |
| | | | | io_uring_setup | 50 | 50 |

- **Twelve classes match exactly.** The surplus in the others is background activity during the 60 s window (sshd, the runner), which can only add.
- So, for the hooks and success conditions in census v2 on this kernel, **no silent hook** of the kind seen with `syscalls:sys_enter_*` (E-0022).

## 2. Rates differ a lot from the v1 run; the cause is NOT the v2 hooks (corrected)

> **Correction (2026-10-25, E-0035).** This section first attributed the rate drop to the extra v2 hooks. An interleaved A/B on fixed work ([`../2026-10-25-ab-find-serial/`](../2026-10-25-ab-find-serial/README.md)) found v2 **no slower** than v1: serial `find` ×3 took 2.57 s untraced, 3.28 s under v1 and 2.89 s under v2. The table and the selectivity result below stand. The interpretation in the bullets ("the slowdown grows with syscall rate… some hook adds a per-syscall tax") does **not**. The remaining candidates are host drift between the two runs and a concurrency effect (5 parallel finds); both are being tested. The original text is kept below so the history stays honest.

### Original analysis (superseded where noted above)

The same workloads, same VM, 29 minutes apart. The only planned difference is the v2 probe set (+27 fexit functions vs +7):

| Workload | Syscalls/s, v1 probe | Syscalls/s, v2 probe | v2/v1 | Selectivity v1 | Selectivity v2 |
|---|---:|---:|---:|---:|---:|
| idle | 135 | 78 | 0.58 | 0.043 | 0.068 |
| exec-storm | 12,820 | 4,430 | **0.35** | 0.193 | 0.193 |
| file-churn | 58,420 | 15,997 | **0.27** | 0.656 | 0.717 |
| super-producer | 1,585,601 | 267,565 | **0.17** | 0.067 | 0.067 |
| xfer | 1,042 | 733 | 0.70 | 0.250 | 0.262 |
| io-uring | 3,960 | 2,186 | 0.55 | 0.880 | 0.834 |

The workloads' own logs agree. `file-churn` completed 245,079 reads under v1 and 68,709 under v2: **3.6× less work in the same 60 s**.

What this means:
- **Selectivity is a property of the workload and holds steady across probe sets**: exec-storm 0.193 → 0.193, super-producer 0.067 → 0.067, file-churn 0.66 → 0.72. **Rates are not**: they depend on how much the probes slow the workload.
- So the "records/s" figures from either run are **lower bounds** for what the product would see. The v1 "super-producer exceeds the budget" result (E-0026) and the v2 "everything within budget" result are both statements about a slowed-down machine.
- **Sizing must use:** projected records/s = **untraced** syscall rate × census selectivity. The untraced rate comes from P12 (no BPF attached).
- **The slowdown grows with the syscall rate** (super-producer worst, xfer least). That points to a per-syscall cost added by the v2 set, not general host contention (INF). None of the v2 hooks is on `find`'s obvious hot path (openat, getdents64, newfstatat, close), so which hook costs what is **OPEN**.
- **For the product this matters more than any rate.** One of the hooks the design plans to use may impose a per-syscall tax. An A/B bisection (untraced; v1; v2; v2 minus each family) will find it. That's the next PR.

## 3. Other observations

- `super-producer` under v2: OPEN is still 99.9 % of emitted records (17,825 of 17,843/s). The record mix doesn't depend on the probe set.
- `exec-storm`: `mmap_exec` ≈ 212/s, about 8 library mappings per exec at 26 execs/s. If code-mapping records were ever emitted, they would outnumber exec records ~8:1 (input for ADR-0010).
- `file-churn`: the census counted **68,878 unlinks** = 68,425 deletes during the run + 449 files removed at cleanup + 4 from the background. That's **exact** against the workload's own log. (A first draft compared per-second rates over different durations; the totals are the right comparison.)

## Not concluded here

- No claim about what the product's overhead or rates will be. Both need the untraced baseline (P12) and the A/B bisection.
