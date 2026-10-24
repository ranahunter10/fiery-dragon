# Census, light workloads: first real numbers (2026-10-24 22:17 UTC)

**What:** P10 event-rate census, light set, 60 s per workload. Run with `bench/census/run.py` at commit `8594df0`, probe sha256 `fbd41524…`, which matches the committed `census.bt`.

**Where and how:**
- VM `p15-dev-2604` at snapshot `01-toolchain`: kernel 7.0.0-38, bpftrace 0.25.0, 4 vCPU, 7.2 GiB.
- Host: plugged in, Best performance, Hyper-V on, no other apps (operator's note).
- Swap was off during runs. Workloads ran as `ashu`.
- All six runs are **ok**: bpftrace stopped cleanly, output complete, **0 lost events**, workloads exited 0.

**Integrity:**
- Tarball `census-light.tgz` sha256: `2b29f3d98e926a107a9107ce5afbe969e82a7ba9403b6d77ba6ab84767e7b0c8`, the same value the VM printed and received.
- The raw files are byte for byte: see `SHA256SUMS`.

## Results

Rates are per second, over 100 ms windows. Log bandwidth uses the **assumed** record sizes: 64 B, exec 256 B, open 128 B (INF until ADR-0008). The budget is 63.7 MB/s ÷ 3 = 21.2 MB/s.

| Workload | Syscalls/s mean | Emitted records/s mean | p99 | max | Log MB/s p99 | Verdict | Dominant classes (mean/s) |
|---|---:|---:|---:|---:|---:|---|---|
| idle | 135 | 6 | 0 | 2,381 | 0.00 | within | background noise |
| exec-storm | 12,820 | 2,481 | 4,274 | 4,753 | 0.41 | within | rd_reg 1,239 · open 1,008 · exec/fork/exit 77 each |
| file-churn | 58,420 | 38,320 | 79,951 | 90,990 | 6.69 | within | wr_reg 14,119 · rd_reg 12,242 · open 11,955 |
| **super-producer** | **1,585,601** | **105,731** | **221,670** | **353,461** | **28.36** | **EXCEEDS** | **open 105,637** (find opening directories) |
| xfer | 1,042 | 261 | 2,236 | 2,527 | 0.18 | within | splice 124 (130 MB/s payload) · splice_direct 2 |
| io-uring | 3,960 | 3,483 | 23,099 | 234,106 | 1.48 | within | uring 2,454 · wr_reg bursts (fio file layout) |

## What the numbers say

Each finding is graded. MEAS means it is visible in the raw files here.

1. **The super-producer exceeds the budget, and one class causes it: `open`** (MEAS).
   - `find /usr` × 5 drove **1.59 M syscalls/s** on average (3.3 M p99, 5.3 M peak), but only **6.7 %** became records.
   - Of those, `open` is 99.9 %: 105,637/s mean, 221,434/s p99, 353,167/s peak. These are almost all **directory opens**: find opens each directory to list it.
   - At the assumed 128 B per open record, p99 is 28.4 MB/s, against a budget of 21.2 MB/s.
   - **Implications:**
     - The budget question is really about **OPEN records**. Their size, which depends on whether every record carries the full path, and whether directory opens get their own "what kind" class, both decide it.
     - At 64 B, the same p99 would be 14 MB/s, within budget (INF: arithmetic on MEAS rates).
   - Inputs to **ADR-0005** (filtering by kind), **ADR-0008** (schema: path once per file, or in every record) and **ADR-0006** (ring sizing for ~350 k records/s peaks).
2. **io_uring file I/O is invisible to `vfs_read`/`vfs_write` hooks** (MEAS).
   - During fio's steady state, `uring` completions run at 2,454/s while `rd_reg` stays at 7/s.
   - The `wr_reg` bursts (max 234,066/s) are fio laying out its file with plain writes before the io_uring phase.
   - This confirms on the target that the io_uring hook is required, not optional.
3. **In-kernel copies move data with almost no records** (MEAS). `xfer` moved ~130 MB/s through `splice` with 124 records/s.
   - This confirms that byte totals, not call counts, carry the meaning for transfer records.
   - It also confirms E-0018: `cat` uses splice.
4. **One `cp` fires two of our hooks; the one-layer rule is needed** (MEAS).
   - `copy_range` = **60** (one per iteration, from `cp`), and `splice_direct` = **120**, each call exactly 67,108,864 B = 64 MiB.
   - On ext4, which has no reflink, `vfs_copy_file_range` falls back **internally** to `do_splice_direct`. The other 60 are the Python `sendfile`.
   - So every `cp` is counted at **both** layers. The product must emit **one** transfer record per copy: the outermost hook wins, and the nested `do_splice_direct` is suppressed (blueprint §4.1, "count each transfer at exactly one layer").
   - The census reports both on purpose. In this workload the overlap inflates the transfer counts by 60 per minute.
   - *(An earlier draft of this note said `copy_range` was 0. That was wrong: the per-class printout used to check it was truncated to the top 9 classes. Recomputed from the raw file before commit.)*
5. **Process creation is slow on this VM** (MEAS rate; cause INF).
   - `exec-storm` reached **77 execs/s**. The 2-vCPU dev container managed 633/s with a lighter probe set.
   - Likely causes: process creation under VirtualBox-on-Hyper-V (page-table work), plus probe overhead.
   - **An untraced baseline (P12) and the planned Hyper-V on/off experiment are needed** before any exec-rate number is quoted as a property of the design.
6. **The record-class list has a gap: file metadata operations are not counted** (design finding, not a measurement).
   - `file-churn` deleted ~243,000 files (workload log), and the census has no class for that.
   - The blueprint's record list also has no class for **unlink, rename, chmod/chown, link/symlink, mkdir/rmdir, truncate**. Yet "rename a dropped file into `/usr/bin`", "chmod +x then exec" and "delete the evidence" are core attack steps, and the DARPA TC schema has unlink and rename events.
   - The census v2 and the record-class ADR (0010) must add a **META** family. The same goes for connect/accept/bind and the capability family (mmap, memfd, ptrace), which census v1 doesn't count yet.
7. **bpftrace's 100 ms timer slips under extreme load** (MEAS): `super-producer` has 408 windows in 60.9 s, not ~609.
   - Rates stay correct, because the summarizer divides by the real elapsed time.
   - But "p99 of 100 ms windows" becomes "p99 of ~150 ms windows" for that workload, which smooths the peaks slightly.
8. **The census's own cost is not the product's** (INF). The census hooks `raw_syscalls` enter **and** exit on every syscall, which is 3.2 M probe runs/s in `super-producer`. The product hooks neither, so overhead measured with the census overstates the product's.

## Not concluded here

- No overhead numbers: the census is not an overhead benchmark (L7).
- Nothing about Nginx, Redis or kernel builds: the service workloads PR comes next.
- The verdicts depend on the **assumed** record sizes and on this VM's virtual disk (63.7 MB/s minimum under Hyper-V). Both are inputs to decisions, not results.
