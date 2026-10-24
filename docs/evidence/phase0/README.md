# Phase 0 evidence: platform and kernel facts

These are the raw outputs from VM `p15-dev-2604`, captured on 2026-10-21 (UTC), and committed **byte for byte**. Don't edit them. `SHA256SUMS` lets anyone check that.

**How they got here:**
- Captured on the VM in `~/p15-evidence/`.
- Packed there with `tar czf ~/p15-evidence-phase0.tgz -C ~ p15-evidence` and copied out with `scp`.
- The tarball received on 2026-10-25 has sha256 `334b1b2a12c02f9ac2740bbbe17a663fd9fe09e369e2d893315138c816a6b223` (6,568 bytes).
- The members were checked to be plain files with relative paths before extraction.

**Conditions for all files:**
- Host: Windows laptop, i5-1135G7 (4C/8T), 16 GB, Hyper-V present (VirtualBox runs on the Windows hypervisor), VirtualBox 7.2.22.
- VM: 4 vCPU, 8 GB, 64 GB fixed VDI on SATA AHCI, host I/O cache off.
- Guest: Ubuntu 26.04.1, kernel 7.0.0-38-generic (held).
- VM snapshots: `00-fresh-pinned` for file 00, `01-toolchain` for files 01–05.

| File | Probe | What it establishes | Grade |
|---|---|---|---|
| [`00-vm-baseline.txt`](00-vm-baseline.txt) | baseline, P3, P4 | OS and kernel; kernel packages held; no `bpf` in the LSM list; lockdown `none`; Secure Boot off; clocksource `tsc`; BTF present (7,067,009 B); timezone UTC; 4 GB swap present | MEAS |
| [`01-toolchain.txt`](01-toolchain.txt) | toolchain | clang 21.1.8 with BPF targets; bpftool 7.7.0 built on libbpf 1.7 with an empty `features:` line; libbpf-dev 1.6.3; pahole 1.31; bpftrace 0.25.0; gcc 15.2.0; perf 7.0.14; Python 3.14.4 | MEAS |
| [`02-p1-attach-points.txt`](02-p1-attach-points.txt) | P1 | Every function the design hooks is in BTF and in `available_filter_functions`, **except `__sock_sendmsg`** (inlined). All 9 needed tracepoints exist | MEAS |
| [`03-p2-feature-probe.txt`](03-p2-feature-probe.txt) | P2 | Full `bpftool feature probe kernel`: program types `tracing`, `lsm`, `syscall`, `raw_tracepoint`; maps `ringbuf`, `user_ringbuf`, `task_storage` available; `inode_storage` **not** available | MEAS |
| [`04-p1b-fexit-check.txt`](04-p1b-fexit-check.txt) | P1b | No `.isra`/`.constprop`/`.part` clones of the key functions; BTF signatures of vfs_read/write/readv/writev, security_file_open, do_splice, vfs_copy_file_range; fields of `sock:sock_send_length`; **live fexit on `vfs_read` read 769 calls / 795,645 bytes in 3 s** | MEAS |
| [`05-p5-disk.txt`](05-p5-disk.txt) | P5 | Sequential write, 3 × 30 s each: direct 1 MiB 63.7 / 105 / 92.3 MB/s; buffered 64 KiB + fdatasync per MiB 65.8 / 93.4 / 110 MB/s | MEAS |

## Reading notes and corrections

1. **The LINKAGE column in file 02 is meaningless.** It shows `static` for every function, including the exported `vfs_read`, because pahole encodes all vmlinux functions that way. It cannot detect inlining. The clone check in file 04 is the proper check. *(Correction made 2026-10-21.)*
2. **`bpf_get_func_ret` / `bpf_get_func_arg` are absent from file 03. That is expected, not a missing feature.**
   - In file 03 (lines 2318–2325), bpftool prints **"Could not determine which helpers are available"** for the program types `tracing`, `struct_ops`, `ext` and `lsm`. It does not probe helpers for types that need an attach target.
   - These helpers exist only for tracing programs, so file 03 cannot show them.
   - File 04's live fexit test reads `retval` successfully.
   - **Status: INF.** It becomes MEAS when the first program that calls `bpf_get_func_ret()` loads on this VM.
3. **`bpf_d_path` appears once in file 03 (line 2466), under program type `syscall`.** Whether it is usable from our `fexit` programs on `security_file_open` must be shown by a real load, for the reason in note 2. **Status: OPEN.**
4. **Disk variance is large (±25 %), and run 1 is the slowest in both series.** Quote the minimum. Any later disk measurement must repeat ≥ 3 runs and record the Hyper-V state.
5. **Trailing whitespace** in files 00 and 01 is part of the raw tool output and is kept on purpose, so that the hashes stay valid.
