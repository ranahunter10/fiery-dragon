# P8: the 32-bit (compat) syscall ABI

**Question (blueprint §9.B, compat row):** a 64-bit kernel also accepts syscalls through the i386 ABI:
- from 32-bit programs;
- from any program that executes `int $0x80`.

Do the capture hooks see that I/O and exec? And what do they see? Two things are at stake:
1. **Coverage:** do `fexit vfs_read`/`vfs_write`, `security_file_open` and `sched_process_exec` fire for compat calls?
2. **Interpretation:** `raw_syscalls:sys_enter` reports the **i386 number**. For example, compat `read` is 3, which is `close` in the x86_64 table, and compat `execve` is 11, which is `munmap`.
   - A capture that decodes ids with the 64-bit table misreads these calls.
   - The census's exec flag, keyed on ids 59/322, misses a compat execve.
   - The kernel marks compat calls with `TS_COMPAT` in `thread_info.status`, set in `syscall_32_enter` (v7.0, `arch/x86/entry/syscall_32.c` line 55) before the tracepoint fires.

## Method

- **[`compat.c`](compat.c)** does one native read, then a compat open + read, an open + write, and an execve of `/bin/true`. Each I/O has its own byte count (1111, 2222, 3333), so a `vfs_*` return value identifies the operation. It prints what each call returned.
- **[`run.py`](run.py)** builds it twice:
  - **64-bit**, using `int $0x80`. No 32-bit libraries needed. In the dev container this built and ran: all calls succeeded.
  - **32-bit static** (`gcc -m32 -static`), where libc enters through the vDSO, a different compat entry stub. This needs **`gcc-multilib`**, which the VM doesn't have. Without it, the variant is reported as **SKIPPED** and the exit code is 3, not 0.
- **[`compat.bt`](compat.bt)** prints every syscall, `vfs_read`/`vfs_write` return, file open and exec of the two programs, each with the `TS_COMPAT` bit.
- **The analysis:**
  - checks that each operation produced the 12 records it should, with the right number, bit, size and name;
  - lists the compat ids seen and what an x86_64-table reader would call them;
  - counts native execve ids (59/322);
  - shows the `TS_COMPAT` bit at `sched_process_exec`.

## Run on the VM

```bash
cd ~/fiery-dragon && git fetch -q && git checkout -q bench/probes-p6-p8 && git pull -q
sudo python3 bench/probes/p8_compat/run.py
```

**Exit codes:**
- 0: both variants ran and every check passed;
- 3: every check passed, but the 32-bit variant was skipped;
- 1: a check or an operation failed.

Output goes to `/var/tmp/fd-probes/<UTC>-p8/`.

**The 32-bit variant needs a VM change (a decision for the maintainer):** `sudo apt install gcc-multilib` after a snapshot. It is dev-only and doesn't touch the held kernel.

## Tests

```bash
python3 -m unittest -v bench/probes/p8_compat/test_run.py   # 9 tests, no root, no BPF
```
