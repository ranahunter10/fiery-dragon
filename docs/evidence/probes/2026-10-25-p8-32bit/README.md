# P8 with gcc-multilib: both compat entry paths (2026-10-25 01:31 UTC)

**What:** `sudo apt install -y gcc-multilib` (decision E-0048), then `bench/probes/p8_compat/run.py` at commit `2ec3326`. That commit includes the TS_COMPAT normalization fix (E-0051).

**Raw output:**
- [`terminal.txt`](terminal.txt) is the operator's terminal transcript, as attached, byte for byte (`SHA256SUMS`).
- The run directory on the VM is `/var/tmp/fd-probes/20261025T013114Z-p8`; its raw probe output is to be added.

**Conditions:**
- **Installed:** 21 packages: `gcc-multilib`, `libc6-dev-i386`, the lib32/libx32 runtimes, and so on.
- **The kernel is unchanged:** after the install, `apt-mark showhold` still lists `linux-generic`, `linux-headers-generic` and `linux-image-generic`, and `uname -r` prints `7.0.0-38-generic`.
- **The pre-install state is the `01-toolchain` snapshot.** The transcript's first line is the snapshot command pasted as a shell comment, so **no `02-multilib` snapshot was taken by it**.

## Findings (MEAS)

1. **Both variants pass all 12 checks; P8 exits 0.**
2. **The 32-bit variant behaves like the `int $0x80` one.** That variant is a static i386 program whose libc enters the kernel through the vDSO.
   - `fexit vfs_read` saw 1111 and 2222 bytes and `fexit vfs_write` saw 3333 bytes, all with TS_COMPAT set.
   - `fexit security_file_open` saw the opens of both files.
   - `sched_process_exec` saw the exec of `/bin/true`.
   - This closes the open item in E-0050.
3. **Every syscall a 32-bit program makes enters with TS_COMPAT set and its i386 number.**
   - In this run: 3, 4, 5, 6, 11, 45, 125, 191, 192, 243, 258, 295, 305, 311, 355, 383, 386. Examples: `brk`, `mprotect`, `mmap2`, `set_thread_area`, `openat`.
   - None of them is reported as id 59 or 322.
   - A 64-bit syscall table is wrong for every one of them.
