# Build scaffolding: vendored toolchain, vmlinux.h, CO-RE smoke (2026-10-25)

**Where:** the cloud dev container (Ubuntu 24.04 userland, kernel 6.18.44, clang 18.1.3, running as root). **This is not the target kernel.** The authoritative run is on the VM, still to do.

| File | What it shows |
|---|---|
| [`01-vmlinux-needs-ms-extensions.txt`](01-vmlinux-needs-ms-extensions.txt) | clang rejects the 7.0 `vmlinux.h` without `-fms-extensions` |
| [`02-build-and-smoke.txt`](02-build-and-smoke.txt) | the full build from clean with the vendored libbpf v1.7.0 and bpftool v7.7.0, and both smoke programs passing |
| [`03-vm-build-no-openssl.txt`](03-vm-build-no-openssl.txt) | **the first VM build** (commit 3334b50, kernel 7.0.0-38, clang 21.1.8): the bpftool bootstrap fails, because OpenSSL headers are missing |

## Findings (MEAS, dev container)

1. **Kernel 7.0's BTF contains anonymous *tagged* members** that a plain C compiler rejects. Five sites:
   - `struct aes_enckey;` inside `struct aes_key`;
   - `struct ns_tree;`;
   - `struct __filename_head;`;
   - `union pipe_index;`;
   - `struct freelist_counters;`.

   `clang -Wall -Werror` fails with "declaration does not declare anything". Compiling with `-fms-extensions -Wno-microsoft-anon-tag` builds it. That flag gives these members the meaning the kernel's own build gives them: the kernel is built with `-fms-extensions` (INF; not checked in the kernel Makefile here).
   - Whether clang 21 on the VM needs the same flag: INF yes; the VM build settles it.
2. **The vendored toolchain builds from clean:** static libbpf from `third_party/libbpf` (v1.7.0), and bpftool bootstrap from `third_party/bpftool` (v7.7.0). The bootstrap bpftool reports `v7.7.0, using libbpf v1.7`.
3. **CO-RE smoke passes:**
   - `core_smoke.bpf.c` reads `task->group_leader->start_boottime` and `task->tgid` with CO-RE at `tp_btf/sched_process_exec`, and sends them through a ring buffer.
   - Loaded through its bpftool-generated skeleton and attached, it saw the test child's exec with the child's tgid and a non-zero start time.
   - `seen 1, reserve_failed 0`.
   - This exercises ADR-0002 (toolchain), ADR-0003 (tp_btf spine hook), ADR-0006 (ring buffer, counted reserve failure) and ADR-0009 (identity fields), on a non-target kernel.

## Findings on the VM (MEAS, the target)

4. **The first VM build failed in the bpftool bootstrap:** `sign.c: fatal error: openssl/opensslv.h: No such file or directory`.
   - bpftool v7.7.0 links libcrypto unconditionally (`LIBS_BOOTSTRAP = … -lcrypto …` in `third_party/bpftool/src/Makefile` line 128) for program signing, so **`libssl-dev` is a build dependency**.
   - The dev container and the CI runner happen to have it; the VM doesn't.
   - Fix: a `make deps` check that names the missing package, `libssl-dev` added to CI's package list and to the runbook (§5a).
   - The file's sha256 starts `a8bb14713cfd1c52abcf`, which matches the 29 hex digits of the VM's `sha256sum` pasted in chat. The paste was cut off.
5. **On the VM, clang 21.1.8 built `vmlinux-7.0.0-38.h` and `core_smoke.bpf.o` without errors**, with `-fms-extensions` in the flags. libbpf v1.7.0 also built.
   - Whether clang 21 would fail *without* the flag was not tried there.
