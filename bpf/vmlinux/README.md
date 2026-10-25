# Kernel type headers (`vmlinux.h`)

BPF programs get kernel types from a header dumped from the target kernel's BTF, so the build needs no kernel headers. CO-RE relocations then adjust field offsets at load time (ADR-0002).

| File | What |
|---|---|
| `vmlinux.h` | the include the programs use; selects the dump for the pinned kernel |
| `vmlinux-7.0.0-38.h` | **generated**: the dump for 7.0.0-38-generic, the kernel of ADR-0001 |
| `SHA256SUMS` | checksum of the dump; CI verifies it |

**How `vmlinux-7.0.0-38.h` was made:**
- On VM `p15-dev-2604` (kernel 7.0.0-38-generic, distro bpftool v7.7.0), on 2026-10-25, with:
  ```bash
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > ~/vmlinux-7.0.0-38.h
  ```
- It was copied off the VM with `scp` and committed unchanged: 3,522,907 bytes, sha256 `e1b0accd1e92c990e40a06af44a238686b2702546714d32b5b5ea465dca7c907`, LF line endings.
- The VM-side checksum was not pasted, so the hash above is the one taken on receipt.

**Don't edit it.** For a new kernel, dump a new file, add it next to this one, and change the include in `vmlinux.h`. A kernel change is a new ADR (ADR-0001).
