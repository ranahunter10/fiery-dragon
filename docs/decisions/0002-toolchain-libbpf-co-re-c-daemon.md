---
status: accepted
date: 2026-10-25
owner: Ashish Rana
consulted: [capture blueprint v1 §0, §2.3, §3 (2026-10-21), E-0004, E-0013, E-0054, v3.7 G3 loss study]
supersedes: none
---

# 0002: Build with libbpf v1.7.0 + CO-RE skeletons and a C daemon; Python only after the WAL

## Context and problem statement

v3.7 loaded BPF with BCC and drained events in Python. Its drain topped out at about 9,400 records/s, falling to about 4,300/s under load, because Python ran per record on the event path (blueprint L2).

The VM now has two libbpf versions:
- libbpf-dev 1.6.3 from the distro;
- libbpf 1.7, built into bpftool 7.7.0 (E-0004).

So "which libbpf" is ambiguous unless pinned.

**Question:** what compiles and loads the BPF programs, what language drains them, and which exact versions are used?

## Decision drivers

1. Nothing slow on the event path: the kernel→WAL path must sustain well above v3.7's ceiling.
2. Reproducible builds: the same sources give the same objects on the VM, in CI and on a reviewer's machine.
3. No runtime compiler and no kernel headers on the target (CO-RE).
4. One language for the BPF programs and the loader, so layouts and tests are shared.
5. Mainstream tooling a reviewer can check: what libbpf-tools and Falco's modern probe use.

## Considered options

1. **C + libbpf (vendored v1.7.0) + CO-RE + bpftool-generated skeletons**; Python only reads the WAL
2. Rust: libbpf-rs or aya
3. Go: cilium/ebpf
4. BCC with a Python drain (v3.7)

## Decision outcome

**Chosen option:** option 1, because it meets drivers 1, 3 and 4 directly. It is also the stack the kernel's own BPF selftests and libbpf-tools use (driver 5). **The language choice (C rather than Rust or Go) is the maintainer's** (blueprint Q-D2). Accepting this ADR takes it.

| Component | Choice | Pin |
|---|---|---|
| BPF programs | C, compiled with clang `-target bpf -O2 -g` | clang 21.1.8 on the VM (E-0004) |
| Loader library | **libbpf v1.7.0**, vendored as a git submodule at `third_party/libbpf` | tag `v1.7.0` = commit `f5dcbae736e5d7f83a35718e01be1a8e3010fa39` |
| Skeletons | `bpftool gen skeleton` | **bpftool v7.7.0** (the same version as on the VM), vendored as a submodule at `third_party/bpftool`, tag `v7.7.0`, so CI generates identical skeletons |
| Kernel types | `vmlinux.h` dumped from the target's BTF (`bpftool btf dump file /sys/kernel/btf/vmlinux format c`) | checked in as `bpf/vmlinux/vmlinux-7.0.0-38.h`, generated |
| Daemon (`p15d`) | C (gnu11), `-Wall -Wextra -Werror`, linked statically against the vendored libbpf | — |
| Analysis tier | Python 3.14 in a project venv, torch from the PyTorch CPU index | E-0054 |
| bpftrace | measurement scripts in `bench/` only, **never** part of the product | — |
| Licences | BPF programs `GPL-2.0-only OR BSD-2-Clause`; everything else MIT | `LICENSES/` |

**Rules:**
- **Python never sits on the kernel→WAL path.** It reads WAL segments (ADR-0007) in batches.
- **The distro libbpf-dev (1.6.3) is not used by the product.** It stays installed, since bpftrace and other tools depend on it.
- **Authoritative builds happen on the VM.** CI builds with the runner's clang as a smoke check. A pinned build container that matches the VM's clang is a Phase-1 task, and until it exists CI is not authoritative for BPF objects.

### Consequences

- Good: the drain is C. A C libbpf consumer drains roughly 1–10 M records/s in the kernel's own benchmark, depending on wakeup batching. That is two to three orders of magnitude above the v3.7 ceiling; it is a design input, not yet our measurement.
- Good: one vendored libbpf and one bpftool, so skeletons and loader behaviour are identical everywhere they are built.
- Good: CO-RE plus BTF means one object for the pinned kernel without kernel headers.
- Bad: C is unforgiving for the daemon (memory safety). Mitigations: small daemon scope (drain, WAL, stats); `-Werror`; unit tests; fuzzing the WAL reader (blueprint L1).
- Bad: two submodules to keep at their pins, and a build step for bpftool in CI.

### Confirmation

- `git submodule status` shows `third_party/libbpf` at `f5dcbae7…` and `third_party/bpftool` at its `v7.7.0` commit. CI fails if they move without a change to this ADR's table (Phase-1 task).
- The daemon prints `libbpf_version_string()` and the skeleton's bpftool version at start, and writes both into the WAL header (ADR-0007).
- The CI `bpf` job already builds a tp_btf and a syscall program with BTF and loads them through the verifier (`bpf/test/load_check.c`, PR #15).

### Falsifier

Reopen if:
- libbpf v1.7.0 lacks something a Phase-1 program needs, and a later tag has it;
- the C daemon can't sustain the zero-loss knee target (≥ 10× v3.7 on the spine, blueprint Phase 1) and profiling shows the language or library is the cause, not the design;
- the maintainer chooses Rust or Go for the daemon (Q-D2).

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | VM toolchain: clang 21.1.8, libbpf-dev 1.6.3, bpftool 7.7.0 using libbpf 1.7, pahole 1.31, gcc 15.2.0, Python 3.14.4 | MEAS | [`01-toolchain.txt`](../evidence/phase0/01-toolchain.txt); E-0004 |
| 2 | Maintainer decision: vendor the latest libbpf 1.7.x tag | decision | E-0013 |
| 3 | The latest libbpf 1.7.x tag is `v1.7.0` → `f5dcbae7…`; bpftool's `v7.7.0` tag exists | MEAS | `git ls-remote --tags` on github.com/libbpf/libbpf and /libbpf/bpftool, 2026-10-25 |
| 4 | v3.7's Python drain: about 9,395 records/s, about 4,287/s under load | MEAS | v3.7 project, `G3_loss_under_load_2026-10-19.md` (old repo; not re-run) |
| 5 | BCC's Python API calls a Python function for every record | SRC | `bcc/table.py`, via blueprint v1 §2.3 |
| 6 | A C libbpf ring-buffer consumer: about 0.93 M rec/s with a wakeup per record, about 9.9 M/s batched | SRC | kernel commit c97099b0 (ringbuf benchmark), via blueprint v1 §2.3; different hardware |
| 7 | The analysis packages install as binaries on 3.14; maintainer chose 3.14 | MEAS, decision | E-0053, E-0054 |
| 8 | A tp_btf and a syscall program built with clang and loaded with libbpf pass the verifier (dev container, kernel 6.18) | MEAS | PR #15 commit message; CI `bpf` job |

## Pros and cons of the options

### 1. C + libbpf
- Good: shared language with the BPF programs; the reference stack; smallest runtime.
- Bad: memory safety is on us.

### 2. Rust (libbpf-rs / aya)
- Good: memory safety in the daemon.
- Bad: a second language next to the BPF C; aya uses its own loader, not libbpf; extra build complexity in CI.

### 3. Go (cilium/ebpf)
- Good: mature (Tetragon uses it); safe.
- Bad: a garbage collector on the drain path; a second language; its own loader, so libbpf behaviour differs.

### 4. BCC + Python drain
- Bad: the measured v3.7 ceiling (evidence 4); a runtime compiler and kernel headers on the target. Rejected by the blueprint.
