---
status: proposed
date: 2026-10-25          # proposed; set to the merge date on acceptance
owner: Ashish Rana
consulted: [capture blueprint v1 §2.1 and §3 (2026-10-21), phase-0 evidence, Phase 0 audit (2026-10-25)]
supersedes: none
---

# 0001: Develop and measure on Ubuntu 26.04 LTS with the GA kernel 7.0.0-38, held

## Context and problem statement

Every hook, offset and measurement in the capture layer belongs to one kernel. The old capture (v3.7) was built on 5.4. Its platform choice was argued from rhetoric ("industry floor 5.15"), and then the facts moved: 26.04 shipped, and 24.04's HWE kernel became 7.0. If the kernel can change underneath us, a hook can silently re-route (blueprint L12), and numbers measured last week stop meaning anything.

**Question:** which distribution and kernel do we build, test and measure on, and how is it kept from changing?

## Decision drivers

1. The BPF features the design needs exist: BTF, fentry/fexit with return values, ring buffer, task storage, `BPF_PROG_RUN` on `syscall` programs.
2. Support window covers the thesis and some years beyond.
3. **The kernel must not change under us** without a decision.
4. The toolchain from the distro is recent enough to need no hand builds: clang, libbpf, bpftool, pahole, Python ≥ 3.11.
5. Facts measured on the platform, not argued.

## Considered options

1. Ubuntu 26.04 LTS, GA kernel 7.0, **held**
2. Ubuntu 24.04 LTS, GA kernel 6.8, held
3. Ubuntu 24.04 LTS with the HWE kernel (7.0 since 24.04.5)
4. Ubuntu 22.04 LTS, kernel 5.15 (the earlier VAP proposal)

## Decision outcome

**Chosen option:** option 1, because it is the only one that meets drivers 1–4 together, and every Phase-0 measurement (P1–P12) was taken on it.

**The platform, as built and measured:**

| Item | Value | Evidence |
|---|---|---|
| Distribution | Ubuntu 26.04.1 LTS | `00-vm-baseline.txt` line 10 |
| Kernel | `7.0.0-38-generic` (GA `linux-generic`) | `00`; E-0002 |
| Pin | `apt-mark hold linux-generic linux-image-generic linux-headers-generic`; unattended-upgrades disabled | `00` "holds"; E-0002 |
| BTF | `/sys/kernel/btf/vmlinux` present (7,067,009 B) | `00` line 54 |
| LSM / lockdown / Secure Boot | no `bpf` in the LSM list; lockdown `none`; Secure Boot off | `00` lines 41–46 |
| Compat | `CONFIG_IA32_EMULATION=y`, not disabled by default | P8 conditions; E-0050 |
| Clock | clocksource `tsc`, timezone UTC | `00` lines 47–50 |
| VM | VirtualBox 7.2.22, 4 vCPU, 8 GB, 64 GB fixed VDI, EFI, built by `tools/vm/create-vm.ps1` | `00` lines 3–6; runbook |
| Snapshots | `00-fresh-pinned`, `01-toolchain`; `gcc-multilib` added after `01` (E-0052) | runbook; E-0052 |

**Changing the kernel is a new ADR** that supersedes this one. Applying a kernel security update is such a change.

### Consequences

- Good: all Phase-0 findings apply directly. The capture is designed against kernel 7.0 function names, not against names that are already gone.
- Good: 7.0 lets BPF logic be *executed* in tests (`BPF_PROG_RUN` on `syscall` programs). The dev container (6.18) and the CI runner can already load such programs (CI `bpf` job).
- Bad: **a held kernel receives no security updates.** The VM is a development and measurement machine behind VirtualBox NAT, and must not be exposed or used for anything else.
  - SSH reaches it through a NAT port forward on host port 2222.
  - The rule's host IP is empty (`ssh,tcp,,2222,,22`). Setting it to `127.0.0.1` keeps the port off the laptop's network. That is a follow-up for `create-vm.ps1`.
- Bad: v3.7 can't run here as a live oracle. Its hooks are `syscalls:sys_enter_*`, which deliver nothing to BPF on 7.0 (E-0022, 75 % confidence, E-0056). The old 5.4 VM is gone (E-0009). The v3.7 comparison uses its recordings and the semantic oracle diff (blueprint Phase 1).
- Bad: results are for one kernel. Portability to other kernels is not claimed until the KVM kernel matrix exists (blueprint §7.3).

### Confirmation

- **Every run records the kernel:** census, baseline and probe runs write `uname -r` into `conditions.json` today; the WAL header will carry the kernel release (ADR-0007).
- **The load-time self-test** (ADR-0003) runs on every daemon start and fails loudly if a hook stops delivering.
- **To do:** a script under `tools/vm/` that re-captures `00-vm-baseline.txt` (audit finding, runbook "known gap"). Until it exists, the check is manual: `uname -r; apt-mark showhold`.

### Falsifier

Reopen if any of these is observed:
- a needed BPF feature requires a kernel newer than 7.0;
- Canonical ends maintenance of the 7.0 GA kernel on 26.04, or the hold stops working (`uname -r` changes without a decision);
- a deployment target with a specific kernel is required;
- a Phase-1 load on 7.0.0-38 shows a hook the design depends on cannot be attached or never fires.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | The VM runs Ubuntu 26.04.1, kernel 7.0.0-38, with the kernel packages held | MEAS | [`docs/evidence/phase0/00-vm-baseline.txt`](../evidence/phase0/00-vm-baseline.txt); E-0002 |
| 2 | BTF present; no `bpf` LSM; lockdown none; Secure Boot off | MEAS | `00-vm-baseline.txt`; E-0003 |
| 3 | Program types tracing, raw_tracepoint, syscall, lsm; maps ringbuf, user_ringbuf, task_storage available; inode_storage not | MEAS | [`03-p2-feature-probe.txt`](../evidence/phase0/03-p2-feature-probe.txt); E-0007 |
| 4 | fexit attach with a return value works on this kernel (vfs_read: 769 calls, 795,645 B in 3 s) | MEAS | [`04-p1b-fexit-check.txt`](../evidence/phase0/04-p1b-fexit-check.txt); E-0006 |
| 5 | All 20 census-v2 hooks deliver on 7.0 | MEAS | [census v2](../evidence/census/2026-10-24T224617Z-v2/README.md); E-0032 (audit: 85 %, "≥" check) |
| 6 | The hold survived a 21-package install (`gcc-multilib`): still 7.0.0-38 | MEAS | [P8 32-bit run](../evidence/probes/2026-10-25-p8-32bit/terminal.txt); E-0052 |
| 7 | 26.04 is supported to 2031; 24.04 to 2029; 22.04 standard support ends 2027 | DOC | ubuntu.com/about/release-cycle, via blueprint v1 §2.1 (not re-checked for this ADR) |
| 8 | 24.04's HWE kernel is 7.0 since 24.04.5 | DOC | Ubuntu kernel lifecycle, via blueprint v1 §2.1 (not re-checked) |
| 9 | 22.04/5.15 lacks `bpf_get_func_ret` and the user ring buffer, and ships Python 3.10 | SRC/DOC | blueprint v1 §2.1 (`platform_kernel.md`) |
| 10 | On 7.0, `syscalls:sys_enter_*` deliver no events to BPF via bpftrace 0.25 | MEAS (no raw file yet) | E-0021/E-0022; E-0056 |

## Pros and cons of the options

### 1. 26.04 + GA 7.0, held
- Good: newest BPF; longest support; distro toolchain new enough; every probe measured here.
- Bad: young LTS; held kernel means no security updates (managed by isolating the VM).

### 2. 24.04 + GA 6.8, held
- Good: older and more battle-tested.
- Bad: shorter support; its HWE stream is already 7.0, so "6.8" means opting out of the default; none of our measurements were taken on it.

### 3. 24.04 + HWE
- Bad: HWE rolls forward (7.0 now, later releases next), which breaks driver 3 unless held, and then it is option 1 on an older userland.

### 4. 22.04 + 5.15
- Bad: missing BPF features (evidence 9); Python 3.10 below our minimum; standard support ends in 2027.
