---
status: proposed
date: 2026-10-25          # proposed; set to the merge date on acceptance
owner: Ashish Rana
consulted: [capture blueprint v1 §2.2, §4.1, §4.4 (2026-10-21), Linux v7.0 source (tag v7.0, 028ef9c), P1/P2/P6/P8/P10 evidence, Phase 0 audit]
supersedes: none
---

# 0003: Hook policy: BTF-checked attach points, the spine on `tp_btf` sched tracepoints, argv from the kernel's copy, and a per-pid load-time self-test

## Context and problem statement

v3.7 used only syscall tracepoints, under design rule D2 ("tracepoints only, so nothing breaks across kernels"). On the target kernel that rule fails in three measured ways:
- **`syscalls:sys_enter_*` deliver nothing to BPF on 7.0** (E-0022): v3.7's exec/open/connect hooks would be silent.
- **Argv read at syscall entry can be swapped:** under a racing rewrite, it matched what the kernel ran in 45 of 1,000 execs (E-0049).
- **Syscall ids are ABI-dependent:** compat calls arrive with i386 numbers (E-0050, E-0052).

In addition, the kernel docs state that no attach point is stable ABI, tracepoints included (blueprint §2.2).

**Question:** which kinds of attach points may the capture use, which ones does the process spine use, and how does it know at start-up that each one really delivers?

This revises D2 (blueprint Q-A2). The blueprint marked that for the advisor; the maintainer decides it here.

## Decision drivers

1. **No silent blind spots.** A hook that stops delivering, or is re-routed, must be detected at start-up, not discovered in the data.
2. Record what the kernel *did*, not what user memory said beforehand (TOCTOU).
3. Coverage of compat and in-kernel paths that syscall tracepoints miss.
4. The cheapest hook that gives the needed fields: one program per event, not enter+exit joins.
5. Failures are loud: refuse to start rather than run degraded silently.

## Considered options

1. **BTF-checked attach points** (`tp_btf` where a tracepoint carries the fields, fentry/fexit otherwise), each checked at load, with declared fallbacks and a per-pid self-test
2. Syscall tracepoints only (D2 as in v3.7)
3. BPF-LSM programs joined to syscall-exit tracepoints (the VAP design)
4. kprobes everywhere

## Decision outcome

**Chosen option:** option 1, because it is the only one that meets drivers 1–3 together on the measured kernel. Options 2 and 3 fail on measured facts: E-0022, E-0049, E-0050, and option 3 needs a GRUB change (no `bpf` in the LSM list, E-0003).

### Policy (all families)

1. **Attach-point order:**
   1. `tp_btf` on a tracepoint that carries the needed objects;
   2. fentry/fexit on a kernel function, using `bpf_get_func_ret()` for return values, never a positional argument;
   3. a kprobe only as a declared fallback where BTF lacks the function.
2. **Every attach point is checked at load:**
   - present in BTF and in `available_filter_functions`, and attached;
   - else its declared fallback;
   - else the family is `unavailable`.
3. **The daemon refuses to start** if any family is unavailable or fails the self-test, unless `--allow-degraded` is given. The WAL header (ADR-0007) records the attached-hook manifest and the self-test result.
4. **Not used:**
   - `syscalls:sys_enter_*` / `sys_exit_*`: E-0022, and they ignore compat syscalls;
   - BPF-LSM programs: not enabled on the target;
   - **comm-based filtering** of any kind.
5. **`raw_syscalls` is not used by the product.** If a later ADR adds it, ids must be decoded only after checking TS_COMPAT (`thread_info.status & 0x2`), because compat calls carry i386 numbers (E-0050, E-0052).

### The process spine (Phase 1)

| Event | Attach point (v7.0 prototype) | What is read |
|---|---|---|
| fork / clone | `tp_btf/sched_process_fork (struct task_struct *parent, struct task_struct *child)` | parent and child identity (ADR-0009); thread or process (`child->tgid == parent->tgid`) |
| exec | `tp_btf/sched_process_exec (struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)` | see the exec rules below |
| exit | `tp_btf/sched_process_exit (struct task_struct *p, bool group_dead)` | exit code; `group_dead` marks the end of the process |
| comm change | `tp_btf/task_rename (struct task_struct *task, const char *comm)` | old and new comm (also fires on exec) |

**Exec rules:**
- **argv** is read from the new program's stack, `mm->arg_start .. mm->arg_end`, at `sched_process_exec`, which fires after the new mm is installed and before the program runs (`fs/exec.c` lines 1718, 1826, v7.0).
  - The copy is bounded. The record carries the copied length and the full length, and **truncation is counted**.
  - Basis: E-0049 (1,000 of 1,000 under a race).
- **The binary** is recorded two ways:
  - `bprm->filename`, the name as passed, or `/dev/fd/N` for `execveat`;
  - the identity of `bprm->file` (device, inode, generation; ADR-0009).
- **The resolved path is not taken here.** `bpf_d_path` is not allowed in `tp_btf` programs; the v7.0 allowlist is `security_file_open`, `security_file_permission` and a few others, plus iterators (`kernel/trace/bpf_trace.c` lines 931–958). The resolved path comes from the FILE_OPEN record of the same open (Phase 2), joined on file identity.

### Load-time self-test (replaces the census's system-wide "≥" check, audit A4)

1. At start, after attaching, the daemon forks a **test child**. The child, and only the child:
   - forks a grandchild;
   - renames itself (`prctl(PR_SET_NAME)`);
   - execs `/bin/true` with a known argv;
   - exits with a known code.
   Later phases add their families' operations: read, write, readv, splice, sendfile, copy_file_range, TCP/UDP/unix send/recv, io_uring, a 32-bit read, mmap shared write (blueprint §4.4).
2. The daemon counts the records **whose process identity is the test child's**, and requires **exact** counts and field values. For example: exactly one EXEC with argv `["true", "fd-selftest"]`, and an EXIT with the known code.
3. Any mismatch is a failed self-test (see policy item 3). Background activity can't make a broken hook pass, because records are attributed to the test child's identity, not counted system-wide.

### Consequences

- Good: v3.7's main failure mode on this kernel (silent hooks) becomes a start-up error.
- Good: argv is the kernel's copy, so the argv-swap TOCTOU (blueprint §4.2 "remaining on argv before exec") is closed for exec.
- Good: compat processes are covered by the spine for free. The sched tracepoints don't depend on the syscall ABI (E-0052: `sched_process_exec` fired for a compat execve).
- Bad: fentry/fexit and `tp_btf` depend on kernel internals. A signature change fails the load (loud), but an added argument or a re-routed caller is silent unless the self-test exercises it. **The self-test must grow with every family.**
- Bad: the spine can't name the resolved exec path by itself; it relies on the Phase-2 FILE_OPEN join.

### Confirmation

- **Phase 1:** the self-test is part of `p15d` start-up. Its result is in the WAL header, and an L4 test asserts that a deliberately detached hook makes start-up fail.
- **Phase 1:** a libbpf build of the spine on the VM also settles the open items below.
- CI already proves a `tp_btf/sched_process_exec` program passes the verifier on the runner's kernel (PR #15). That is not the target, so it is not proof for 7.0.

### Falsifier

Reopen if:
- a spine tracepoint on 7.0.0-38 doesn't fire for an operation the self-test performs;
- `mm->arg_start..arg_end` at `sched_process_exec` ever differs from what the program received (a P6-style run with a mismatch);
- the self-test proves too slow or too flaky to run at every start (it should take well under a second; to be measured).

### Open items this ADR does not settle (and where they get settled)

| Item | Status | Settled by |
|---|---|---|
| Whether `sys_enter_*` silence is the kernel or bpftrace | OPEN (E-0021/22, no raw file: E-0056) | a libbpf `tp/syscalls/sys_enter_execve` load on the VM in Phase 1, recorded with raw output. The decision above doesn't depend on it |
| `bpf_get_func_ret` loads from our fexit programs on 7.0 | INF (E-0007, E-0012) | first fexit program, Phase 2 |
| `bpf_d_path` from fexit `security_file_open` | SRC (allowlist above); not yet loaded | Phase 2 |
| Exec from a non-leader thread: identity across `de_thread` | see ADR-0009 | L4 test in Phase 1 |

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | `syscalls:sys_enter_execve/openat` deliver 0 events to BPF on 7.0.0-38 (bpftrace 0.25), while tracefs shows them and `sys_exit_*` and `raw_syscalls` deliver | MEAS (no raw file yet) | E-0021, E-0022; E-0056 |
| 2 | Argv read at syscall entry matched what ran in 45 of 1,000 raced execs; the `mm->arg_start` read at `sched_process_exec` in 1,000 of 1,000 | MEAS | [P6 run](../evidence/probes/2026-10-25-p6-p8/README.md); E-0049 |
| 3 | `raw_syscalls` reports i386 numbers with TS_COMPAT set for compat calls; `sched_process_exec` fires for a compat execve | MEAS | [P6/P8](../evidence/probes/2026-10-25-p6-p8/README.md), [P8 32-bit](../evidence/probes/2026-10-25-p8-32bit/README.md); E-0050, E-0052 |
| 4 | `copy_strings` copies argv before `bprm_execve`; `sched_process_exec` fires after the new mm is installed | SRC | `fs/exec.c` lines 1826, 1846, 1718 at [v7.0](https://github.com/torvalds/linux/blob/v7.0/fs/exec.c#L1718) |
| 5 | Spine tracepoint prototypes as in the table | SRC | `include/trace/events/sched.h` lines 337, 398, 426; `include/trace/events/task.h` line 36, at v7.0 |
| 6 | `bpf_d_path` is allowed only for the listed functions, iterators and sleepable LSM hooks | SRC | `kernel/trace/bpf_trace.c` lines 931–958 at [v7.0](https://github.com/torvalds/linux/blob/v7.0/kernel/trace/bpf_trace.c#L931) |
| 7 | No `bpf` in the LSM list on the target | MEAS | `00-vm-baseline.txt`; E-0003 |
| 8 | All 20 census-v2 hook points (fexit on vfs/security functions, sock/io_uring tracepoints) deliver on 7.0 | MEAS | [census v2](../evidence/census/2026-10-24T224617Z-v2/README.md); E-0032 (audit: system-wide "≥", 85 %) |
| 9 | The kernel docs say no BPF attach point is a stable ABI | DOC | `Documentation/bpf/bpf_design_QA.rst`, via blueprint v1 §2.2 |
| 10 | A tp_btf program on `sched_process_exec` passes the verifier (dev container 6.18; CI runner) | MEAS | PR #15 |
| 11 | Per-syscall tracepoints ignore compat syscalls on x86 (`ARCH_TRACE_IGNORE_COMPAT_SYSCALLS`) | SRC | `arch/x86/include/asm/ftrace.h`, via blueprint v1 §2.2 (not re-read for this ADR) |
| 12 | `task_rename` fires on exec too | SRC | `fs/exec.c` line 1079 at v7.0 |

## Pros and cons of the options

### 1. BTF-checked attach points + self-test
- Good: works on the measured kernel; sees compat and in-kernel paths; loud on failure.
- Bad: depends on internals; the self-test is extra code that must keep up.

### 2. Syscall tracepoints only (D2)
- Bad: silent on 7.0 for `sys_enter_*` (evidence 1); TOCTOU on pointer arguments (evidence 2); blind to compat calls and io_uring.

### 3. BPF-LSM + syscall exit join
- Bad: needs `lsm=…,bpf` on the kernel command line (evidence 7); misses reads AppArmor denied; no exit to join for io_uring (blueprint §2.2).

### 4. kprobes everywhere
- Good: attach anywhere.
- Bad: no BTF-typed arguments; slower than fentry/fexit; silent on inlining. Kept only as a declared fallback.
