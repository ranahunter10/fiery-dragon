---
status: accepted
date: 2026-11-05
accepted: 2026-11-06
owner: Ashish Rana
consulted: [ADR-0007 rule 3, ADR-0023 rules 1-2, kernel v7.0 source (kernel/bpf/bpf_iter.c, kernel/bpf/task_iter.c, kernel/trace/bpf_trace.c, fs/bpf_fs_kfuncs.c), the kernel's selftest bpf_iter_task_vmas.c, ARIES fuzzy checkpoints (research note 2026-11-05)]
supersedes: ADR-0023 rule 2 in part (the "gone by the end" check gains a window)
---

# 0024: How the process snapshot is taken, and the closing snapshot's window

## Context and problem statement

Building ADR-0007 rule 3 (the opening snapshot) and ADR-0023 (the closing one) raised four questions the ADRs don't settle.

1. **The executable's path.** ADR-0007 says `bpf_d_path` is allowed in iterators, so the snapshot "can carry resolved executable paths". It is allowed, but only safe on a file the iterator pins. The task iterator pins the task, not its `mm`. So `task->mm->exe_file` can be freed under the program by an exit. The kfuncs that take a reference on `exe_file`, `bpf_get_task_exe_file` and `bpf_path_d_path`, are LSM-only (`fs/bpf_fs_kfuncs.c` line 371). This kernel has no BPF-LSM.
2. **Exact books.** `bpf_seq_read` shows an object a second time after its output overflowed the iterator's 32 KiB buffer (`bpf_iter.c` lines 105, 172–199). That would count it twice.
3. **Who takes the closing snapshot.** It must be taken while the hooks are attached (ADR-0023's fuzzy-checkpoint order), and the writer thread owns the WAL.
4. **A process forked while the closing snapshot runs** can be missed by it, if the iterator has already passed its pid. ADR-0023 rule 2 would then count it `exit_unexplained`: a false loss.

## Decision drivers

1. Never read kernel memory the program doesn't hold (kernel safety first).
2. Books that close exactly (ADR-0006 rule 6).
3. One owner of the WAL (ADR-0017 layer 2).
4. No false losses, and no silent set-asides.

## Considered options

For the path:
1. `bpf_d_path(&task->mm->exe_file->f_path)`.
2. The file mapped at `mm->start_code`, through the open-coded `bpf_iter_task_vma`, compared by inode with `mm->exe_file`.
3. `readlink /proc/<pid>/exe` in p15d, checked against the identity the iterator read.
4. No path: executable identity (device, inode, generation) only.

For the window:
1. ADR-0023 rule 2 as written.
2. Set aside, and count, every process forked after the closing snapshot began.

## Decision outcome

**Path: option 2.** It is the kernel's own selftest pattern, with the file pinned by its mapping under the mmap lock. Option 1 risks a use-after-free on an exiting process. Option 3 races pid reuse in userspace. Option 4 loses the name a person reads.

**Window: option 2.**

### Rules

1. **Path.**
   - The snapshot reads the path of the file mapped at `mm->start_code`, inside `bpf_rcu_read_lock` with `bpf_iter_task_vma`.
   - It does so only when that file's inode is `mm->exe_file`'s.
   - Otherwise the path is left empty with `P15_F_READ_FAILED`, counted by cause: `path_unlocked` (the mmap lock was busy), `path_not_found`, `path_failed`. A path longer than 255 bytes is `TRUNCATED`.
   - argv is read with `bpf_copy_from_user_task`, outside that section, so the mmap lock is never taken twice.
2. **Books.**
   - p15d reads the iterator in 16 KiB pieces, so the kernel never re-shows a task.
   - SNAP_DONE carries both halves of the books: `tasks = threads + emitted + write_failed` (the program's side) and `emitted = entries + invalid + unwritten` (p15d's side).
   - A snapshot whose books don't close, or that lost or refused a record, makes the run INVALID.
3. **The closing snapshot.**
   - At an orderly stop, main asks, and the writer thread takes the snapshot while the hooks are still attached. Main keeps draining meanwhile, then detaches.
   - END v2's `closing_snapshot` records the outcome: 1 taken and complete, 0 not taken (`p15_fail`), or a negative errno.
4. **Window (supersedes ADR-0023 rule 2 in part).** In the "gone by the end" check, a process whose FORK is at or after the closing snapshot's start is set aside, not required to have an EXIT. It is counted (`born_during_closing`).

### Consequences

- Good:
  - no unpinned kernel memory is read;
  - the books close exactly, and the program's side is checked against p15d's;
  - a process the closing snapshot missed by timing is not a false loss.
- Bad:
  - a process whose text mapping isn't its `exe_file` has no path (counted);
  - a lost EXIT of a process forked during the closing snapshot is not located.

### Confirmation

1. The dev container's end-to-end test (cases 1–3) shows paths for every user process and books that close in both snapshots. Case 1's reconciliation is complete; case 3's located losses stay within the counted ones.
2. The same on the VM.
3. Unit tests: framing across reads, invalid and foreign records, a cut stream, and books that don't close; the window (a fork during the closing snapshot is set aside).

### Falsifier

Reopen if any snapshot on the VM shows `path_not_found` for an ordinary ELF program, if a kernel splat names the snapshot program, or if a run with zero counted losses shows `born_during_closing` processes that never existed (a window bug).

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | The safe `exe_file` kfuncs are LSM-only | SRC | `fs/bpf_fs_kfuncs.c` line 371, v7.0 |
| 2 | `bpf_d_path` is allowed in every iterator; its safety rests on pinned objects | SRC | `kernel/trace/bpf_trace.c` lines 947–951, v7.0 |
| 3 | `bpf_iter_task_vma_new` takes the mmap read lock (try-lock); the mapping holds `vm_file` | SRC | `kernel/bpf/task_iter.c` lines 818–850, v7.0 |
| 3a | The kernel's own selftest reads `bpf_d_path(&vma->vm_file->f_path)` in a vma iterator | SRC | `tools/testing/selftests/bpf/progs/bpf_iter_task_vmas.c` lines 37–52, v7.0 |
| 4 | Sleepable programs see pointers walked from trusted ones as untrusted outside an RCU section; `bpf_d_path` refuses them | MEAS | verifier log in the container, 2026-11-05 ([evidence](../evidence/build/2026-11-05-snapshot-4c/README.md)) |
| 5 | An object is re-shown only after an overflow of the 32 KiB buffer | SRC | `kernel/bpf/bpf_iter.c` lines 105, 172–199, v7.0 |
| 6 | The container's kernel never shows pid 1 to a task iterator, even one asked for tid 1 | MEAS | E-0105 |
