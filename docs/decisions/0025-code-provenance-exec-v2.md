---
status: proposed
date: 2026-11-06
owner: Ashish Rana
consulted: [research note 2026-11-06 §1 and §5 slice A, ADR-0003, ADR-0007 rule 3, ADR-0009, ADR-0017 layer 1, ADR-0020 rule 5, ADR-0024, kernel v7.0 fs/exec.c, include/uapi/linux/magic.h, net/core/sock_diag.c, Falco libs ppm_events_public.h, Tetragon bpf_execve_bprm_commit_creds.c]
supersedes: ADR-0003's EXEC field table (version 1 → 2) and the snapshot's PROC field table (version 1 → 2). ADR-0020 rule 5 is carried out for EXEC only; FORK and EXIT stay at version 1.
---

# 0025: Code provenance on EXEC and PROC (EXEC v2, PROC v2)

## Context and problem statement

The process graph knows *that* a program started, and from which file identity. It does not know **where that program's code came from** (a normal file on disk, an in-memory file, a deleted file, a tmpfs file) or **what its standard streams are connected to** (a terminal, a file, a pipe, a network socket). Both are needed to tell an ordinary program start from an unusual one, and both are cheap to read at the moment of exec. Falco records four executable flags on every exec and in its task iterator; Tetragon records the executable's link count. We record neither.

## Decision drivers

1. Facts in the kernel, interpretation in the reader: no policy in BPF, so a rule can change without a record version.
2. Only data the program's own task owns at that moment (no unpinned memory: ADR-0024's lesson).
3. No new attach point; cost invisible next to an exec (ADR-0018 to confirm).
4. The same facts in the snapshot, so processes running before capture are described the same way.

## Considered options

1. New fields on EXEC (v2) and PROC (v2).
2. A separate PROVENANCE record per exec.
3. Interpreted flags computed in BPF (memfd, writable, …) instead of raw facts.

## Decision outcome

**Option 1, with raw facts (not option 3).** These facts belong to one exec and cannot change after it; a separate record would only add a join. Raw facts let the reader derive and re-derive classes without touching BPF.

### Rules

1. **When.** EXEC v2 is filled at `sched_process_exec`. By then `begin_new_exec` has unshared the file table (v7.0 fs/exec.c L1126), set `mm->exe_file` (L1135), closed close-on-exec descriptors (L1186) and committed the new credentials (L1255); the tracepoint fires at L1718. So the fields describe exactly what the new program starts with, and no other thread shares the file table.
2. **Executable facts** (from `current->mm->exe_file`, all CO-RE reads): `exe_nlink`, `exe_fs_magic` (low 32 bits of `s_magic`), `exe_mode`, `exe_uid`, `exe_gid`, `exe_ctime_ns`, `exe_mtime_ns`, and the executable's own name, `exe_name` (the dentry name, NUL-padded, cut at 31 bytes; `exe_name_len` is the full length, so a cut is visible). The v1 fields (`exe_ino`, `exe_dev`, `exe_gen`, `old_tid`) stay.
3. **Credentials** after the commit: `uid`, `euid`, `gid`, `egid`, `fsuid`, `fsgid`.
4. **`self_exec_id`** (u64; increments once per successful exec, v7.0 fs/exec.c L1243): ADR-0020 rule 5's per-process exec counter.
5. **Standard streams.** For each of fds 0, 1 and 2: `ino`, `dev` (superblock `s_dev`), `rdev`, `mode` (full `i_mode`, so the file type is in it). A closed descriptor is all zero. For a pipe, `ino` is the pipe inode, so a reader's fd 0 and its writer's fd 1 share it — the exact "producer piped into interpreter" join, by identity, not a time window. No socket cookie: `bpf_get_socket_cookie` is barred in a classic tracepoint, and 7.0 has no stable `sk_cookie` field to read, so the socket→NET join waits for a helper-capable hook (raised below). A socket stream is still visible as such from `mode`.
6. **PROC v2** carries the same executable facts, credentials and `self_exec_id` for each thread-group leader in a snapshot. It does **not** carry the standard streams: those are an arbitrary task's open files, and walking another task's file table in the sleepable iterator is higher-risk than reading `current`'s at exec. A pre-existing process's streams, when they are needed, come from a later file-open slice, not from the snapshot. (Decision raised below.)
7. **Reader-side classes** (`python/p15/provenance.py`, unit-tested), derived from the facts, with the magic numbers of v7.0 include/uapi/linux/magic.h:
   - *in-memory file:* `exe_name` starts `memfd:`, the filesystem is tmpfs (0x01021994) or hugetlbfs (0x958458f6), and `exe_nlink` is 0;
   - *deleted file:* `exe_nlink` is 0 and not in-memory;
   - *tmpfs file:* tmpfs and linked;
   - *container layer:* overlayfs (0x794c7630);
   - *writable by its runner:* the mode bits allow `fsuid`/`fsgid` (or others) to write, excluding the case of a root-owned file run as root;
   - *stream kinds:* terminal, character device, regular file, pipe (pipefs 0x50495045), socket (sockfs 0x534F434B), other, closed.
8. **The EXEC build ways.** Decision 4 removes the `fixed` and `dynptr` ways after the VM repeats `bench-exec-cost`; EXEC v2 is written for the `output` way only once that evidence is in.

### Consequences

- Good: every program start says where its code came from and what its streams are, for processes started during capture and before it; pipe identities link a producer's stdout to a consumer's stdin exactly; no new hook.
- Bad: EXEC grows by about 160 bytes; the name is a basename, not a path (the path stays with the snapshot and, later, file-open records); a mode-bit writability test ignores ACLs and capabilities (stated in the class).

### Confirmation

1. The loader self-test starts a program from an in-memory file, and one each with stdin a pipe, stdout a regular file and stderr a socket, and checks every field.
2. `it_p15d.sh` checks the same facts in a real run, and that a running process's PROC v2 matches its EXEC v2 where both exist.
3. On the VM, ADR-0018's harness shows the exec cost difference v1 → v2 is not resolved or is below 1 % of an exec.

### Falsifier

Reopen if a field read at the tracepoint disagrees with `/proc/<pid>/` for the same process in the self-test, or if the VM measures a resolved cost above 1 % of an exec.

## Decisions raised

**Socket → NET join.** EXEC v2 records a socket stream's inode and type but not its NET cookie, because no cookie is reachable from a classic tracepoint on 7.0 (rule 5). So a reverse shell is visible (a shell with a socket on stdio) but not yet tied to the exact connection in the NET records. Recommendation: defer; the file/socket data-flow slice adds fexit hooks where `bpf_get_socket_cookie` is allowed, and the join comes with it. The maintainer decides whether to pull it forward (it would need the exec side moved to an fentry on a function that has the task and the fds, which is a larger change).

**PROC standard streams.** PROC v2 omits the standard streams (rule 6). The alternative is to walk each snapshotted task's file table in the iterator, as Falco's task iterator does, so a pre-existing reverse shell is visible from the opening snapshot alone. Recommendation: defer. The exec side already captures streams for every process that starts during capture, and a pre-existing process's streams can come from a file-open slice later; the iterator stays simple until that slice needs it. The maintainer decides whether to pull it forward.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | Files unshared, exe_file set, close-on-exec done and creds committed before the exec tracepoint | SRC | v7.0 fs/exec.c L1126, L1135, L1186, L1255, L1718 |
| 2 | `self_exec_id` increments once per exec | SRC | v7.0 fs/exec.c L1243 |
| 3 | `sk_cookie` is 0 until generated | SRC | v7.0 net/core/sock_diag.c L27-37 |
| 4 | Filesystem magic numbers | SRC | v7.0 include/uapi/linux/magic.h L18-93 |
| 5 | Falco records writable / memfd / overlay-layer flags on exec and in its task iterator | SRC | falcosecurity/libs@0815626 driver/ppm_events_public.h L664-667, modern_bpf iterators/task.bpf.c L72-86 |
| 6 | Tetragon records the executable's link count at exec | SRC | cilium/tetragon@e4ea242 bpf/process/bpf_execve_bprm_commit_creds.c L74, L158-160 |
