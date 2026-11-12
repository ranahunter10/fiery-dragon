---
status: accepted
date: 2026-11-12
owner: Ashish Rana
consulted: [kernel v7.0 fs/d_path.c, fs/dcache.c, fs/pipe.c, net/socket.c, fs/anon_inodes.c, fs/open.c, kernel/bpf/trampoline.c; Tetragon bpf/lib/bpf_d_path.h at 63332a1 and Tracee pkg/ebpf/c/common/filesystem.h at 2f9dc40 (R-043); bench/path_walk on the VM (E-0196) and on CI's 7.0 runner; maintainer 2026-11-12 ("recommendations are accepted", E-0193, STATE decisions 28-30)]
supersedes: ADR-0015 rule 6, third bullet of the session return ("OPEN with flag PATH_MISSING ... nothing guesses the path"), and the part of its confirmation 1 that expects PATH_MISSING from the test-only switch. Every other rule of ADR-0015 is unchanged.
---

# 0029: When the path fentry is skipped, the session's return walks the path

## Context and problem statement

ADR-0015 rule 6 writes each open's OPEN from a fentry on `security_file_open` with `bpf_d_path`, and, when the kernel skipped that fentry for another task, from a kprobe.session's return with flag `PATH_MISSING` and no path. Under contention the kernel skips the fentry for about one open in ten (10.8 % of 2.4 M opens with 12 processes on 3 vCPUs, E-0192), because tracing programs run preemptible on 7.0 and a task preempted inside one blocks that program for the CPU's other tasks (kernel/bpf/trampoline.c L1143-1196). A 25 % shorter program did not change the rate (E-0192). One open in ten without a path is a hole in provenance exactly when the host is busy, which is when an attack is likely to be. The kprobe.session is not skipped that way (it runs with preemption off), but it cannot call `bpf_d_path` (allowed only for tracing programs on an allowlist, kernel/trace/bpf_trace.c L931-958).

**Question:** how does an open whose fentry was skipped get its path?

## Decision drivers

1. Never a wrong path without a flag saying so (a provenance graph built on a false path is worse than one with a hole).
2. No path lost under contention.
3. Cost on the common path: the file programs are at 897.3 ns per open+close against a 0.5 us budget (E-0192, E-0193).
4. One code path that is tested on every CI run, not only under contention.

## Considered options

1. **(a) Walk only when skipped:** keep the fentry and `bpf_d_path`; the session's return, when the fentry did not run, builds the path with a bounded walk of the dentries and mounts (`bpf/include/p15_dpath.h`) and writes OPEN with flag `PATH_WALKED`.
2. **(b) Walk always, one program:** drop the fentry; the kprobe.session writes every OPEN with the walk.
3. **(c) Keep PATH_MISSING** (no change).

## Decision outcome

**Chosen option: (a)**, because the walk is correct (driver 1: no unflagged difference from `bpf_d_path` on any case or in 19,788 compared samples of a rename race, E-0196) but costs 1.5 to 1.6 times `bpf_d_path` (233 against 156 ns on 8 components, 510 against 310 on 25), so walking every open would add about 77 to 200 ns per open (driver 3); the rule for this choice was stated before the run (PR #72). (c) fails driver 2.

The rules:
1. **The walk** follows `d_path` (fs/d_path.c v7.0 L101-139, L155-196, L265-292): the opener's root, mount crossings, `" (deleted)"` for an unlinked dentry. It reads the rename and mount sequence counters before and after, retries once, and flags `RACED` if they moved again (`d_path` retries under the lock; neither Tetragon nor Tracee reads the counters, R-043). Bounds: 128 steps, 64 components, 255 bytes a name, 4,095 in all.
2. **Names made by the filesystem (`d_dname`).** The walk writes the string the kernel's own function would for the four the kernel uses for pseudo files: `simple_dname` (`"/" name " (deleted)"`, a memfd reopened through `/proc`), `pipe:[ino]`, `socket:[ino]`, `anon_inode:name` (fs/dcache.c L1866-1879, fs/d_path.c L301-325, fs/pipe.c L874-878, net/socket.c L374-378, fs/anon_inodes.c L74-78). It identifies them by the dentry's flags, its superblock's magic and default dentry operations, never by kernel addresses (an address resolved at load time could be ambiguous and fail the whole object). Any other `d_dname`: no path, flag `PATH_MISSING`, counted.
3. **The record.** OPEN as in ADR-0015 rule 6, written by the session's return, with `fflags` `PATH_WALKED` and the walked path, and the verdict. `RACED` sets `PATH_RACED` and keeps the path (the reader may distrust it). A path cut by a bound has header flag `TRUNCATED` and keeps its last components (the leaf and its nearest directories, not rooted), `path_full` unknown. No path (an unknown `d_dname`, a task without `fs`, no scratch): `PATH_MISSING` as before. Each case is counted.
4. **An overlay's real file** (`FMODE_BACKING`) opened when the fentry was skipped gets BACKING from the session's return, as the fentry would have written, not an OPEN of the real file (before this ADR it got an OPEN with `PATH_MISSING`, an extra open the graph could not tie to the overlay file). A denial after it gets OPEN_VERDICT. Both counted.
5. **Scratch.** The return builds the record in a per-CPU slot of its own. A kprobe.session program cannot run twice at once on one CPU (the kprobe-multi path skips a nested run and counts it in the program's `missed`), so no claim is needed, unlike the fentry's.
6. **Books** (bpf/include/p15_file.h): the return's OPENs = walked + without a path; the walked include the raced and the truncated; the return's runs add the BACKING branch; the drain's emitted sum adds the return's BACKING and OPEN_VERDICT records. FILE_STATS version 2 carries the new counters.

### Consequences

- Good: an open has its path when the host is busy; a skipped open is written exactly as the fentry would have written it except for the flag that says how.
- Good: a skipped overlay open is no longer an extra file in the graph.
- Bad: two path builders, `bpf_d_path` and the walk, must stay equal; the harness (bench/path_walk) checks them against each other in CI on every PR.
- Bad: under contention about one open in ten costs about 80 to 200 ns more in the return (the walk), with no saving elsewhere.
- Bad: a walked path during a rename storm can be RACED (0.48 % of samples under about 4,000 renames in 20,000 opens, E-0196): kept, flagged, counted.
- Bad: the `d_dname` names depend on four kernel formats; a kernel that changes one shows up as a MISMATCH in the harness, not in production records.

### Confirmation

1. `bench/path_walk` in CI (every PR): every case and every race sample equal to `bpf_d_path` or flagged; memfd, pipe, socket and eventfd equal (SYNTH).
2. The self-test's no-path mode (`--test-no-path-fentry`): the create and the reopen are OPENs with `PATH_WALKED` and the path the self-test opened, verdict 0, the facts of `fstat`; the CLOSE names the object.
3. `it_p15d.sh` case 12: with the fentry unattached, every OPEN has `PATH_WALKED` or `PATH_MISSING`; the walked ones have a path; FILE_STATS's walked count equals the records'.
4. `bench/open_sections contend` on the VM: the opens the fentry missed arrive walked (`PATH_WALKED`), not `PATH_MISSING`, and the books close.
5. Mutation entries: the return writing `PATH_MISSING` when it could walk; dropping `PATH_RACED`; the backing branch removed; a book term dropped.

### Falsifier

Reopen if:
- the harness shows an unflagged difference on any kernel CI or the VM runs;
- `PATH_RACED` exceeds 1 % of walked opens on a real workload;
- a measurement shows the walk-always design (b) costs no more per open+close than (a) under the same workload (the fentry's trampoline and repeated work saved could outweigh the walk's extra cost: not measured, OPEN);
- the kprobe.session is seen skipped under contention.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | The fentry is skipped for 10.8 % of opens with 12 processes on 3 vCPUs; the session and close programs for none | MEAS | [open-path-v2](../evidence/vm/2026-11-12-open-path-v2/README.md), E-0192 |
| 2 | The walk equals `bpf_d_path` or flags why on 16 cases and 19,788 race samples, on the VM and on CI's runner | MEAS | [path-walk](../evidence/vm/2026-11-12-path-walk/README.md), E-0196; CI run 43100198875 |
| 3 | The walk costs 233.2 ns (8 components) and 509.8 ns (25) in a kprobe.session; `bpf_d_path` 156.3 and 310.1 | MEAS | same, E-0196 |
| 4 | `bpf_d_path` is not callable from a kprobe | SRC | kernel/trace/bpf_trace.c L931-958, v7.0 |
| 5 | A memfd's dentry gets `simple_dname` from `d_alloc_pseudo` | SRC | fs/dcache.c L1866-1879, fs/d_path.c L318-325, v7.0 |
| 6 | Pipes, sockets and anonymous inodes name themselves with `dynamic_dname` from the inode number or the dentry name | SRC | fs/pipe.c L874-878, net/socket.c L374-378, fs/anon_inodes.c L74-78, fs/d_path.c L301-316 |
| 7 | A socket's reopen through `/proc` reaches `security_file_open` before `->open` refuses it | SRC | fs/open.c L921-947 (do_dentry_open), v7.0 |
| 8 | Tetragon and Tracee walk without the sequence counters | SRC | text search of both trees at the commits of R-043 |
| 9 | Walk-always (b) would cost more per open+close than (a) | INF | from 3, without the saving of dropping the fentry, which is not measured (OPEN) |

## Pros and cons of the options

### (a) Walk only when skipped
- Good: no change to the common path's cost or its kernel-made path.
- Good: no path lost under contention.
- Bad: two path builders to keep equal (checked by the harness).

### (b) Walk always, one program
- Good: one program, one path builder, no skip-dependent branch; saves the fentry's trampoline and the facts and maps it repeats (E-0188).
- Bad: every path is the walk's, 1.5 to 1.6 times `bpf_d_path`'s cost, and every path depends on the four `d_dname` formats and the counters' retry instead of the kernel's lock.

### (c) Keep PATH_MISSING
- Good: no new code.
- Bad: one open in ten has no path under contention.
