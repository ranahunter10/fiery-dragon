---
status: proposed
date: 2026-11-09
owner: Ashish Rana
consulted: [research note 2026-11-06-dataflow-slice-b (kernel-v7.0.md §3-5, tools.md §3, provenance-and-pids.md §2-4), research note 2026-11-09-slice-b-design-checks.md (K1-K18), ADR-0006, ADR-0009, ADR-0017 layer 1, ADR-0020, ADR-0024, ADR-0025, ADR-0026, maintainer's slice B plan (STATE decisions 15.5 and 17)]
supersedes: none (fills the reserved number 0015 of the planned list, "file identity, split from 0009")
---

# 0015: File identity: objects, open files and names

## Context and problem statement

Slice B records data flow between processes and files, pipes and sockets. Every such record must name the thing the data went to or came from, and the graph must join records about the same thing: the writer and the reader of a pipe, two processes on one file, the bytes read through an overlay mount and the file underneath. The kernel gives no single stable name:

- an inode number is reused after the file is deleted (ext4 and xfs free and reallocate it), and the numbers of pipes and sockets come from a 32-bit counter that wraps (K8);
- `i_generation` separates the incarnations of a number on ext4, xfs and tmpfs, but is 0 on pipes, sockets, overlay and many others, and is a transaction id on btrfs (kernel-v7.0.md §3);
- btrfs subvolumes share one superblock device and can share inode numbers (K9);
- on overlayfs one user-visible file is backed by a lower file and, after a copy-up, by an upper one (K4);
- the path is a name, not an identity: it changes with rename, and a file can have several or none.

Slice B also needs the full path at open, since every PIDSMaker detector that uses file labels reads the path (provenance-and-pids.md §4), and it needs the files that were already open when capture started.

**Question:** how does capture identify the objects that data flows through and the open files it flows through, how does it name them, and what does the kernel side record about each?

## Decision drivers

1. **Never merge two different objects.** A false merge creates false connectivity, which the reductions literature treats as the worst error (Xu et al. Table 3; the SoK, provenance-and-pids.md §5). Splitting one object into two nodes is a smaller error, and the reader can repair it from facts.
2. **Facts in the kernel, interpretation in the reader** (ADR-0025 driver 1). Which filesystems have trustworthy generations is reader knowledge.
3. **The identity path cannot be skipped for another task** (ADR-0020's lesson): the hooks that register objects and open files run with preemption off. A hook that can be skipped is allowed only for the path, and then a lost path is located to its open.
4. **No silent loss, no silent cap.** Every full map, stale entry, truncated or failed path is counted, and no event is dropped because a map is full.
5. **Cheap per I/O event.** A data-flow record carries two short ids, not a full identity and a path.
6. **No kernel addresses in records** (they would leak KASLR into the WAL).

## Considered options

For object identity:
- **I1.** (device, inode) only, as Kunai and Elastic do (tools.md §3).
- **I2.** (device, inode, ctime), as Tracee does.
- **I3.** (device, subvolume, inode, generation) as raw facts, plus a capture sequence number per in-memory inode (chosen).
- **I4.** A capture sequence only (CamFlow's per-boot counter), without the kernel's numbers.

For the path at open:
- **P1.** fexit on `security_file_open` with `bpf_d_path` for the whole open record.
- **P2.** A kprobe on `security_file_open` with a hand-written dentry walk.
- **P3.** A fentry on `security_file_open` with `bpf_d_path` writes the open record with its path, and a non-preemptible kprobe.session on the same function writes one only when the fentry did not, or adds the verdict when the open is denied (chosen).

## Decision outcome

**I3 and P3.** I3 because it is the only option that never merges (driver 1) while keeping the kernel's numbers so the reader can join the same file across in-memory lifetimes (driver 2). P3 because the open itself, which carries the causality, is then never lost to a skip for another task, while the path keeps the kernel's own `d_path` semantics (driver 3), a skipped path is located to its exact open, and the common case costs one record.

### Rules

1. **Two kinds of id, both capture sequence numbers.**
   - An **object id** (`obj`) names one in-memory inode for its lifetime: it is assigned the first time capture sees that inode and forgotten when the inode is freed.
   - An **open-file id** (`fid`) names one `struct file` for its lifetime: assigned at its first sighting and forgotten when it is freed.
   - Both come from one 64-bit counter of the run, never 0, never reused; records already carry the boot id and the run's identity (ADR-0007). Every data-flow record carries `fid` and `obj`; the kernel addresses that key the maps never leave the kernel (driver 6).
   - Processes that share a `struct file` (fork, `dup`, `SCM_RIGHTS`) share its `fid`, as they share its offset in the kernel. That matches the "file open descriptor" attribute of Xu's aggregability definition (X1), which ADR-0005 builds on.
2. **Object facts travel with the first record that names the object.** There is no record of their own: the OPEN, FILE, FD or BACKING record (rules 4-7), or the inline FLOW of ADR-0005 rule 8, that first names an object id carries its facts, with flag `OBJ_NEW`. The facts:
   - `dev` (`i_sb->s_dev`, kernel encoding), `ino`, `gen` (`i_generation`), `mode` (full `i_mode`), `fs_magic` (low 32 bits of `s_magic`), `nlink` at that moment;
   - `subvol`: on btrfs, the subvolume's root id (`BTRFS_I(inode)->root->root_key.objectid`, what `statx` reports as `stx_subvol`, K9), read by CO-RE against the btrfs module's BTF and guarded so the programs load where btrfs is absent; 0 elsewhere;
   - btrfs is a module on the VM, and it may load after p15d (V6). Then the CO-RE guard has already compiled the read out, and two subvolumes could share one (dev, ino). So an object whose `fs_magic` is btrfs's (`0x9123683E`, a constant, no BTF needed) while the subvolume read is compiled out carries flag `SUBVOL_UNKNOWN`, and the reader gives it a node per lifetime (rule 3), never the tuple. The WAL header records whether the read was available at load;
   - how it was first seen (open, snapshot, first I/O, mmap, network).
3. **The reader decides what a graph node is** (driver 2), from rule 2's facts. The kernel gives every in-memory inode its own id rather than only the pipes, sockets and reused numbers, because it cannot tell at the moment of sighting which numbers will be reused:
   - on filesystems where (dev, subvol, ino, gen) cannot name two files during one boot (ext4, xfs, tmpfs by their random generations; btrfs by its never-reused numbers within a mount, kernel-v7.0.md §3), the node is that tuple, so a file evicted from the inode cache and read back is still one node;
   - everywhere else (pipes, sockets, anonymous inodes, overlay inodes, filesystems with `gen` 0), the node is the object id: one in-memory lifetime, never merged with another;
   - the list of filesystems is a reader table with its evidence, not kernel code.
4. **Overlayfs: the BACKING record.** When `security_file_open` sees a file with `FMODE_BACKING` (the backing file an overlay opens for each user open, and the upper file it opens after a copy-up, K4), it writes BACKING with the backing file's object id (its real upper or lower inode) and the object id of the overlay inode it stands for (`backing_file_user_path(f)->dentry->d_inode`, read by CO-RE: the VM's `struct backing_file` differs from upstream v7.0's, K6). The reader joins the overlay object to its real ones by object id, not by time.
   - **Bytes are counted once, on the overlay file.** The read and write hooks (`vfs_read`, `vfs_write`, `vfs_readv`, `vfs_writev`) see the user's I/O on the overlay file; the overlay passes it to the backing file through `vfs_iter_*` / `vfs_iocb_iter_*` (K5), which are not hooked. A `mmap` of an overlay file maps the backing file (kernel-v7.0.md §6), so the MMAP record names the backing file's `fid`, and BACKING ties it to the overlay object.
5. **The FILE record** is written once per open-file id first seen anywhere but an open or the snapshot (pseudo files from `alloc_file_pseudo`, which never reach `security_file_open`, K3: pipes, sockets, memfds, anonymous inodes; and any open file that missed both):
   - `fid`, `obj`, `f_flags`, `f_mode`, and the dentry name, at most 63 bytes as in ADR-0025 rule 2 (`memfd:<name>`, the anonymous-inode name). The reader builds `pipe:[ino]` and `socket:[ino]` itself;
   - a regular file first seen this way means its open was missed; it is counted by kind;
   - an open that fails after `security_file_open` (in `->open`) is not a separate case: its `struct file` is freed without `FMODE_OPENED` (K1, K2), and the CLOSE record (rule 8) says so.
6. **The OPEN record: one per open, with its path (option P3, N1).** Two programs on `security_file_open`, one record in the common case:
   - A **fentry** writes OPEN: `fid`, `obj` (with the object's facts when new, rule 2), `f_flags`, `f_mode`, and the path from `bpf_d_path(&file->f_path)` (allowed there, K10), so the kernel's own rules apply (mount crossing, `(deleted)`, the task's root). It marks the file-map entry "open written". For a file with `FMODE_BACKING` it writes BACKING instead (rule 4).
   - A **kprobe.session** (non-preemptible, ADR-0020 driver 4; entry and return skipped together or not at all, K11; decided over two links, below) keeps the file pointer in its cookie at entry. Its return run comes after the fentry's run for the same call, because the fentry runs before the function body and the return at its exit. So the return run knows whether the fentry wrote, and writes:
     - nothing, when OPEN was written and the verdict is 0 (the common case);
     - OPEN_VERDICT (`fid`, verdict) when the LSM denied the open;
     - OPEN with flag `PATH_MISSING` and the verdict, when the fentry did not run: it was skipped for another task (the E-0089 mechanism, counted in its `recursion_misses`). The open is not lost, the missing path is located to it, and nothing guesses the path.
   - Whichever program runs first creates the file-map entry and the other finds it, so both name the same `fid`.
   - The two can share the function on the target: both saw 2,000 of 2,000 opens on the VM (E-0138).
   - **Truncation:** the path is cut at `PATH_MAX` (4,096 bytes). A path that does not fit (`-ENAMETOOLONG`) is written as its dentry name with flag `TRUNCATED`; any other error as an empty path with flag `ERROR` and the errno. Each is counted.
   - OPEN has its exact size (ADR-0017 layer 1). Because the fentry runs preemptible, its scratch buffer is claimed per call, never shared by two tasks on one CPU (the lesson of E-0097 and Falco's owner-claimed pool, tools.md §7); a failed claim writes a full-size record instead and is counted, so no path is lost to it.
   - O_PATH opens never reach `security_file_open` (K1). No I/O is possible through them; an exec through one opens the file again and is seen.
7. **Files already open at start: the snapshot's FD pass.**
   - The data-flow hooks attach before the opening snapshot. The snapshot (ADR-0007 rule 3, ADR-0024) gains a pass with `iter/task_file` over thread-group leaders (threads sharing the leader's table are skipped by the kernel, K14). For each descriptor it writes an FD record: the process key, the descriptor number, `fid`, `obj`, `f_flags`, `f_mode`, the offset, and the path from `bpf_d_path` (allowed in iterators, K10). It registers the open file and object as rules 1-2 do.
   - A file opened between attach and the iteration is seen twice; the first registration wins and the second is counted, never written twice.
   - The pass has books like the PROC pass: descriptors seen = FD written + failures by cause, in SNAP_DONE.
   - This also delivers the standard streams of processes that started before capture, which ADR-0025 deferred to this slice (its "PROC standard streams" decision): they are FD rows 0-2.
   - Every segment's opening snapshot repeats the pass, and each FD row carries the open file's and the object's facts (rules 2 and 5) with their existing ids, not only on first registration: a segment can be read alone (ADR-0007's self-describing segments).
8. **The CLOSE record and the end of an open-file id.**
   - `security_file_free` runs for every `struct file`, including failed opens (K2). Its kprobe writes CLOSE (`fid`, and flag `NEVER_OPENED` when `FMODE_OPENED` is not set), carrying the open file's pending data-flow aggregate when there is one (ADR-0005 rule 8, N1), and deletes the entry. So an open, a read and a close cost two records: OPEN and CLOSE.
   - `security_file_release` is not used for this: it is skipped for failed opens (K2). Release and free run in the same call for an opened file, so nothing is lost by using free.
   - The free may run in the task that closed the file, in task work, or in the `delayed_fput` worker (kernel-v7.0.md §5). CLOSE belongs to the open file, not to a process: its header carries `current` as every record does, with flag `KTHREAD` when that is a kernel thread, and the reader never reads it as "this process closed the file".
9. **Map lifetimes and stale entries.**
   - The open-file map is keyed by the `struct file` address and holds `fid`, `obj` and the inode address; the object map is keyed by the inode address and holds `obj` and the facts of rule 2. Entries are deleted at `security_file_free` and at `security_inode_free` (K7), both kprobes.
   - A free that the kernel skipped (counted in `recursion_misses`) leaves a stale entry whose address may be reused. Every lookup compares the stored facts (the file's inode address; the inode's `dev`, `ino`, `gen`) with the live object; a mismatch is counted as stale, and the entry is replaced with a new id. A reused address with identical facts is the residual case (INF: it needs a missed free and an identical pseudo inode number).
   - Plain hash maps, not LRU: an LRU evicts silently (tools.md §7). A full map is counted, and the event is written as its own record with the identity facts inline (ADR-0005 rule 8), so no event is lost to it.
   - Sizes are configurable and recorded in the WAL header; the defaults are set from the census in step 2.
10. **Sockets.** A socket's object is its sockfs inode. The NET records of ADR-0004 are keyed by socket cookie, which no kprobe or classic tracepoint can read on 7.0 (ADR-0025 rule 5). The exact join is to put the socket's object id in NET (its fexit programs can read the socket's inode; for accept, the new socket has its file before `ops->accept` runs, K16). That is a NET record version change (NET v3), made in step 2e (decided below).

### Consequences

- Good: no two objects are ever merged by capture; pipes and sockets stay distinct past the 32-bit wrap; overlay bytes are counted once with both identities known; btrfs subvolumes are told apart.
- Good: no open is lost to a skip for other tasks, a missing path is visible per open, and the common case is one record per open (two for open, read, close).
- Good: the snapshot describes the files open at start, standard streams included, which closes ADR-0025's deferred item.
- Bad: two programs per open (kprobe.session and fentry), and one more kprobe on every `struct file` free and every inode free. With a trivial body on the VM a kprobe.session added 141 ns per call and a fentry 14 ns (on `vfs_read`, E-0138); the real bodies are measured in slice B's own tests (STATE decision 17).
- Bad: on filesystems the reader does not trust (rule 3), one file evicted from the inode cache and read again becomes two nodes.
- Bad: the BACKING record depends on a struct private to fs/file_table.c whose layout on the VM differs from upstream (K6); CO-RE handles the layout, and the self-test of step 2 checks the result against `stat` on an overlay mount.

### Confirmation

Built in step 2 (slice B code); each check fails if its rule is broken:
1. The load-time self-test opens, reads and closes a file, a pipe and a socket, and checks every object fact against `stat(2)`/`statx(2)`/`statfs(2)` (`dev`, `ino`, `mode`, `fs_magic`, `nlink`; `stx_subvol` when the test file is on btrfs), the OPEN and FILE flags against the open, and OPEN's path against the path it opened. A test-only load switch leaves the fentry unattached: every open must then arrive from the session return with `PATH_MISSING`, and the books must still close.
2. `it_p15d.sh` (a new case): the pipe's writer and reader share one `obj`; an overlay mount's file has a BACKING record whose real object matches `stat` of the upper or lower file, and its bytes appear once; a deep path longer than `PATH_MAX` is flagged `TRUNCATED` and counted; an open that fails after `security_file_open` ends with `NEVER_OPENED` (a FIFO opened `O_WRONLY | O_NONBLOCK` with no reader: `fifo_open`, the FIFO's `->open`, returns `-ENXIO`, v7.0 fs/pipe.c L1121, L1186-1188, L1247); a process running before capture has FD rows 0-2 matching `fstat` of its descriptors.
3. A mutation sweep entry per rule: dropping the stale check, writing OPEN without the claim, the session return writing OPEN when the fentry already did, or nothing when it did not, skipping BACKING, using release instead of free, CLOSE dropping its aggregate.

### Falsifier

Reopen if:
- two different objects ever get one node under rule 3 (for example two pipes, or a reused ext4 inode whose generation repeated);
- a VM run shows the kprobe.session skipped for another task, or `PATH_MISSING` opens common enough that paths are routinely missing (the maintainer decides the threshold from slice B's measurement);
- overlay bytes are counted twice in any test, or a `vfs_iter_*` path is found that carries user I/O on a non-overlay file past our hooks.

## Decisions (taken 2026-11-09, maintainer, E-0139)

1. **kprobe.session instead of separate kprobe.multi and kretprobe.multi links**, for every entry/return pair in slice B (the open here, the read and write hooks of ADR-0005). Same mechanism, one link: the kernel skips entry and return together, and the 8-byte cookie replaces a per-thread stash (K11). Measured on the VM with a trivial body (E-0138): 141 ns added per `vfs_read` call against 315 ns for the two links, 39 % less; fexit, which can be skipped, adds 22 ns.
2. **NET v3 with the socket's object id** (rule 10), in step 2e, with its own self-test check; it closes ADR-0025's deferred socket → NET join by identity.
3. **The reader's trust table** (rule 3): ext4, xfs, tmpfs and btrfs join by tuple, everything else per lifetime; a filesystem is added only with its source evidence.
4. **`SUBVOL_UNKNOWN`** (rule 2) for btrfs objects when btrfs's BTF was absent at load.
5. **One record per open** (N1, rules 2, 6, 8): object facts inline, OPEN from the fentry, the session return writing only on a skip or a denial, CLOSE carrying the last aggregate.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | Aggregability needs the same open descriptor for file reads and writes | PDF | Xu et al. CCS'16 §3.1.3, Def. 4, p. 5; design-checks X1 |
| 2 | Generations: random on ext4, tmpfs, xfs v3; transid on btrfs; 0 elsewhere; ext4 reuses freed numbers | SRC | kernel-v7.0.md §3 |
| 3 | Pseudo inode numbers come from a wrapping 32-bit counter | SRC | design-checks K8 |
| 4 | btrfs reports `anon_dev` and the root id, not `s_dev` | SRC | design-checks K9 |
| 5 | Overlay opens a backing file through `security_file_open` at open, and an upper file lazily after copy-up | SRC | design-checks K4 |
| 6 | Overlay I/O reaches the backing file only through `vfs_iter_*` / `vfs_iocb_iter_*` | SRC | design-checks K5 |
| 7 | The VM's `struct backing_file` has a field upstream v7.0 lacks | MEAS | design-checks K6 |
| 8 | `security_file_open` precedes `->open`; failed opens get no release but always a free | SRC | design-checks K1, K2 |
| 9 | Pseudo files never reach `security_file_open` | SRC | design-checks K3 |
| 10 | `bpf_d_path` is allowed in fentry/fexit on `security_file_open` and in iterators; not in kprobes | SRC | design-checks K10; kernel-v7.0.md §2 |
| 11 | kprobe.session skips entry and return together and has a per-call cookie | SRC | design-checks K11 |
| 12 | kprobe.multi runs with preemption off and is not skipped through program nesting | SRC | kernel-v7.0.md §1.2 |
| 13 | Tracee keys files by (dev, inode, ctime) and truncates deep paths without a flag; Kunai keys by inode only; Tetragon flags unresolved paths | SRC | tools.md §3 |
| 14 | LRU maps evict silently and approximately | SRC/BLOG | tools.md §7 |
| 15 | PIDSMaker's detectors read full paths (Kairos hashes every prefix) | SRC | provenance-and-pids.md §4 |
| 16 | The task-file iterator skips threads sharing the leader's table | SRC | design-checks K14 |
| 17 | The accept fexit can read the new socket's inode | SRC | design-checks K16 |
| 18 | The hooks named here exist in BTF and ftrace on 7.0.0-38: `security_file_open`, `vfs_read`, `vfs_write`, `vfs_readv`, `vfs_writev` | MEAS | `docs/evidence/phase0/02-p1-attach-points.txt` |
| 19 | `security_file_free` and `security_inode_free` in BTF and ftrace on 7.0.0-38; the kprobe.session config (`CONFIG_FPROBE=y`) | MEAS | design-checks V1, V4; [`vm-sliceb-attach.txt`](../evidence/research/2026-11-09-slice-b-design/vm-sliceb-attach.txt) |
| 20 | kprobe.session attaches on 7.0.0-38, and beside a fentry on `security_file_open` both see every open (2,000 of 2,000) | MEAS | [`2026-11-09-rw-hook-cost-vm`](../evidence/probes/2026-11-09-rw-hook-cost-vm/README.md) (PR #60), E-0138 |
| 21 | btrfs and overlay are modules on the VM; their BTF exists only once loaded | MEAS | design-checks V6 |
| 22 | Added per `vfs_read` call, trivial body, VM: fentry 14 ns, fexit 22 ns, kprobe.multi entry 21 ns, two links with a stash 315 ns, kprobe.session 141 ns; no skips (one thread) | MEAS | same, E-0138 |

## Pros and cons of the options

### I1. (device, inode)
- Good: simplest; what most tools record.
- Bad: merges a deleted file with the next file given its number, and two pipes after the counter wraps (driver 1).

### I2. (device, inode, ctime)
- Good: separates incarnations without a generation.
- Bad: ctime changes on every write and chmod, so one file becomes many; two files can share a ctime.

### I3. Facts plus a capture sequence (chosen)
- Good: never merges; the reader can still join one file across in-memory lifetimes where the facts allow.
- Bad: two maps with frees hooked; the reader carries a trust table.

### I4. Capture sequence only
- Good: never merges.
- Bad: one file read at two times becomes two nodes whenever it leaves the inode cache, and nothing joins them.

### P1. fexit with `bpf_d_path` for everything
- Good: one program; exact path.
- Bad: when it is skipped for another task the whole open is lost, counted only per program, not located.

### P2. kprobe with a dentry walk
- Good: not skipped for other tasks.
- Bad: a hand-written walk cannot take the kernel's locks, misses pseudo names and `(deleted)`, must cross mounts by itself and is bounded in depth; Tracee's walk gives a plausible wrong path past 20 components (tools.md §3).

### P3. fentry writes the open with its path, kprobe.session covers its skips (chosen)
- Good: the open is never lost to a skip for another task; the path is the kernel's own; a lost path is located; one record in the common case.
- Bad: two programs per open, joined by `fid`.
