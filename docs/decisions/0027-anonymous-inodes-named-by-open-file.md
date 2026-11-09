---
status: accepted
date: 2026-11-10
owner: Ashish Rana
consulted: [kernel v7.0 fs/anon_inodes.c; ADR-0015; the step 2a dry run on CI (E-0145) and on the VM (E-0146); maintainer's decision 2026-11-10 (E-0147, STATE decision 20)]
supersedes: ADR-0015 rule 3, second bullet, for the anonymous-inode filesystem only (magic 0x09041934). The rest of rule 3, and every other rule of ADR-0015, is unchanged.
---

# 0027: On the anonymous-inode filesystem the graph node is the open file, not the object

## Context and problem statement

ADR-0015 rule 3 lets the reader decide what a graph node is: the (dev, subvol, ino, gen) tuple on trusted filesystems, and the object id (one in-memory inode) everywhere else. The object id is right when one inode is one thing. On the anonymous-inode filesystem it is not: `anon_inode_getfile`, `anon_inode_getfile_fmode` and `anon_inode_getfd` hook every file they make to one inode the kernel allocates at boot (`fs/anon_inodes.c` lines 153, 195-199 and 351, v7.0). eventfd, signalfd, timerfd (`anon_inode_getfile_fmode`), eventpoll and the bpf map, program and link files (`anon_inode_getfile`, `anon_inode_getfd`) are all made that way (`fs/eventfd.c` 404, `fs/signalfd.c` 274, `fs/timerfd.c` 435, `fs/eventpoll.c` 2192, `kernel/bpf/syscall.c` 1189, 2534, 3470). The step 2a dry run saw it on both kernels: 21 descriptors of the probe's own process (bpf maps, links, programs, an eventpoll, a BTF object, the iterator) had one object id (E-0145, E-0146). Under rule 3 two unrelated eventfds would be one node, and data written to one would appear to flow to readers of the other: the false merge ADR-0015's first driver forbids.

**Question:** what names a graph node for a file on the anonymous-inode filesystem?

## Decision drivers

1. Never merge two different objects (ADR-0015 driver 1).
2. Facts in the kernel, interpretation in the reader (ADR-0015 driver 2): no kernel change if the records already carry what the reader needs.
3. One rule the reader can apply from the records alone.

## Considered options

1. Keep rule 3: the object id is the node.
2. The open file (`fid`) is the node for every object whose `fs_magic` is the anonymous-inode filesystem's.
3. Change the kernel side: give each anonymous file an object id of its own (key the object map by the file, not the inode, on that filesystem).

## Decision outcome

**Chosen option 2**, because it removes the false merge (driver 1) without a kernel change (driver 2): every record that names an anonymous file already carries `fid` and the object's `fs_magic`.

### Rules

1. For an object whose `fs_magic` is `0x09041934` (`ANON_INODE_FS_MAGIC`, include/uapi/linux/magic.h), the reader's node is the open file: one node per `fid`.
2. This holds also for anonymous files with an inode of their own (`anon_inode_create_getfile`: io_uring, userfaultfd; `anon_inode_make_secure_inode`: KVM): such an inode has one file, so the node is the same thing either way, and the reader needs no way to tell the two kinds apart.
3. Processes that share the open file (fork, `dup`, `SCM_RIGHTS`) share its `fid` (ADR-0015 rule 1), so an eventfd passed between processes is still one node.
4. The kernel side is unchanged: OPEN, FD and the later FILE and FLOW records keep naming the object as ADR-0015 says; the object id of the shared inode stays in the records as a fact.

### Consequences

- Good: no false merge through eventfd, signalfd, timerfd, eventpoll or bpf objects.
- Good: no kernel change, no record change.
- Bad: the reader carries one more filesystem rule beside rule 3's trust table.

### Confirmation

- The reader's node function (step 7, the graph builder) has a test: two FD rows on the anonymous-inode filesystem with one object id and two `fid`s are two nodes; one `fid` in two processes is one node.
- Step 2a's `it_p15d.sh` case opens two eventfds in two processes and checks that their FD rows have one object id and two `fid`s (the fact this ADR rests on).

### Falsifier

Reopen if a file on the anonymous-inode filesystem is found whose one open file stands for two things that must stay apart, or if a kernel gives the shared anonymous inode's files distinct object facts so that the object id would no longer merge them.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | Files made by `anon_inode_getfile`, `anon_inode_getfile_fmode` and `anon_inode_getfd` share one inode, allocated once at init; eventfd, signalfd, timerfd, eventpoll and bpf objects use them | SRC | `fs/anon_inodes.c` lines 153, 195-199, 226-235 and 351; `fs/eventfd.c` 404, `fs/signalfd.c` 274, `fs/timerfd.c` 435, `fs/eventpoll.c` 2192, `kernel/bpf/syscall.c` 1189, 2534, 3470 (v7.0) |
| 2 | `anon_inode_create_getfile` makes an inode per file; io_uring and userfaultfd use it | SRC | `fs/anon_inodes.c` lines 113-132, 146-148 and 267; `io_uring/io_uring.c` 2754, `fs/userfaultfd.c` 2156 (v7.0) |
| 3 | 21 anonymous-inode descriptors of one process had one object id, on CI's 7.0.0-1017-azure and on the VM's 7.0.0-38 | MEAS | [`2026-11-10-sliceb-probe-ci`](../evidence/probes/2026-11-10-sliceb-probe-ci/README.md), [`2026-11-10-sliceb-probe-vm`](../evidence/probes/2026-11-10-sliceb-probe-vm/README.md) |
| 4 | Shared open files share a `fid` (fds 1 and 2 after `dup` had one `fid` on the VM) | MEAS | same, `sliceb-probe.txt` |

## Pros and cons of the options

### 1. Keep rule 3
- Good: nothing changes.
- Bad: every eventfd, timerfd and eventpoll of the run is one node.

### 2. The open file is the node (chosen)
- Good: exact; no kernel change.
- Bad: one more reader rule.

### 3. A per-file object id in the kernel
- Good: the object id alone would be right everywhere.
- Bad: a special case in the hot identity path, and the object id would no longer mean "one in-memory inode", which ADR-0015's stale checks rely on.
