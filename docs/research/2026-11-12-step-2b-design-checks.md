# Step 2b design checks (2026-11-12)

The checks made before step 2b's programs, after its records (PR "schema: FLOW and FILE records"). They close two gaps the accepted ADRs leave to the code, and list what the 2b dry run must measure on the VM. Nothing was run: the kernel source (v7.0, tag `Linux 7.0`, commit 028ef9c) and two tools' sources were read. Grades as in `CONTRIBUTING.md` §5.

## 1. Facts

| # | Fact | Grade | Where |
|---|---|---|---|
| D1 | A kprobe.session's cookie is 8 bytes per call: the link sets `entry_data_size = sizeof(u64)`, and `bpf_session_cookie()` returns that slot. A session on `vfs_read` cannot keep both the `struct file *` (needed at the return, where the arguments are gone) and the entry time in it. | SRC | kernel/trace/bpf_trace.c L2846, L3347-3352 |
| D2 | `bpf_task_storage_get` and `bpf_task_storage_delete` are in the base helper set given to every program with CAP_BPF, kprobes included; 7.0 has no separate "recursion-checked" variant. | SRC | kernel/bpf/helpers.c L2169-2172; kernel/bpf/bpf_task_storage.c L169-197 |
| D3 | A task-storage lookup that hits the per-task cache takes no lock (two loads and a compare); a miss walks the task's short list; creating the entry (`BPF_LOCAL_STORAGE_GET_F_CREATE`) allocates and takes an rqspinlock, which can fail and returns NULL. The entry is freed with the task. | SRC | include/linux/bpf_local_storage.h L146-172; kernel/bpf/bpf_local_storage.c L403-420, L697-746 |
| D4 | Tracee keeps a syscall's entry time per thread in an LRU hash keyed by tid (`task_info_map`, 10,240 entries), which evicts silently; Tetragon uses `BPF_MAP_TYPE_TASK_STORAGE` for its per-task state on 6.18+ kernels. | SRC | study-tracee pkg/ebpf/c/maps.h L61-66, tracee.bpf.c L70-88; study-tetragon bpf/process/uprobe_dyn.h L94 (included for 6.18+ objects, uprobe_offload.h L57-62) |
| D5 | `sock_send_length` is fired with flags 0 always: the send side passes no message flags. `sock_recv_length` passes the receive flags (so `MSG_PEEK` is visible). Both carry the socket's `struct sock *`, its family and protocol, and the return. | SRC | net/socket.c L719-735, L1070-1085; include/trace/events/sock.h L267-306 |
| D6 | Every user-space send and receive path reaches the two tracepoints: `write`/`read` through `sock_write_iter`/`sock_read_iter` (L1195, L1170), `sendto`/`recvfrom` (L2206, L2256), `sendmsg`/`recvmsg`/`sendmmsg`/`recvmmsg` (L2589-2592, L2810-2812). So do `kernel_sendmsg`/`kernel_recvmsg` (L785-789, L1120-1125), which kernel code uses on sockets that have no `struct file`. | SRC | net/socket.c |
| D7 | `splice` and `sendfile` into a socket reach `sock_sendmsg` (with `MSG_SPLICE_PAGES`), so the send tracepoint fires inside them. | SRC | fs/splice.c L884 |
| D9 | Whether the VM's kernel builds task storage at all (`BPF_MAP_TYPE_TASK_STORAGE`) is not read from its config here; the dev container's 6.18 kernel creates the map. | OPEN | checked by `bench/flow_cost`'s load on the VM |
| D8 | `vfs_readv` and `vfs_writev` are `static` in 7.0; on the VM's kernel they are not inlined and attach (CLAUDE.md, measured in Phase 0). | SRC, MEAS | fs/read_write.c L992, L1030; `docs/evidence/phase0/02-p1-attach-points.txt` |

## 2. Gap 1: where FLOW's start time comes from

ADR-0005 rule 8 asks for `first_ts`, the start of the first event, and rule 5 for in-progress marks set at entry (step 2c). ADR-0015's decision 1 chose kprobe.session for "every entry/return pair ... the 8-byte cookie replaces a per-thread stash". D1 shows that for `vfs_read` the cookie cannot hold both the file and the time. Options:

| | How | Cost (to be measured) | What can go wrong, and its counter |
|---|---|---|---|
| A | cookie = the file pointer; task storage = {file, entry time} | one task-storage lookup at entry and one at return (D3) | creation fails (D3), or a nested transfer in the same task overwrote the slot (the stored file differs from the cookie's): `START_UNKNOWN`, counted |
| B | per-tid hash map, as Tracee but a plain hash (D4) | a hash update at entry, a lookup and delete at return | map full, or a stale entry after a missed exit: counted |
| C | two records per transfer (Falco's enter and exit) | twice the records | none, at twice the volume |
| D | end time only (eAudit, Tetragon's kretprobes) | none | breaks rule 8; needs a superseding ADR, and 2c's in-progress marks still need entry state |

Recommendation: **A**, because it keeps the identity in the cookie (never lost), loses only the start time when it fails (flagged per record, counted), needs no bound of its own, and frees itself with the task. To be confirmed by the dry run's cost numbers against D. The record already has `START_UNKNOWN` (schema), so the choice does not change FLOW's layout.

## 3. Gap 2: the edges of the socket tracepoints

1. **Sockets without a file** (D6): `kernel_sendmsg` on a kernel socket in a user task's context (a network filesystem, for example) fires the tracepoint with `sk->sk_socket->file` NULL. ADR-0005 rule 11 puts the kernel's internal I/O out of scope. Recommendation: count it `no_file` per kind, write nothing.
2. **Sends inside splice and sendfile** (D7): ADR-0005 rule 11 counts them `inside_splice` once SPLICE records exist (step 2d). Until then they are the only record of that transfer. Recommendation: in 2b, write them as SEND; 2d switches to the rule.
3. **Send flags** (D5): the send side has no flags, so FLOW's key for SEND is (process, open file, kind) only; `PEEK` exists for RECV only, as the schema says.

## 4. What the 2b dry run measures on the VM (before 2b's programs, as PR #61 did for 2a)

1. Each hook fires once per transfer for: `read`/`write`/`pread64`/`pwrite64`/`readv`/`writev`/`preadv2` on a regular file, a pipe, a terminal and `/dev/null`; `read`/`write`/`send`/`recv`/`sendmsg`/`recvmsg`/`sendmmsg` on TCP, UDP and UNIX sockets (the tracepoints once, the VFS hooks seeing the socket and counting it `owned_by_sock`); `sendfile` and `splice` into a socket (D7); a receive with `MSG_PEEK`.
2. Option A's start time against the entry time a separate test program records, and its failure counters at zero.
3. The added cost per call on `vfs_read` of: the session with an empty body; A's two task-storage lookups; D (no start time); and a full FLOW record (reserve, fill, submit). With E-0138's 141 ns for an empty session as the anchor.
4. The kernel's skips of every program under E-0090's contention pattern (decision 17).
