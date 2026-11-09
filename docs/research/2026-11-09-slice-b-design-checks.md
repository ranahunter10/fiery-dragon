# Slice B design checks (2026-11-09)

The checks made in this session before ADR-0015 and ADR-0005 were written. It closes the gaps the [2026-11-06 research](2026-11-06-dataflow-slice-b/README.md) left open where a design rule depends on them. Nothing was run; the kernel source was read, and the paper was read in the PDF.

Grades as in `CONTRIBUTING.md` §5.

## 1. Xu et al., CCS'16 (CPR), read in the PDF

Source: the authors' PDF (DOI 10.1145/2976749.2978378; `https://www.eecis.udel.edu/~hnw/paper/ccs16b.pdf`). The maintainer supplied the file on 2026-11-09 (13 pages, sha256 `5e0459f233ead9e372d35d5684549813a891d50c54888f2c677b9f663bd8a9da`; not committed, it is the authors' copyright). The session read its text (extracted with pypdf) for §3.1-3.4, Algorithms 1-3, §4.2-4.4 and Tables 2-3. **Grade: PDF.**

An earlier pass the same day went through the session's fetch tool, because the proxy refuses that host. Reading the PDF itself confirmed X1-X8, corrected X9 and added X10-X12. Page numbers are the PDF's.

| # | Question | What the paper says | Where |
|---|---|---|---|
| X1 | When are two events aggregable? | Same event type, same source and destination entities, and, for some types such as file reads and writes, the same attributes, the file open descriptor being the example. Def. 4 names the attribute set A (process executable, file path, event type, type-specific operation such as read, write or execute). Open/close sessions and several handles on one file are not discussed. | §3.1.3, Def. 4, p. 5 |
| X2 | The backward check | It fails if the time window of any *incoming* event of the source u overlaps [te(e_p), te(e_l)], the end times of the stack top and the new event. Def. 2 states the same as te(e) > te(e1) and ts(e) < te(e2); §3.2.1 walks through the three cases. | Alg. 2, p. 5; Def. 2, p. 4; §3.2.1, p. 6 |
| X3 | The forward check | It fails if the time window of any *outgoing* event of the destination v overlaps [ts(e_p), ts(e_l)], the start times. Def. 2 states it as te(e) > ts(e1) and ts(e) < ts(e2), and §3.2.2 the same. Only the one-paragraph overview in §3.2 says "an end time between the start times", which is narrower. | Alg. 3, p. 5; Def. 2, p. 5; §3.2, §3.2.2, p. 5-6 |
| X4 | The merged event | The later event is absorbed: te(e_p) is set to te(e_l) and the later event is deleted, so the window becomes [ts(e1), te(e2)]; as a point of interest it backtracks from te(e2) and forward-tracks from ts(e1). | Alg. 1 MERGE, p. 5; §3.2.3, p. 6 |
| X5 | How attributes combine | "Tune attributes of e_p" and nothing more; sizes and counts are never discussed. | Alg. 1, p. 5; §3.2.3 |
| X6 | Which event types | Not listed as a rule. Def. 4's examples are file access and IP channel access; Fig. 1-2 show exec, read and write edges. Process creation is not excluded. | §3.1.3; Fig. 1-2, p. 3-4 |
| X7 | Bounds and flushing | One stack per (source, destination, type); no bound and no flush policy. The prototype runs in user space at about 4,000 events per second with hash tables, under 2 GB for CPR, PCAR and the domain rules together. | Alg. 1, p. 5; §4.4, p. 11 |
| X8 | Causal dependency | e1 = (u1, v1) and e2 = (u2, v2) are dependent if v1 = u2 and ts(e1) < te(e2). | Def. 1, p. 4 |
| X9 | Results (corrected) | CPR's average reduction is 56 % over one month of 31 hosts (18 Linux, 13 Windows), raising capacity 2.27x (2.63x Linux, 1.61x Windows); the "up to 3.4x" of the introduction is CPR+PCAR's maximum, not a conflicting figure. Over 20,000 random backtracking points, CPR gave 0 false positives; a naive 10-second window gave 2,778 (13.9 %), and those false-positive cases had 17 % extra connectivity and 8.8 % extra entities. On ten attack and workload cases, CPR kept every connectivity (Table 2). | §4.2, Fig. 7, p. 8; Tables 2-3 and §4.3, p. 10; abstract, p. 1 |
| X10 | Reverse-direction events (new) | Def. 2 leaves out the events between the same two entities in the other direction: the backward condition counts incoming events of u from any entity *except v*, the forward one outgoing events of v to any entity *except u*. Algorithms 2 and 3 do not make that exception: they test every incoming event of u and every outgoing event of v. | Def. 2, p. 4-5; Alg. 2-3, p. 5 |
| X11 | Input order (new) | Algorithm 1 requires the event stream sorted by start time. | Alg. 1, p. 5 |
| X12 | Domain rules (new) | §3.4.1 drops events on "special files" with no explicit information flow (the example is `/proc`; `/shm` is kept). §3.4.2 drops every event of a temporary file, defined as a file touched by only one process in its lifetime. Both run after CPR. | §3.4.1-3.4.2, p. 7-8 |

What the design takes from it:
- the aggregation key includes the open file, not only the (process, file) pair (X1);
- one window covering both checks, [ts(e1), te(e2)], is at least as strict as the two checks together (X2, X3): it contains [te(e1), te(e2)] and [ts(e1), ts(e2)], so an event that overlaps either overlaps it (INF, a set inclusion, argued in ADR-0005);
- the kernel follows Algorithms 2-3, not the narrower Def. 2: an event from the same pair in the other direction also blocks a fold (X10). That gives up some reduction (a process that reads and writes one file alternately) and never exactness;
- Algorithm 1's sorted input (X11) holds per key because an aggregate has one owner thread (ADR-0005 rules 4 and 10): one thread's events on one open file start and end in order. The kernel sees events at their end, not sorted by start; the in-progress marks of ADR-0005 rule 5 are what make the check online;
- the record carries first and last time, count and bytes, because the paper leaves attributes open (X5);
- the bounds and the flush rules are ours to state (X7);
- the domain rules (X12) are downstream at most, never in capture: §3.4.2 would delete the trace of a memfd payload written and run by one process (research note 2026-11-06 §1a). §3.4.1's "special files" point the same way as the shared-device false flows of Improv (Kimm et al., PRISM 2026): a matter for the reader and the graph, not for capture.

## 2. Kernel v7.0 (`028ef9c96e96`), read in a sparse clone

| # | Fact | Grade | Where |
|---|---|---|---|
| K1 | `do_dentry_open` sets `f_inode` (L895), calls `security_file_open` (L926) **before** `->open` (L949), and sets `FMODE_OPENED` only after it (L953). An O_PATH open returns earlier (L900-904) and never reaches `security_file_open`. | SRC | fs/open.c |
| K2 | `__fput` returns without `security_file_release` when `FMODE_OPENED` is not set (L450-451), so an open that fails after `security_file_open` has no release; `file_free` calls `security_file_free` for **every** struct file (L69-71, reached from L482 and L524). | SRC | fs/file_table.c |
| K3 | Pseudo files (`alloc_file_pseudo`) are born with `FMODE_OPENED` (L337), so they get a release, but no `security_file_open`. | SRC | fs/file_table.c |
| K4 | `ovl_open` opens its backing file at open time (`ovl_open_realfile`, L222) through `backing_file_open` → `vfs_open` (fs/backing-file.c L32-52), so `security_file_open` fires a second time, for a file with `FMODE_BACKING` whose `backing_file_user_path()` is the overlay file's path. After a copy-up, an upper file is opened lazily from the read/write path (`ovl_real_file_path`, L122-160) and fires it again. | SRC | fs/overlayfs/file.c |
| K5 | Overlay reads go to the backing file through `vfs_iter_read` / `vfs_iocb_iter_read` (fs/backing-file.c L169, L180) and writes through `vfs_iter_write` / `vfs_iocb_iter_write` (L223, L243), not through `vfs_read`/`vfs_write`/`vfs_readv`/`vfs_writev`. | SRC | fs/backing-file.c |
| K6 | `struct backing_file` is `{ struct file file; union { struct path user_path; ... }; }` in upstream v7.0 (L47-53). The VM's BTF has a `void *security` after the union, and so has the dev container's 6.18 kernel; where the field comes from is not known. | SRC + MEAS | fs/file_table.c; `bpf/vmlinux/vmlinux-7.0.0-38.h` L46157-46164; [`container-btf.txt`](../evidence/research/2026-11-09-slice-b-design/container-btf.txt) |
| K7 | `security_inode_free` is called from `__destroy_inode` (L372) for every inode. | SRC | fs/inode.c |
| K8 | `get_next_ino` (pipe, socket and other pseudo inodes) is a 32-bit counter handed out in per-CPU batches of 1024, skipping 0 (L1142-1166): it wraps. | SRC | fs/inode.c |
| K9 | btrfs `getattr` reports `st_dev = root->anon_dev` and `stx_subvol = root->root_key.objectid` (L8262-8265); `struct btrfs_inode` has `root` (btrfs_inode.h L129). | SRC | fs/btrfs/inode.c |
| K10 | `bpf_d_path` is allowed for any TRACING program attached to a function in `btf_allowlist_d_path` (fentry and fexit alike), which holds `security_file_open`, and for any iterator (L931-958). | SRC | kernel/trace/bpf_trace.c |
| K11 | kprobe.session: when the entry run is skipped because `bpf_prog_active` is set, it returns 1 and the return run is skipped too (L2571-2575, L2600-2601); `bpf_session_cookie()` gives 8 bytes per call shared by both runs (L3347-3352). With separate kprobe.multi and kretprobe.multi links the two runs are skipped independently. | SRC | kernel/trace/bpf_trace.c |
| K12 | KPROBE, TRACEPOINT, PERF_EVENT and RAW_TRACEPOINT programs cannot use `bpf_spin_lock` (L21607-21658). | SRC | kernel/bpf/verifier.c |
| K13 | A non-sleepable BPF iterator runs under `rcu_read_lock_dont_migrate()` and takes no `bpf_prog_active` (L683-703); the hash map's iterator walks buckets under RCU only (hashtab.c L2104-2121). | SRC | kernel/bpf/bpf_iter.c, kernel/bpf/hashtab.c |
| K14 | `iter/task_file` skips threads whose file table is the leader's (L80, L126). | SRC | kernel/bpf/task_iter.c |
| K15 | `read(2)`/`write(2)` on a socket go `vfs_read` → `sock_read_iter` → `sock_recvmsg` (L1170) and `vfs_write` → `sock_write_iter` → `__sock_sendmsg` (L1195), so both the VFS hooks and the `sock_*_length` tracepoints (L722, L1072) see the same transfer. | SRC | net/socket.c |
| K16 | `do_accept` gives the new socket its file (L1979) before `ops->accept` (L1988), so the accept fexit can read the new socket's inode. | SRC | net/socket.c |
| K17 | `vmsplice` (L1578) moves user memory into a pipe through `vmsplice_to_pipe` (L1534) and `tee` (L1977) copies pipe to pipe; neither passes `rw_verify_area` or the VFS read/write functions. | SRC | fs/splice.c |
| K18 | An overflowing CQE fires `io_uring_cqe_overflow` (io_uring.c L668), with no request or file. | SRC | io_uring/io_uring.c, include/trace/events/io_uring.h L565 |

## 3. The VM: 7.0.0-38 (MEAS)

[`vm-sliceb-attach.txt`](../evidence/research/2026-11-09-slice-b-design/vm-sliceb-attach.txt), run by the maintainer on 2026-11-09:

| # | Fact | Settles |
|---|---|---|
| V1 | Every planned hook function is in BTF and attachable by ftrace: `security_file_open`, `security_file_release`, `security_file_free`, `security_inode_free`, `security_mmap_file`, `security_file_mprotect`, `vfs_read`, `vfs_write`, `vfs_readv`, `vfs_writev`, `do_splice`, `do_sendfile`, `vfs_copy_file_range`, `vmsplice_to_pipe`, `do_tee`, the inode and path rename/unlink/link/truncate hooks, `vfs_rename`, `vfs_unlink`, `vfs_link`, `do_truncate`, `__fput`, `do_file_open`, `filename_unlinkat`, `filename_renameat2`. | O1 |
| V2 | `vmsplice_to_user` is in neither (inlined into the system call, v7.0 fs/splice.c L1501, L1610). The pipe-to-user direction of vmsplice needs another hook point: the system call function itself, with the direction taken from the file's mode as the kernel does (L1592-1610). Step 2d decides. | O5 |
| V3 | The five tracepoints exist: `sock_send_length`, `sock_recv_length`, `io_uring_complete`, `io_uring_submit_req`, `io_uring_cqe_overflow`. | — |
| V4 | `CONFIG_FPROBE=y`, `CONFIG_FUNCTION_GRAPH_TRACER=y`, `CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y`: kprobe.multi and kprobe.session can be built on this kernel. That they attach, alone and beside a fentry on the same function, is still for step 2's load test. | O2 (config only) |
| V5 | `CONFIG_SECURITY_PATH=y`, `CONFIG_PREEMPT_RCU=y`, `CONFIG_IA32_EMULATION=y` (32-bit system calls exist, so a system-call hook point has an `__ia32_` twin). | — |
| V6 | `CONFIG_BTRFS_FS=m` and `CONFIG_OVERLAY_FS=m`, neither loaded at the time: their BTF is absent until the module loads. `struct backing_file` is in vmlinux, so the BACKING record does not need overlay's BTF; btrfs's subvolume id does need btrfs's (ADR-0015 rule 2). | O3 |
| V7 | `struct backing_file` on the running kernel has `void *security` after the union, as the VM's `vmlinux.h` says (K6). | K6 |

Open items as of the first pass (struck through where §3 settles them):
- ~~O1~~ (V1): `security_file_release`, `security_file_free`, `security_inode_free`, `vmsplice_to_pipe`, `do_tee` (or the tee path) and the rename/unlink hooks in BTF and in `available_filter_functions` on 7.0.0-38 (P1 checked the others, `docs/evidence/phase0/02-p1-attach-points.txt`);
- O2 (config settled by V4; attaching still for step 2): kprobe.multi and kprobe.session attach on 7.0.0-38 (`CONFIG_FPROBE`), and a fentry and a kprobe.session on the same function at once;
- ~~O3~~ (V6): whether btrfs and overlay are modules on the VM (where their BTF lives);
- ~~O5~~ (V2): the dev container's 6.18 BTF ([`container-btf.txt`](../evidence/research/2026-11-09-slice-b-design/container-btf.txt)) has no `vmsplice_to_pipe` / `vmsplice_to_user` (probably inlined) nor the 7.0 `do_file_open` / `filename_*` names; VMSPLICE may need the syscall's own entry instead. The VM answers for 7.0.0-38;
- O4 (not needed by the sweep if it empties the slot instead of deleting the entry, ADR-0005 rule 9 under discussion): whether deleting the current element from inside a hash map iterator program is allowed and safe (the sweep of ADR-0005 rule 9 needs it).
