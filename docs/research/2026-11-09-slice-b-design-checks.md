# Slice B design checks (2026-11-09)

The checks made in this session before ADR-0015 and ADR-0005 were written. It closes the gaps the [2026-11-06 research](2026-11-06-dataflow-slice-b/README.md) left open where a design rule depends on them. Nothing was run; the kernel source was read, the paper was read through a fetch tool.

Grades as in `CONTRIBUTING.md` §5.

## 1. Xu et al., CCS'16 (CPR), from the paper's full text

Source: the authors' PDF, `https://www.eecis.udel.edu/~hnw/paper/ccs16b.pdf` (DOI 10.1145/2976749.2978378). The session cannot download files from that host (the proxy refuses it), so the paper was read through the session's fetch tool, which answers questions from the PDF's full text. Each answer below names the section it came from. **Grade: PDF, read through a tool, not yet by a person.** The research register row R-039 stays `verified = no` until the maintainer reads §3.1.3 and Algorithms 2 and 3 himself; ADR-0005 says so.

| # | Question | Answer from the paper | Where |
|---|---|---|---|
| X1 | When are two events aggregable? | Same event type, same source and destination entities, and the same attributes. For file reads and writes the attributes include the file open descriptor (the only mention of descriptors in the paper; open/close sessions and several handles on one file are not discussed). | Def. 4, §3.1.3 |
| X2 | What does the backward check test? | It fails if any *incoming* event of the source node u has a time window overlapping the interval between the **end** times of the stored event and the new one, [te(e1), te(e2)]. The prose agrees. | Alg. 2, §3.2.1 |
| X3 | What does the forward check test? | It fails if any *outgoing* event of the destination node v has a time window overlapping the interval between the **start** times, [ts(e1), ts(e2)]. The §3.2 overview words it as "an end time between the start times", which is narrower than the algorithm; §3.2.2 and Alg. 3 use the overlap. | Alg. 3, §3.2.2 |
| X4 | The merged event's window | [ts(e1), te(e2)]: the earlier event absorbs the later one. | §3.2.3 |
| X5 | How attributes combine | Not specified: the merge copies the attributes and "tunes" them; byte counts are never discussed. | §3.2.3, Alg. 1 |
| X6 | Which event types | Not listed. File read and write are the worked example; Def. 4 names file access and IP channel access; exec appears in Fig. 1. Process creation is not excluded explicitly. | §3.1.3, Fig. 1 |
| X7 | Bounds and flushing | One stack of events per (source, destination, type); no size limit or flush policy; events that cannot be aggregated are output. | §3.2, §4.4 |
| X8 | Causal dependency | e1=(u1,v1) and e2=(u2,v2) are dependent if v1 = u2 and ts(e1) < te(e2). | Def. 1, §3.1.1 |
| X9 | Results | CPR removes 56 % of events on average over one month of 31 hosts (18 Linux, 13 Windows), with 0 false positives on random points of interest; a naive 10-second window gave 17 % false connectivity. The paper's capacity figures are not consistent (3.4x in the introduction, 2.27x and 2.18x in §4). | §4.2, Table 3 |

What the design takes from it:
- the aggregation key includes the open file, not only the (process, file) pair (X1);
- one window covering both checks, [ts(e1), te(e2)], is at least as strict as the two checks together (X2, X3): it contains [te(e1), te(e2)] and [ts(e1), ts(e2)], so an event that overlaps either overlaps it (INF, a set inclusion, argued in ADR-0005);
- the record carries first and last time, count and bytes, because the paper leaves attributes open (X5);
- the bounds and the flush rules are ours to state (X7).

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

Still OPEN, to be checked on the VM before or with step 2 (commands in the PR):
- O1: `security_file_release`, `security_file_free`, `security_inode_free`, `vmsplice_to_pipe`, `do_tee` (or the tee path) and the rename/unlink hooks in BTF and in `available_filter_functions` on 7.0.0-38 (P1 checked the others, `docs/evidence/phase0/02-p1-attach-points.txt`);
- O2: kprobe.multi and kprobe.session attach on 7.0.0-38 (`CONFIG_FPROBE`), and a fentry and a kprobe.session on the same function at once;
- O3: whether btrfs and overlay are modules on the VM (where their BTF lives);
- O5: the dev container's 6.18 BTF ([`container-btf.txt`](../evidence/research/2026-11-09-slice-b-design/container-btf.txt)) has no `vmsplice_to_pipe` / `vmsplice_to_user` (probably inlined) nor the 7.0 `do_file_open` / `filename_*` names; VMSPLICE may need the syscall's own entry instead. The VM answers for 7.0.0-38;
- O4: whether deleting the current element from inside a hash map iterator program is allowed and safe (the sweep of ADR-0005 rule 9 needs it).
