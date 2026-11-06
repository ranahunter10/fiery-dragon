# Research B: kernel facts at Linux v7.0 for the file/socket data-flow capture layer

**How this was done.** All source was read from the `v7.0` tag (raw.githubusercontent.com/torvalds/linux/v7.0/...). Links point to elixir. A cite like `file.c#Lnn` that has no link refers to the same file as the linked cite before it.

**Grades:**
- **SRC**: source read at v7.0
- **DOC**
- **BLOG**
- **INF**: my inference, never a result
- **OPEN**

Nothing was run. The Ubuntu kernel config was not read, so every claim that depends on a config option stays INF until it is checked on `p15-dev-2604`.

---

## 1. Recursion protection per attach type

### 1.1 Building blocks (SRC)

- **`bpf_prog_active`.** One global per-CPU `int` ([syscall.c#L59](https://elixir.bootlin.com/linux/v7.0/source/kernel/bpf/syscall.c#L59)). It is shared by all kprobe, classic-tracepoint, kprobe.multi and perf_event programs.
- **`prog->active`.** A per-program, per-CPU `u8[BPF_NR_CONTEXTS=4]` ([bpf.h#L1773](https://elixir.bootlin.com/linux/v7.0/source/include/linux/bpf.h#L1773), #L1802). The per-context split exists **only on ARM64**.
  - On x86, `bpf_prog_get_recursion_context` does `this_cpu_inc_return(*(int*)prog->active) == 1` ([bpf.h#L2043-L2061](https://elixir.bootlin.com/linux/v7.0/source/include/linux/bpf.h#L2043)).
  - So any nesting on that CPU counts as recursion, whatever the task or context.
- **`rcu_read_lock_dont_migrate()`.** Calls `migrate_disable()` only if `CONFIG_PREEMPT_RCU` is set, then takes the RCU read lock. Preemption stays enabled ([rcupdate.h#L987](https://elixir.bootlin.com/linux/v7.0/source/include/linux/rcupdate.h#L987)).
  - `PREEMPT_RCU` defaults to y under `PREEMPT` or `PREEMPT_DYNAMIC` ([rcu/Kconfig#L21](https://elixir.bootlin.com/linux/v7.0/source/kernel/rcu/Kconfig#L21)). That Ubuntu sets it is INF.
- **Tracepoint call site.** Normal `TRACE_EVENT`s run under `guard(srcu_fast_notrace)`, which is **preemptible** ([tracepoint.h#L305](https://elixir.bootlin.com/linux/v7.0/source/include/linux/tracepoint.h#L305)). Syscall events run under `rcu_tasks_trace` (#L319-L330).
- **Skip counter.** `bpf_prog_inc_misses_counter()` increments `stats->misses` ([syscall.c#L2445](https://elixir.bootlin.com/linux/v7.0/source/kernel/bpf/syscall.c#L2445)). Userspace reads it as `bpf_prog_info.recursion_misses` (#L5069).

### 1.2 Per attach type

**Columns:**
- (a) Preemption state while the program runs.
- (b) The recursion guard.
- (c) Can a *different task* on the same CPU be skipped because another task is preempted inside the same program?
- Last column: which counter records the loss.

**Summary of (c):** only tp_btf on normal tracepoints and the trampoline family (fentry/fexit/fmod_ret/fsession) can skip another task through program nesting. The other types are exposed only through the §1.3 map-syscall window.

| Type | (a) | (b) | (c) | Loss counter |
|---|---|---|---|---|
| **kprobe** (ftrace-based) | **off**: the ftrace recursion trylock calls `preempt_disable_notrace` ([kprobes/ftrace.c#L16-L38](https://elixir.bootlin.com/linux/v7.0/source/arch/x86/kernel/kprobes/ftrace.c#L16), [trace_recursion.h#L156](https://elixir.bootlin.com/linux/v7.0/source/include/linux/trace_recursion.h#L156)). The int3 path has IRQs off ([kprobes/core.c#L978](https://elixir.bootlin.com/linux/v7.0/source/arch/x86/kernel/kprobes/core.c#L978)). | `kprobe_running()`, then `trace_call_bpf`, then global `bpf_prog_active` ([bpf_trace.c#L109-L153](https://elixir.bootlin.com/linux/v7.0/source/kernel/trace/bpf_trace.c#L109)) | Not through nesting. Possible via §1.3. | `recursion_misses` (#L123). Kprobe `nmissed` appears as `bpf_link_info.perf_event.kprobe.missed` (syscall.c#L3963). A failed trylock is **uncounted** (ftrace.c#L28). |
| **kretprobe** (rethook) | **off**: rethook handler `preempt_disable_notrace` ([rethook.c#L299](https://elixir.bootlin.com/linux/v7.0/source/kernel/trace/rethook.c#L299)) | Same as kprobe (`trace_kprobe.c#L1732`) | Same as kprobe | When the pool is empty, `rp->nmissed++` ([kprobes.c#L2183](https://elixir.bootlin.com/linux/v7.0/source/kernel/kprobes.c#L2183)). Default `maxactive = max(10, 2·ncpu)` (#L2284): **10 on 3 vCPU**. BPF perf-kprobes pass 0 (trace_kprobe.c#L1937). Shows in `kprobe.missed`. |
| **kprobe.multi / kprobe.session** (fprobe on fgraph) | **off** (fgraph.c#L662; fprobe.c#L273, #L477) | Global `bpf_prog_active` ([bpf_trace.c#L2571](https://elixir.bootlin.com/linux/v7.0/source/kernel/trace/bpf_trace.c#L2571)) | Not through nesting. Possible via §1.3. | `recursion_misses` (#L2572). A failed fgraph reserve increments `fp->nmissed`, shown as `kprobe_multi.missed` (fprobe.c#L412; bpf_trace.c#L2419). A fgraph recursion failure is **uncounted**: the source has a "TODO … missed counter" ([fprobe.c#L419](https://elixir.bootlin.com/linux/v7.0/source/kernel/trace/fprobe.c#L419)). |
| **Classic tracepoint** (perf) | **off**: `perf_trace_##call` has `guard(preempt_notrace)` ([perf.h#L74](https://elixir.bootlin.com/linux/v7.0/source/include/trace/perf.h#L74)). Syscall events have the same guard ([trace_syscalls.c#L1419](https://elixir.bootlin.com/linux/v7.0/source/kernel/trace/trace_syscalls.c#L1419), #L1551). | Per-**task** perf rctx (`current->perf_recursion`, events/core.c#L11013), then `trace_call_bpf` with `bpf_prog_active` ([events/core.c#L11322](https://elixir.bootlin.com/linux/v7.0/source/kernel/events/core.c#L11322)) | Not through nesting. Possible via §1.3. | `recursion_misses`. When rctx < 0 the event is dropped **uncounted** ([trace_event_perf.c#L410](https://elixir.bootlin.com/linux/v7.0/source/kernel/trace/trace_event_perf.c#L410)). This can only happen within the same task. |
| **raw_tp / tp_btf** on a normal tracepoint | **on**, with migration disabled ([bpf_probe.h#L45](https://elixir.bootlin.com/linux/v7.0/source/include/trace/bpf_probe.h#L45), [bpf_trace.c#L2073-L2093](https://elixir.bootlin.com/linux/v7.0/source/kernel/trace/bpf_trace.c#L2073)) | Per-program `prog->active` | **YES.** This is the E-0089 mechanism. | `recursion_misses` (#L2081) |
| **raw_tp / tp_btf** on `raw_syscalls:sys_enter/exit` | **off**: `__BPF_DECLARE_TRACE_SYSCALL` uses `preempt_disable_notrace` ([bpf_probe.h#L56-L64](https://elixir.bootlin.com/linux/v7.0/source/include/trace/bpf_probe.h#L56)) | Per-program | No | `recursion_misses` |
| **fentry / fexit / fmod_ret / fsession** | **on**. TRACING programs other than ITER satisfy `bpf_prog_check_recur` ([bpf_verifier.h#L965](https://elixir.bootlin.com/linux/v7.0/source/include/linux/bpf_verifier.h#L965)), which selects `__bpf_prog_enter_recur`, which uses `rcu_read_lock_dont_migrate` ([trampoline.c#L1143-L1157](https://elixir.bootlin.com/linux/v7.0/source/kernel/bpf/trampoline.c#L1143), #L1303). x86 JIT: bpf_jit_comp.c#L3002. | Per-program `prog->active` | **YES** | `recursion_misses` (#L1151) |
| **FSESSION** | Exists at v7.0 (`BPF_TRACE_FSESSION`, [uapi bpf.h#L1156](https://elixir.bootlin.com/linux/v7.0/source/include/uapi/linux/bpf.h#L1156)). It is TRACING, so it behaves as the row above. | | YES | |
| perf_event (sampling) | Perf overflow path | `bpf_prog_active` (events/core.c#L10596) | Via §1.3 | **Uncounted** |

The trampoline guard covers only the program's own execution, not the time spent inside the traced function. A blocking `vfs_read` therefore does not widen the window (INF).

### 1.3 Cross-task channel that also reaches the "immune" types

`bpf_disable_instrumentation()` is `migrate_disable(); this_cpu_inc(bpf_prog_active)`. Preemption stays on ([bpf.h#L2547](https://elixir.bootlin.com/linux/v7.0/source/include/linux/bpf.h#L2547)).

The `bpf(2)` syscall wraps these map operations with it (SRC):
- update ([syscall.c#L270](https://elixir.bootlin.com/linux/v7.0/source/kernel/bpf/syscall.c#L270))
- lookup (#L317)
- delete (#L1862)
- batch delete (#L1974)
- lookup-and-delete (#L2204)
- hashtab batch lookup ([hashtab.c#L1838](https://elixir.bootlin.com/linux/v7.0/source/kernel/bpf/hashtab.c#L1838))

The comment at hashtab.c#L41-L53 describes this design.

**INF:** a p15d task that is preempted inside one of these windows makes every kprobe, kretprobe, kprobe.multi and classic-tracepoint program fired by *another* task on that CPU get skipped. The skip is counted in `recursion_misses`.

**Answer for hot paths (INF):** the attach types that are immune to cross-task *program* nesting are:
- kprobe and kretprobe
- kprobe.multi and kprobe.session
- classic tracepoints
- raw_tp/tp_btf on the raw syscall events

These still lose events while a userspace `bpf()` map operation is preempted on the same CPU.

---

## 2. Re-verified prior conclusions at v7.0 (all SRC)

- **Signatures.** `vfs_read(struct file *, char __user *, size_t, loff_t *)` ([read_write.c#L554](https://elixir.bootlin.com/linux/v7.0/source/fs/read_write.c#L554)). `vfs_write(..., const char __user *, ...)` (#L668).
- **Functions that bypass vfs_read/vfs_write:**
  - static `vfs_readv`/`vfs_writev` (#L992/#L1030)
  - `vfs_iter_*` and `vfs_iocb_iter_*` (#L870-L985)
  - `do_sendfile` (#L1304)
  - `vfs_copy_file_range` (#L1554)
  - splice (`do_splice`, [splice.c#L1300](https://elixir.bootlin.com/linux/v7.0/source/fs/splice.c#L1300))
  - AIO ([aio.c#L1600](https://elixir.bootlin.com/linux/v7.0/source/fs/aio.c#L1600))
  - io_uring ([io_uring/rw.c#L947](https://elixir.bootlin.com/linux/v7.0/source/io_uring/rw.c#L947), #L1165)
  - `kernel_read` (#L543), `__kernel_read` (#L508), `__kernel_write(_iter)` (#L603, #L633)
- **`rw_verify_area`** ([#L453](https://elixir.bootlin.com/linux/v7.0/source/fs/read_write.c#L453)) calls `security_file_permission` (#L474).
  - **Reached by:** every path above, plus `vfs_splice_read` (splice.c#L1004) and `do_splice` (#L1341, #L1367).
  - **Not reached by** `__kernel_read`, `__kernel_write_iter` or `__kernel_write` (#L508-L540, #L603-L650), or by vmsplice and tee.
  - It is a pre-check: it sees the requested count, not the bytes moved.
- **`sock:sock_send_length` / `sock_recv_length`.**
  - `TP_PROTO(struct sock *sk, int ret, int flags)`, with fields sk, family, protocol, ret, flags ([sock.h#L267-L308](https://elixir.bootlin.com/linux/v7.0/source/include/trace/events/sock.h#L267)).
  - Fired inside `sock_sendmsg_nosec` / `sock_recvmsg_nosec` ([socket.c#L725](https://elixir.bootlin.com/linux/v7.0/source/net/socket.c#L725), #L1075). Send passes flags = 0.
  - Also reached through socket read/write (#L1170, #L1195), `splice_to_socket` (splice.c#L884), io_uring (io_uring/net.c#L682, #L977) and sendmsg/recvmsg (#L2589, #L2810).
- **`io_uring_complete`.**
  - `TP_PROTO(struct io_ring_ctx *ctx, void *req, struct io_uring_cqe *cqe)` ([io_uring.h#L321](https://elixir.bootlin.com/linux/v7.0/source/include/trace/events/io_uring.h#L321)).
  - `req` is NULL for aux CQEs (io_uring.c#L759, #L779).
  - `struct io_kiocb` has **`tctx`**, not `task` ([io_uring_types.h#L717](https://elixir.bootlin.com/linux/v7.0/source/include/linux/io_uring_types.h#L717)). Get the task as `tctx->task` (#L115). The struct also has `file` (#L696).
  - With `REQ_F_CQE_SKIP` (#L570), no CQE is filled and **no tracepoint fires** (io_uring.c#L924, #L1136).
  - **New finding:** a CQE that overflows the CQ ring (`io_get_cqe` fails) also never fires the tracepoint ([io_uring/io_uring.h#L304-L315](https://elixir.bootlin.com/linux/v7.0/source/io_uring/io_uring.h#L304); io_uring.c#L1136-L1141).
- **`btf_allowlist_d_path`** ([bpf_trace.c#L931-L945](https://elixir.bootlin.com/linux/v7.0/source/kernel/trace/bpf_trace.c#L931)):
  - `security_file_permission`, `security_inode_getattr`, `security_file_open`
  - `security_path_truncate` (needs `SECURITY_PATH`)
  - `vfs_truncate`, `vfs_fallocate`, `dentry_open`, `vfs_getattr`, `filp_close`
  - Any `iter/` program may also call it (#L949).
  - It is offered only by `tracing_prog_func_proto` (#L1695, #L1742), so kprobes and classic tracepoints cannot call it.

---

## 3. File identity

- **`i_generation` (SRC):**
  - ext4: `get_random_u32()` on allocation ([ext4/ialloc.c#L1290](https://elixir.bootlin.com/linux/v7.0/source/fs/ext4/ialloc.c#L1290)).
  - tmpfs: random ([shmem.c#L3089](https://elixir.bootlin.com/linux/v7.0/source/mm/shmem.c#L3089)).
  - xfs: random on v3 create ([xfs_icache.c#L663](https://elixir.bootlin.com/linux/v7.0/source/fs/xfs/xfs_icache.c#L663)), otherwise read from disk.
  - btrfs: `trans->transid` ([btrfs/inode.c#L6687](https://elixir.bootlin.com/linux/v7.0/source/fs/btrfs/inode.c#L6687)). A transaction id, **not unique per inode**.
  - Everything else: the VFS default of 0 ([inode.c#L256](https://elixir.bootlin.com/linux/v7.0/source/fs/inode.c#L256)). No assignment exists in `overlayfs/{inode,file,super}.c`, `pipe.c` or `socket.c`. That is an absence claim, limited to the files searched.
- **Number reuse.**
  - ext4 clears the inode bit in `ext4_free_inode` (ialloc.c#L235) when the inode is evicted. Allocation (`find_inode_bit`, #L725) can then return the same number (SRC).
  - An unlinked file that is still open keeps its inode (INF).
  - **So (s_dev, i_ino) can be reused during a capture, and (s_dev, i_ino, i_generation) separates the incarnations on ext4, xfs and tmpfs** (INF).
  - btrfs: each root allocates numbers with a monotonic `free_objectid++` ([disk-io.c#L4973](https://elixir.bootlin.com/linux/v7.0/source/fs/btrfs/disk-io.c#L4973)), re-seeded at mount (#L4951). No reuse within one mount (SRC). Reuse across remounts is INF.
- **btrfs st_dev.** `stat->dev = root->anon_dev` ([btrfs/inode.c#L8262](https://elixir.bootlin.com/linux/v7.0/source/fs/btrfs/inode.c#L8262)), not `i_sb->s_dev`, which is what the generic code uses ([stat.c#L88](https://elixir.bootlin.com/linux/v7.0/source/fs/stat.c#L88)). Subvolumes share `i_sb->s_dev` and can share `i_ino`. **The key needs the root id or `anon_dev`** (SRC).
- **Overlayfs (SRC):**
  - **User file.** `do_dentry_open` sets `f_inode = f_path.dentry->d_inode` ([open.c#L891-L895](https://elixir.bootlin.com/linux/v7.0/source/fs/open.c#L891)). So `f_inode`, `file_inode()` and `d_inode(f_path.dentry)` all return the **overlay** inode. The old fake-path model is gone: `file_dentry()` WARNs on a mismatch ([fs.h#L1355-L1369](https://elixir.bootlin.com/linux/v7.0/source/include/linux/fs.h#L1355)).
  - **Backing realfile.** `ovl_open` (overlayfs/file.c#L222) calls `backing_file_open`, which calls `vfs_open(real_path)` ([backing-file.c#L32-L52](https://elixir.bootlin.com/linux/v7.0/source/fs/backing-file.c#L32)). The realfile has `FMODE_BACKING`, `f_inode` = the real upper or lower inode, and `backing_file_user_path()` = the overlay path (file_table.c#L47-L60).
  - **Read path.** `vfs_read(ovl file)` → `backing_file_read_iter` → `vfs_iter_read(realfile)` (backing-file.c#L169), or `vfs_iocb_iter_read` (#L180).
  - **So `rw_verify_area` fires twice for one read:** once with the overlay identity, once with the real identity.
  - `d_real_inode()` ([dcache.h#L585](https://elixir.bootlin.com/linux/v7.0/source/include/linux/dcache.h#L585)) returns the real inode for an overlay dentry.
  - Overlay `i_ino` is the real ino plus xino bits, or a non-persistent counter (overlayfs/inode.c#L826-L870).
- **Pipes and sockets.** Inodes come from `new_inode_pseudo`, with `i_ino = get_next_ino()` ([pipe.c#L894](https://elixir.bootlin.com/linux/v7.0/source/fs/pipe.c#L894), [socket.c#L643](https://elixir.bootlin.com/linux/v7.0/source/net/socket.c#L643)).
  - `get_next_ino` is a **32-bit, per-CPU-batched, wrapping** counter ([inode.c#L1145](https://elixir.bootlin.com/linux/v7.0/source/fs/inode.c#L1145)) (SRC).
  - The numbers are unique until the counter wraps (INF). `i_generation` is 0.
  - `d_path` gives `pipe:[ino]` (pipe.c#L874) and `socket:[ino]` (socket.c#L374).

---

## 4. Path resolution without the allowlist

- **`bpf_path_d_path` exists** ([bpf_fs_kfuncs.c#L79](https://elixir.bootlin.com/linux/v7.0/source/fs/bpf_fs_kfuncs.c#L79)) and is not sleepable. It is registered **only for `BPF_PROG_TYPE_LSM`** (#L414) and its filter rejects other program types (#L368-L374). So it is **unusable here** (SRC).
  - The same applies to `bpf_get_task_exe_file`, `bpf_put_file`, and the xattr kfuncs (which are also `KF_SLEEPABLE`).
- **`bpf_d_path` from `iter/task_file`** is allowed (SRC). It can resolve the fds that are already open at startup (INF).
- **Manual dentry walk** from a kprobe or classic tracepoint, using `bpf_probe_read_kernel` with CO-RE (INF):
  - it cannot take `rename_lock` or `mount_lock`, so paths can be torn
  - crossing a mount needs `struct mount` via `container_of`
  - the loop must be bounded
  - it misses `d_dname` pseudo-names, the "(deleted)" suffix, and chroot or namespace roots

---

## 5. Open and close hooks

- **`security_file_open(file)`** ([security.c#L2635](https://elixir.bootlin.com/linux/v7.0/source/security/security.c#L2635)), called from `do_dentry_open` ([open.c#L926](https://elixir.bootlin.com/linux/v7.0/source/fs/open.c#L926)). SRC.
  - `f_path` and `f_inode` are already set, and the hook is on the d_path allowlist.
  - It runs **before `->open`**, so the open can still fail afterwards.
  - It **also fires for overlay realfiles**.
  - It does **not** fire for pipe, socket, memfd or anon files, which come from `alloc_file_pseudo` (file_table.c#L372; shmem.c#L5863).
  - `security_file_alloc` (file_table.c#L159) sees every file, but before its path is set.
- **`filp_close`** (open.c#L1478) is on the allowlist, but **close(2) does not call it** at v7.0. close(2) runs `file_close_fd`, then `filp_flush`, then `fput_close_sync` ([open.c#L1494-L1510](https://elixir.bootlin.com/linux/v7.0/source/fs/open.c#L1494)). SRC.
- **Last release.** `__fput` (static, [file_table.c#L443](https://elixir.bootlin.com/linux/v7.0/source/fs/file_table.c#L443)) calls `fsnotify_close` (#L455) and then **`security_file_release`** (#L463; security.c#L2397).
  - That gives one event per `struct file`.
  - It runs synchronously from close(2). Otherwise it runs from task_work, or from the `delayed_fput` kworker (#L519-L540), so the context may not be the task that closed the file (SRC).
  - Whether `__fput` itself can be hooked is OPEN.
- **fsnotify is not a universal hook.** It returns early unless the superblock has watchers ([fsnotify.h#L81](https://elixir.bootlin.com/linux/v7.0/source/include/linux/fsnotify.h#L81)). SRC.
- **7.0 renames in fs/namei.c, confirmed (SRC):**

  | Old name | v7.0 name |
  |---|---|
  | `do_filp_open` | **`do_file_open`** (#L4855) |
  | `do_unlinkat` | **`filename_unlinkat`** (#L5504) |
  | `do_renameat2` | **`filename_renameat2`** (#L6071) |
  | mkdirat, rmdir, mknodat, symlinkat, linkat | `filename_mkdirat`, `filename_rmdir`, `filename_mknodat`, `filename_symlinkat`, `filename_linkat` |

  Whether each is present in BTF on this kernel is OPEN.

---

## 6. mmap

- **`security_mmap_file(file, prot, flags)`** ([security.c#L2502](https://elixir.bootlin.com/linux/v7.0/source/security/security.c#L2502)) is called from (SRC):
  - `vm_mmap_pgoff` ([util.c#L575](https://elixir.bootlin.com/linux/v7.0/source/mm/util.c#L575))
  - `remap_file_pages` (mmap.c#L1142)
  - `shmat` (ipc/shm.c#L1644)
- It runs **before `do_mmap`**, so it does not prove the mapping succeeded. `file` is NULL for anonymous maps.
- Later permission changes go through `security_file_mprotect` (mprotect.c#L916).
- On overlay, `vm_file` is the backing realfile (backing-file.c#L325-L340).
- **No per-access hook exists** (INF). After a page is mapped, loads and stores do not enter the kernel. The only events are page-granular, with no byte counts:
  - `mm_filemap_fault` (filemap.c#L3528)
  - `mm_filemap_map_pages` (#L3942)
  - `writeback_dirty_folio`

---

## 7. Classic tracepoints for data flow

All are `TRACE_EVENT`s, so attached as classic tracepoints they run with preemption off (SRC).

| Event | Carries |
|---|---|
| `sock:sock_send_length`, `sock:sock_recv_length` | sk, family, protocol, ret, flags. The file is reachable via `sk->sk_socket->file`. |
| `io_uring:io_uring_complete` | ctx, req, user_data, res. Gaps: CQE_SKIP and overflow (§2). |
| `io_uring:io_uring_submit_req` (io_uring.h#L366) | req, user_data, opcode, flags |
| `filemap:mm_filemap_get_pages` (read path, filemap.c#L2724), `mm_filemap_fault`, `mm_filemap_map_pages` | i_ino, s_dev, page index range. No byte count. |
| `writeback:writeback_dirty_folio`, `writeback:writeback_mark_inode_dirty`, `writeback:writeback_dirty_inode*` | ino, index, flags |
| `syscalls:sys_enter_*` / `syscalls:sys_exit_*` | fd, count, ret. No struct file. **32-bit compat syscalls are ignored** ([x86 ftrace.h#L155-L159](https://elixir.bootlin.com/linux/v7.0/source/arch/x86/include/asm/ftrace.h#L155); trace_syscalls.c#L68). |
| `raw_syscalls:sys_enter` / `sys_exit` | Every syscall |

There is no `fs:`, `vfs:` or `fsnotify:` header at v7.0: those event header paths return 404. Only these names were probed.

---

## Design implications for slice B

All are INF.

1. **Byte accounting on hot paths.**
   - Use kprobe/kretprobe or kprobe.multi/kprobe.session on `vfs_read`, `vfs_write`, `vfs_readv`, `vfs_writev` and `rw_verify_area`.
   - For sockets, io_uring and syscalls, use the classic tracepoints.
   - fentry, fexit and tp_btf on these paths will reproduce the E-0089 loss.
2. **Set kretprobe `maxactive` explicitly**, because the default is 10, or use kprobe.session. Export `missed` for every link.
3. **Avoid `bpf()` map syscalls in p15d while capture is running** (§1.3).
   - Read counters from `BPF_F_MMAPABLE` arrays.
   - Move data through the ringbuf.
   - Measure `recursion_misses` around any map syscall that remains.
4. **Loss counters to export:**
   - `recursion_misses`
   - `kprobe.missed` and `kprobe_multi.missed`
   - io_uring CQ overflow
   - the number of `IOSQE_CQE_SKIP_SUCCESS` submissions, taken from `io_uring_submit_req`
   - a documented list of losses that cannot be counted: ftrace/fgraph trylock failures and perf rctx < 0
5. **File identity key.**
   - (`s_dev`, `i_ino`, `i_generation`).
   - On btrfs, add the root id or `anon_dev`.
   - On overlay, record both the overlay identity and the real identity. De-duplicate the `FMODE_BACKING` hit of `rw_verify_area`, or overlay bytes are counted twice.
   - For pipes and sockets, add a per-capture birth sequence.
6. **Path resolution, once per open.**
   - Option A: fexit on `security_file_open` with `bpf_d_path`. Exact path, but skips are possible; they are counted.
   - Option B: a kprobe with a manual dentry walk. Immune to cross-task skips, but racy.
   - In both cases, take a startup snapshot with `iter/task_file`.
   - For close, hook `security_file_release`, not `filp_close`.
7. **mmap.** Record one edge at `security_mmap_file` with prot and flags, confirmed by the return of `vm_mmap_pgoff`. MAP_PRIVATE with PROT_WRITE does not write to the file. Do not claim per-access bytes.
8. **`__kernel_read` and `__kernel_write`** skip `rw_verify_area`. They need their own hook, or must be declared out of scope.

## Gaps

1. OPEN: Ubuntu config values: `PREEMPT_DYNAMIC`, `PREEMPT_RCU`, `KRETPROBE_ON_RETHOOK`, `SECURITY_PATH`, `IA32_EMULATION`. Also whether overlay and btrfs are built as modules, which decides where their BTF lives.
2. OPEN: whether `__fput`, `vfs_readv`, `do_file_open` and the `filename_*` functions appear in BTF and in `available_filter_functions` on 7.0.0-38.
3. OPEN: the real skip rate from the §1.3 window. This needs a harness.
4. OPEN: whether the overlay identity stays stable across copy-up, and what `bpf_d_path` returns for a realfile, given that realfile mounts are private clones.
5. OPEN: which task context `io_uring_complete` runs in (submitter, io-wq worker, or task_work), and what `res` means for multishot and zero-copy requests.
6. Not covered: uprobes, AF_XDP and zero-copy sockets, NFS and FUSE identity.
