// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * spine.bpf.c: the process spine (ADR-0003, ADR-0020). One program per lifecycle event, each
 * emitting one record (schema/records.toml) into the spine ring buffer (ADR-0006), with the
 * identity fields of ADR-0009. Hook types (ADR-0020 rule 1): fork on tp_btf (it needs the child's
 * task); exec, exit and rename on classic tracepoints, which the kernel runs with preemption off,
 * so its per-CPU recursion guard can't skip them for other tasks. Records wake the reader only
 * above a high-water mark (ADR-0020 rule 2); whatever the kernel still skips is read by p15d
 * from recursion_misses (rule 3).
 *
 * Rules kept here:
 *  - every record byte is written (ring memory is not zeroed);
 *  - every early return is counted (bpf/include/p15_counters.h);
 *  - variable-length fields are bounded copies; truncation and failed
 *    reads are flagged in the record and counted.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "p15_records.h"
#include "p15_counters.h"
#include "p15_kernel.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Spine ring: 4 MiB by default (ADR-0006); the loader may resize it before load. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 << 20);
} spine_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, P15_CTR_MAX);
	__type(key, __u32);
	__type(value, __u64);
} spine_counters SEC(".maps");

/* The ring's high-water mark (ADR-0020 rule 2): the loader sets a quarter of the ring's size.
 * Below it a record doesn't wake the reader, which polls every 10 ms; above it, it does. */
const volatile __u64 spine_wake_bytes = 1 << 20;

static __always_inline __u64 wake(void)
{
	return bpf_ringbuf_query(&spine_rb, BPF_RB_AVAIL_DATA) > spine_wake_bytes ? BPF_RB_FORCE_WAKEUP
										    : BPF_RB_NO_WAKEUP;
}

static __always_inline void count(__u32 type, __u32 kind)
{
	__u32 k = P15_CTR_INDEX(type, kind);
	__u64 *v = bpf_map_lookup_elem(&spine_counters, &k);

	/* Atomic, though the slot is per-CPU: on 7.0 a tp_btf or fentry/fexit program runs with
	 * preemption on (rcu_read_lock_dont_migrate, kernel/bpf/trampoline.c), and the kernel's
	 * recursion guard is per program, so two programs that share a slot can interleave on one
	 * CPU. A plain `*v += 1` is a load, an add and a store: the preempted one would overwrite
	 * the other's count, and the books would no longer close (E-0097). Today each spine slot has
	 * one writer, but nothing enforces that; the atomic add makes it not matter. */
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline void fill_hdr(struct p15_hdr *h, __u16 type, __u16 version, __u16 len, __u16 flags,
				     struct task_struct *t)
{
	h->type = type;
	h->version = version;
	h->len = len;
	h->flags = flags;
	h->ts_ns = bpf_ktime_get_boot_ns();
	h->tgid = BPF_CORE_READ(t, tgid);
	h->tid = BPF_CORE_READ(t, pid);
	h->start_ns = BPF_CORE_READ(t, group_leader, start_boottime);
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(spine_fork, struct task_struct *parent, struct task_struct *child)
{
	struct p15_fork *r;

	count(P15_T_FORK, P15_CK_SEEN);
	r = bpf_ringbuf_reserve(&spine_rb, sizeof(*r), 0);
	if (!r) {
		count(P15_T_FORK, P15_CK_RESERVE_FAILED);
		return 0;
	}
	fill_hdr(&r->h, P15_T_FORK, P15_FORK_VERSION, sizeof(*r), 0, parent);
	r->child_start_ns = BPF_CORE_READ(child, group_leader, start_boottime);
	r->child_task_start_ns = BPF_CORE_READ(child, start_boottime);
	r->child_tgid = BPF_CORE_READ(child, tgid);
	r->child_tid = BPF_CORE_READ(child, pid);
	r->kind = r->child_tgid == r->h.tgid ? 2 : 1;
	__builtin_memset(r->_pad, 0, sizeof(r->_pad));
	bpf_ringbuf_submit(r, wake());
	count(P15_T_FORK, P15_CK_EMITTED);
	return 0;
}

/*
 * EXEC records are variable-length. ADR-0017 layer 1: each takes only its own len in the ring.
 * They are filled in a per-CPU scratch record and copied to the ring with bpf_ringbuf_output()
 * of exactly len bytes (decision 4). The two other ways (FIXED, DYNPTR) were measured in the dev
 * container only (E-0076) and are removed with EXEC v2; the VM repeat of that bench, run from
 * main where bench/rb_cost still is, is ADR-0025 rule 8's condition for merging.
 */
#define EXEC_TAIL (P15_EXEC_MAX_SIZE - (int)sizeof(struct p15_exec))

/* the record is built here, then copied to the ring */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[P15_EXEC_MAX_SIZE]);
} exec_scratch SEC(".maps");

#define P15_S_IFMT   0170000
#define P15_S_IFSOCK 0140000

/* One standard-stream descriptor's identity into (*ino, *dev, *rdev, *mode), from current's
 * file table (ADR-0025 rule 5). fd is a small constant (0, 1, 2). A closed or absent descriptor
 * leaves all four zero. The inode is the backing object's: for a pipe it is the pipe inode, so
 * fd 0 of a reader and fd 1 of its writer share it; the file type is in the mode bits. (No socket
 * cookie: bpf_get_socket_cookie is barred in a classic tracepoint, and 7.0 has no stable
 * sk_cookie field, so a socket-to-NET join waits for a helper-capable hook.) */
static __always_inline void fd_identity(struct file **fdarr, __u32 max_fds, __u32 fd, __u64 *ino, __u32 *dev,
					__u32 *rdev, __u32 *mode)
{
	struct file *f = NULL;
	struct inode *ino_p;

	*ino = 0; *dev = 0; *rdev = 0; *mode = 0;
	if (fd >= max_fds || !fdarr)
		return;
	bpf_probe_read_kernel(&f, sizeof(f), &fdarr[fd]);
	if (!f)
		return;
	ino_p = BPF_CORE_READ(f, f_inode);
	*ino = BPF_CORE_READ(ino_p, i_ino);
	*dev = BPF_CORE_READ(ino_p, i_sb, s_dev);
	*rdev = BPF_CORE_READ(ino_p, i_rdev);
	*mode = BPF_CORE_READ(ino_p, i_mode);
}

/* Code provenance (ADR-0025): the executable's own facts, the committed credentials,
 * self_exec_id and the identity of fds 0/1/2. All CO-RE reads of current's own objects. */
static __always_inline void exec_provenance(struct p15_exec *r, struct task_struct *p)
{
	struct inode *ei = BPF_CORE_READ(p, mm, exe_file, f_inode);
	const struct cred *c = BPF_CORE_READ(p, cred);
	struct file **fdarr = BPF_CORE_READ(p, files, fdt, fd);
	__u32 max_fds = BPF_CORE_READ(p, files, fdt, max_fds);

	r->exe_nlink = BPF_CORE_READ(ei, __i_nlink);
	r->exe_fs_magic = (__u32)BPF_CORE_READ(ei, i_sb, s_magic);
	r->exe_mode = BPF_CORE_READ(ei, i_mode);
	r->exe_uid = BPF_CORE_READ(ei, i_uid.val);
	r->exe_gid = BPF_CORE_READ(ei, i_gid.val);
	r->exe_ctime_ns = (__u64)BPF_CORE_READ(ei, i_ctime_sec) * 1000000000ull + (BPF_CORE_READ(ei, i_ctime_nsec) & P15_CTIME_NSEC_MASK);
	r->exe_mtime_ns = (__u64)BPF_CORE_READ(ei, i_mtime_sec) * 1000000000ull + BPF_CORE_READ(ei, i_mtime_nsec);
	r->self_exec_id = BPF_CORE_READ(p, self_exec_id);
	r->uid = BPF_CORE_READ(c, uid.val);
	r->euid = BPF_CORE_READ(c, euid.val);
	r->gid = BPF_CORE_READ(c, gid.val);
	r->egid = BPF_CORE_READ(c, egid.val);
	r->fsuid = BPF_CORE_READ(c, fsuid.val);
	r->fsgid = BPF_CORE_READ(c, fsgid.val);
	fd_identity(fdarr, max_fds, 0, &r->stdin_ino, &r->stdin_dev, &r->stdin_rdev, &r->stdin_mode);
	fd_identity(fdarr, max_fds, 1, &r->stdout_ino, &r->stdout_dev, &r->stdout_rdev, &r->stdout_mode);
	fd_identity(fdarr, max_fds, 2, &r->stderr_ino, &r->stderr_dev, &r->stderr_rdev, &r->stderr_mode);
}

/* Exe identity, old tid and the filename (into tail). Returns the filename bytes copied.
 * The exec'd file is current->mm->exe_file: begin_new_exec set it to bprm->file before the
 * tracepoint (fs/exec.c, v7.0; ADR-0020 rule 1). The filename is the tracepoint's own copy of
 * bprm->filename (its __data_loc field). exe_name (the dentry basename) goes into the tail at
 * exe_off (after filename and argv, the schema's last var field). */
static __always_inline __u32 exec_head(struct p15_exec *r, __u8 *tail, pid_t old_pid, const char *filename,
				       struct task_struct *p, __u16 *flags)
{
	struct file *exe = BPF_CORE_READ(p, mm, exe_file);
	__u32 fn_len = 0;
	long n;

	r->exe_ino = BPF_CORE_READ(exe, f_inode, i_ino);
	r->exe_dev = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);
	r->exe_gen = BPF_CORE_READ(exe, f_inode, i_generation);
	r->old_tid = old_pid;
	exec_provenance(r, p);

	/* filename: the name as passed (bprm->filename); NUL not stored. */
	n = bpf_probe_read_kernel_str(tail, P15_EXEC_FILENAME_MAX, filename);
	if (n <= 0) {
		*flags |= P15_F_READ_FAILED;
		count(P15_T_EXEC, P15_CK_READ_FAILED);
		r->filename_full = P15_LEN_UNKNOWN;
	} else {
		fn_len = n - 1;
		if (n == P15_EXEC_FILENAME_MAX) {
			/* filled the buffer: possibly cut (a name of exactly MAX-1 bytes is flagged too) */
			*flags |= P15_F_TRUNCATED;
			count(P15_T_EXEC, P15_CK_TRUNCATED);
			r->filename_full = P15_LEN_UNKNOWN;
		} else {
			r->filename_full = fn_len;
		}
	}
	if (fn_len > P15_EXEC_FILENAME_MAX - 1)
		fn_len = P15_EXEC_FILENAME_MAX - 1;
	r->filename_len = fn_len;
	return fn_len;
}

/* argv: the kernel's copy on the new stack, mm->arg_start..arg_end (E-0049). Sets argv_full and
 * *a0; returns the bytes to copy, at most P15_EXEC_ARGV_MAX (a cut is flagged and counted). */
static __always_inline __u32 exec_argv_span(struct p15_exec *r, struct task_struct *p, __u64 *a0, __u16 *flags)
{
	struct mm_struct *mm = BPF_CORE_READ(p, mm);
	__u64 a1, full;
	__u32 av_len;

	*a0 = BPF_CORE_READ(mm, arg_start);
	a1 = BPF_CORE_READ(mm, arg_end);
	full = a1 > *a0 ? a1 - *a0 : 0;
	r->argv_full = full > 0xFFFFFFFEull ? P15_LEN_UNKNOWN : (__u32)full;
	av_len = full > P15_EXEC_ARGV_MAX ? P15_EXEC_ARGV_MAX : (__u32)full;
	if (full > P15_EXEC_ARGV_MAX) {
		*flags |= P15_F_TRUNCATED;
		count(P15_T_EXEC, P15_CK_TRUNCATED);
	}
	av_len &= 2 * P15_EXEC_ARGV_MAX - 1; /* for the verifier: av_len <= ARGV_MAX already */
	if (av_len > P15_EXEC_ARGV_MAX)
		av_len = P15_EXEC_ARGV_MAX;
	return av_len;
}

/* The record's len for `end` bytes of variable fields: padded to 8, at most P15_EXEC_MAX_SIZE.
 * The bound is for the verifier only: (200 + 255 + 1023 + 63 + 7) & ~7 == 1544, so it never cuts. */
static __always_inline __u32 exec_len(__u32 end)
{
	__u32 len = ((__u32)sizeof(struct p15_exec) + end + 7) & ~7u;

	return len > P15_EXEC_MAX_SIZE ? P15_EXEC_MAX_SIZE : len;
}

/* exe_name: the executable's dentry basename, into the tail at `at`. Sets exe_name_len/full,
 * flags truncation. Returns the bytes written (no NUL). */
static __always_inline __u32 exec_name(struct p15_exec *r, __u8 *tail, __u32 at, struct task_struct *p, __u16 *flags)
{
	const unsigned char *nm = BPF_CORE_READ(p, mm, exe_file, f_path.dentry, d_name.name);
	__u32 en = 0;
	long n;

	at &= 2 * P15_EXEC_ARGV_MAX - 1;                 /* for the verifier: at <= fn+av < tail size */
	if (at > EXEC_TAIL - P15_EXEC_EXE_NAME_MAX)
		at = EXEC_TAIL - P15_EXEC_EXE_NAME_MAX;      /* cannot happen (fn+av leave room); bound anyway */
	n = bpf_probe_read_kernel_str(tail + at, P15_EXEC_EXE_NAME_MAX, nm);
	if (n <= 0) {
		*flags |= P15_F_READ_FAILED;
		count(P15_T_EXEC, P15_CK_READ_FAILED);
		r->exe_name_full = P15_LEN_UNKNOWN;
	} else {
		en = n - 1;
		if (n == P15_EXEC_EXE_NAME_MAX) {
			*flags |= P15_F_TRUNCATED;
			count(P15_T_EXEC, P15_CK_TRUNCATED);
			r->exe_name_full = P15_LEN_UNKNOWN;
		} else {
			r->exe_name_full = en;
		}
	}
	if (en > P15_EXEC_EXE_NAME_MAX - 1)
		en = P15_EXEC_EXE_NAME_MAX - 1;
	r->exe_name_len = en;
	return en;
}

/* Fill a whole EXEC record at r (per-CPU scratch), tail packed filename, argv, exe_name in the
 * schema's var order. Returns its len. The record is then copied to the ring by bpf_ringbuf_output
 * (ADR-0017 layer 1, decision 4: the one build way; E-0076). */
static __always_inline __u32 exec_fill(struct p15_exec *r, struct task_struct *p, pid_t old_pid,
				       const char *filename)
{
	__u8 *tail = (__u8 *)(r + 1);
	__u16 flags = 0;
	__u64 a0;
	__u32 fn_len = exec_head(r, tail, old_pid, filename, p, &flags);
	__u32 av_len = exec_argv_span(r, p, &a0, &flags), en_len, end, len;

	if (av_len && bpf_probe_read_user(tail + fn_len, av_len, (const void *)a0)) {
		flags |= P15_F_READ_FAILED;
		count(P15_T_EXEC, P15_CK_READ_FAILED);
		av_len = 0;
	}
	r->argv_len = av_len;
	en_len = exec_name(r, tail, fn_len + av_len, p, &flags);

	/* zero the bytes between the data and the 8-byte end of the record */
	end = fn_len + av_len + en_len;
	for (int i = 0; i < 8; i++) {
		__u32 o = end + i;

		if (o < EXEC_TAIL && ((sizeof(*r) + o) & 7))
			tail[o & (2 * P15_EXEC_ARGV_MAX - 1)] = 0;
		else
			break;
	}
	len = exec_len(end);
	fill_hdr(&r->h, P15_T_EXEC, P15_EXEC_VERSION, len, flags, p);
	return len;
}

SEC("tracepoint/sched/sched_process_exec")
int spine_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *p = bpf_get_current_task_btf();
	const char *filename = (const char *)ctx + (ctx->__data_loc_filename & 0xFFFF);
	pid_t old_pid = ctx->old_pid;
	struct p15_exec *r;
	__u32 zero = 0, len;

	count(P15_T_EXEC, P15_CK_SEEN);
	r = bpf_map_lookup_elem(&exec_scratch, &zero);
	if (!r) {
		count(P15_T_EXEC, P15_CK_BUILD_FAILED);
		return 0;
	}
	len = exec_fill(r, p, old_pid, filename);
	if (bpf_ringbuf_output(&spine_rb, r, len, wake())) {
		count(P15_T_EXEC, P15_CK_RESERVE_FAILED);
		return 0;
	}
	count(P15_T_EXEC, P15_CK_EMITTED);
	return 0;
}


SEC("tracepoint/sched/sched_process_exit")
int spine_exit(struct trace_event_raw_sched_process_exit *ctx)
{
	struct task_struct *p = bpf_get_current_task_btf();  /* do_exit: the exiting task is current */
	struct p15_exit *r;

	count(P15_T_EXIT, P15_CK_SEEN);
	r = bpf_ringbuf_reserve(&spine_rb, sizeof(*r), 0);
	if (!r) {
		count(P15_T_EXIT, P15_CK_RESERVE_FAILED);
		return 0;
	}
	fill_hdr(&r->h, P15_T_EXIT, P15_EXIT_VERSION, sizeof(*r), 0, p);
	r->exit_code = BPF_CORE_READ(p, exit_code);
	r->group_dead = ctx->group_dead ? 1 : 0;
	bpf_ringbuf_submit(r, wake());
	count(P15_T_EXIT, P15_CK_EMITTED);
	return 0;
}

SEC("tracepoint/task/task_rename")
int spine_rename(struct trace_event_raw_task_rename *ctx)
{
	/* the renamed task is current, or a thread of current's group (fs/proc/base.c comm_write
	 * allows only the same thread group, v7.0): the process key is current's, the tid the event's */
	struct task_struct *task = bpf_get_current_task_btf();
	struct p15_rename *r;
	__u16 flags = 0;

	count(P15_T_RENAME, P15_CK_SEEN);
	r = bpf_ringbuf_reserve(&spine_rb, sizeof(*r), 0);
	if (!r) {
		count(P15_T_RENAME, P15_CK_RESERVE_FAILED);
		return 0;
	}
	__builtin_memset(r->old_comm, 0, sizeof(r->old_comm));
	__builtin_memset(r->new_comm, 0, sizeof(r->new_comm));
	/* the event's own copies of the old and the new comm */
	if (bpf_probe_read_kernel_str(r->old_comm, sizeof(r->old_comm), ctx->oldcomm) < 0 ||
	    bpf_probe_read_kernel_str(r->new_comm, sizeof(r->new_comm), ctx->newcomm) < 0) {
		flags |= P15_F_READ_FAILED;
		count(P15_T_RENAME, P15_CK_READ_FAILED);
	}
	fill_hdr(&r->h, P15_T_RENAME, P15_RENAME_VERSION, sizeof(*r), flags, task);
	r->h.tid = (__u32)ctx->pid;
	bpf_ringbuf_submit(r, wake());
	count(P15_T_RENAME, P15_CK_EMITTED);
	return 0;
}
