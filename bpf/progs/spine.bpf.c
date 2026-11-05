// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * spine.bpf.c: the process spine (ADR-0003). One tp_btf program per
 * lifecycle event, each emitting one record (schema/records.toml) into the
 * spine ring buffer (ADR-0006), with the identity fields of ADR-0009.
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

/* The DYNPTR way's kfuncs, bpf_probe_read_user_dynptr and bpf_dynptr_memset, are declared by
 * vmlinux.h: bpftool emits them from the target's BTF (vmlinux-7.0.0-38.h). */

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

static __always_inline void count(__u32 type, __u32 kind)
{
	__u32 k = P15_CTR_INDEX(type, kind);
	__u64 *v = bpf_map_lookup_elem(&spine_counters, &k);

	if (v)
		*v += 1; /* per-CPU slot: no atomics needed */
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
	bpf_ringbuf_submit(r, 0);
	count(P15_T_FORK, P15_CK_EMITTED);
	return 0;
}

/*
 * EXEC records are variable-length. ADR-0017 layer 1: each takes only its own len in the
 * ring. The way is chosen at build time, so the cost harness (bench/rb_cost) measures this
 * code itself, not a copy of it:
 *   FIXED   reserve the maximum and fill it in place (the first build; the harness's baseline);
 *   OUTPUT  fill a per-CPU scratch record, then bpf_ringbuf_output() exactly len bytes;
 *   DYNPTR  fill the fixed part and the filename in scratch, bpf_ringbuf_reserve_dynptr() of
 *           exactly len, copy them in, and read argv straight into the ring.
 */
#define P15_EXEC_WAY_FIXED 0
#define P15_EXEC_WAY_OUTPUT 1
#define P15_EXEC_WAY_DYNPTR 2
#ifndef P15_EXEC_WAY
#define P15_EXEC_WAY P15_EXEC_WAY_OUTPUT
#endif

#define EXEC_TAIL (P15_EXEC_MAX_SIZE - (int)sizeof(struct p15_exec))

/* the record is built here when it is not built in the ring (OUTPUT, DYNPTR) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[P15_EXEC_MAX_SIZE]);
} exec_scratch SEC(".maps");

/* Exe identity, old tid and the filename (into tail). Returns the filename bytes copied. */
static __always_inline __u32 exec_head(struct p15_exec *r, __u8 *tail, pid_t old_pid, struct linux_binprm *bprm,
				       __u16 *flags)
{
	const char *filename;
	__u32 fn_len = 0;
	long n;

	r->exe_ino = BPF_CORE_READ(bprm, file, f_inode, i_ino);
	r->exe_dev = BPF_CORE_READ(bprm, file, f_inode, i_sb, s_dev);
	r->exe_gen = BPF_CORE_READ(bprm, file, f_inode, i_generation);
	r->old_tid = old_pid;

	/* filename: the name as passed (bprm->filename); NUL not stored. */
	filename = BPF_CORE_READ(bprm, filename);
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
 * The bound is for the verifier only: (64 + 255 + 1024 + 7) & ~7 == 1344, so it never cuts. */
static __always_inline __u32 exec_len(__u32 end)
{
	__u32 len = ((__u32)sizeof(struct p15_exec) + end + 7) & ~7u;

	return len > P15_EXEC_MAX_SIZE ? P15_EXEC_MAX_SIZE : len;
}

#if P15_EXEC_WAY != P15_EXEC_WAY_DYNPTR
/* Fill a whole EXEC record at r: P15_EXEC_MAX_SIZE bytes of ring or scratch memory. Returns its len. */
static __always_inline __u32 exec_fill(struct p15_exec *r, struct task_struct *p, pid_t old_pid,
				       struct linux_binprm *bprm)
{
	__u8 *tail = (__u8 *)(r + 1);
	__u16 flags = 0;
	__u64 a0;
	__u32 fn_len = exec_head(r, tail, old_pid, bprm, &flags);
	__u32 av_len = exec_argv_span(r, p, &a0, &flags), end, len;

	if (av_len && bpf_probe_read_user(tail + fn_len, av_len, (const void *)a0)) {
		flags |= P15_F_READ_FAILED;
		count(P15_T_EXEC, P15_CK_READ_FAILED);
		av_len = 0;
	}
	r->argv_len = av_len;

	/* zero the bytes between the data and the 8-byte end of the record */
	end = fn_len + av_len;
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
#endif

SEC("tp_btf/sched_process_exec")
int BPF_PROG(spine_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct p15_exec *r;
#if P15_EXEC_WAY != P15_EXEC_WAY_FIXED
	__u32 zero = 0;
#endif

	count(P15_T_EXEC, P15_CK_SEEN);
#if P15_EXEC_WAY == P15_EXEC_WAY_FIXED
	r = bpf_ringbuf_reserve(&spine_rb, P15_EXEC_MAX_SIZE, 0);
	if (!r) {
		count(P15_T_EXEC, P15_CK_RESERVE_FAILED);
		return 0;
	}
	exec_fill(r, p, old_pid, bprm);
	bpf_ringbuf_submit(r, 0);
#elif P15_EXEC_WAY == P15_EXEC_WAY_OUTPUT
	__u32 len;

	r = bpf_map_lookup_elem(&exec_scratch, &zero);
	if (!r) {
		count(P15_T_EXEC, P15_CK_BUILD_FAILED);
		return 0;
	}
	len = exec_fill(r, p, old_pid, bprm);
	if (bpf_ringbuf_output(&spine_rb, r, len, 0)) {
		count(P15_T_EXEC, P15_CK_RESERVE_FAILED);
		return 0;
	}
#else /* DYNPTR */
	struct bpf_dynptr d;
	__u16 flags = 0;
	__u64 a0;
	__u32 fn_len, av_len, head, end, len;

	r = bpf_map_lookup_elem(&exec_scratch, &zero);
	if (!r) {
		count(P15_T_EXEC, P15_CK_BUILD_FAILED);
		return 0;
	}
	fn_len = exec_head(r, (__u8 *)(r + 1), old_pid, bprm, &flags);
	av_len = exec_argv_span(r, p, &a0, &flags);
	len = exec_len(fn_len + av_len);
	if (bpf_ringbuf_reserve_dynptr(&spine_rb, len, 0, &d)) {
		bpf_ringbuf_discard_dynptr(&d, 0);
		count(P15_T_EXEC, P15_CK_RESERVE_FAILED);
		return 0;
	}
	head = sizeof(*r) + fn_len;
	if (av_len && bpf_probe_read_user_dynptr(&d, head, av_len, (const void *)a0)) {
		flags |= P15_F_READ_FAILED;
		count(P15_T_EXEC, P15_CK_READ_FAILED);
		av_len = 0;
	}
	r->argv_len = av_len;
	fill_hdr(&r->h, P15_T_EXEC, P15_EXEC_VERSION, len, flags, p);
	end = head + av_len;
	/* ring memory is not zeroed: the padding, and argv's bytes after a failed read, are cleared */
	if ((end < len && bpf_dynptr_memset(&d, end, len - end, 0)) ||
	    bpf_dynptr_write(&d, 0, r, head, 0)) {
		bpf_ringbuf_discard_dynptr(&d, 0);
		count(P15_T_EXEC, P15_CK_BUILD_FAILED);
		return 0;
	}
	bpf_ringbuf_submit_dynptr(&d, 0);
#endif
	count(P15_T_EXEC, P15_CK_EMITTED);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(spine_exit, struct task_struct *p, bool group_dead)
{
	struct p15_exit *r;

	count(P15_T_EXIT, P15_CK_SEEN);
	r = bpf_ringbuf_reserve(&spine_rb, sizeof(*r), 0);
	if (!r) {
		count(P15_T_EXIT, P15_CK_RESERVE_FAILED);
		return 0;
	}
	fill_hdr(&r->h, P15_T_EXIT, P15_EXIT_VERSION, sizeof(*r), 0, p);
	r->exit_code = BPF_CORE_READ(p, exit_code);
	r->group_dead = group_dead ? 1 : 0;
	bpf_ringbuf_submit(r, 0);
	count(P15_T_EXIT, P15_CK_EMITTED);
	return 0;
}

SEC("tp_btf/task_rename")
int BPF_PROG(spine_rename, struct task_struct *task, const char *comm)
{
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
	/* at this tracepoint task->comm is still the old name (fs/exec.c __set_task_comm, v7.0) */
	if (bpf_probe_read_kernel_str(r->old_comm, sizeof(r->old_comm), task->comm) < 0 ||
	    bpf_probe_read_kernel_str(r->new_comm, sizeof(r->new_comm), comm) < 0) {
		flags |= P15_F_READ_FAILED;
		count(P15_T_RENAME, P15_CK_READ_FAILED);
	}
	fill_hdr(&r->h, P15_T_RENAME, P15_RENAME_VERSION, sizeof(*r), flags, task);
	bpf_ringbuf_submit(r, 0);
	count(P15_T_RENAME, P15_CK_EMITTED);
	return 0;
}
