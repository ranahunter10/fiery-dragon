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

#define EXEC_TAIL (P15_EXEC_MAX_SIZE - (int)sizeof(struct p15_exec))

SEC("tp_btf/sched_process_exec")
int BPF_PROG(spine_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct p15_exec *r;
	__u8 *tail;
	const char *filename;
	struct mm_struct *mm;
	__u64 a0, a1, full;
	__u32 fn_len = 0, av_len = 0, end;
	__u16 flags = 0;
	long n;

	count(P15_T_EXEC, P15_CK_SEEN);
	r = bpf_ringbuf_reserve(&spine_rb, P15_EXEC_MAX_SIZE, 0);
	if (!r) {
		count(P15_T_EXEC, P15_CK_RESERVE_FAILED);
		return 0;
	}
	tail = (__u8 *)(r + 1);

	r->exe_ino = BPF_CORE_READ(bprm, file, f_inode, i_ino);
	r->exe_dev = BPF_CORE_READ(bprm, file, f_inode, i_sb, s_dev);
	r->exe_gen = BPF_CORE_READ(bprm, file, f_inode, i_generation);
	r->old_tid = old_pid;

	/* filename: the name as passed (bprm->filename); NUL not stored. */
	filename = BPF_CORE_READ(bprm, filename);
	n = bpf_probe_read_kernel_str(tail, P15_EXEC_FILENAME_MAX, filename);
	if (n <= 0) {
		flags |= P15_F_READ_FAILED;
		count(P15_T_EXEC, P15_CK_READ_FAILED);
		r->filename_full = P15_LEN_UNKNOWN;
	} else {
		fn_len = n - 1;
		if (n == P15_EXEC_FILENAME_MAX) {
			/* filled the buffer: possibly cut (a name of exactly MAX-1 bytes is flagged too) */
			flags |= P15_F_TRUNCATED;
			count(P15_T_EXEC, P15_CK_TRUNCATED);
			r->filename_full = P15_LEN_UNKNOWN;
		} else {
			r->filename_full = fn_len;
		}
	}
	if (fn_len > P15_EXEC_FILENAME_MAX - 1)
		fn_len = P15_EXEC_FILENAME_MAX - 1;

	/* argv: the kernel's copy on the new stack, mm->arg_start..arg_end (E-0049). */
	mm = BPF_CORE_READ(p, mm);
	a0 = BPF_CORE_READ(mm, arg_start);
	a1 = BPF_CORE_READ(mm, arg_end);
	full = a1 > a0 ? a1 - a0 : 0;
	r->argv_full = full > 0xFFFFFFFEull ? P15_LEN_UNKNOWN : (__u32)full;
	av_len = full > P15_EXEC_ARGV_MAX ? P15_EXEC_ARGV_MAX : (__u32)full;
	if (full > P15_EXEC_ARGV_MAX) {
		flags |= P15_F_TRUNCATED;
		count(P15_T_EXEC, P15_CK_TRUNCATED);
	}
	av_len &= 2 * P15_EXEC_ARGV_MAX - 1; /* for the verifier: av_len <= ARGV_MAX already */
	if (av_len > P15_EXEC_ARGV_MAX)
		av_len = P15_EXEC_ARGV_MAX;
	if (av_len && bpf_probe_read_user(tail + fn_len, av_len, (const void *)a0)) {
		flags |= P15_F_READ_FAILED;
		count(P15_T_EXEC, P15_CK_READ_FAILED);
		av_len = 0;
	}
	r->filename_len = fn_len;
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
	fill_hdr(&r->h, P15_T_EXEC, P15_EXEC_VERSION, (sizeof(*r) + end + 7) & ~7u, flags, p);
	bpf_ringbuf_submit(r, 0);
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
