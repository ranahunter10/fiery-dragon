// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * rb_size: how much ring space a variable-length record takes, three ways
 * (flood-resilience ADR input). On every exec, each program emits one record
 * of len = 64 + the exec's argv bytes (<= 1024), rounded up to 8:
 *   fixed:  bpf_ringbuf_reserve() of the maximum (1344), the spine's current way
 *   output: build in a per-CPU scratch, then bpf_ringbuf_output() of exactly len
 *   dynptr: bpf_ringbuf_reserve_dynptr() of exactly len, then bpf_dynptr_write()
 * The loader compares the size each record occupies in its ring.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAXREC 1344
#define ARGV_MAX 1024

struct rec { __u32 mode, len, tgid, pad; };

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } rb_fixed SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } rb_output SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } rb_dynptr SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u8[MAXREC]); } scratch SEC(".maps");
/* 0..2: emitted per mode; 3..5: failed per mode */
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 6); __type(key, __u32); __type(value, __u64); } ctr SEC(".maps");

static void bump(__u32 k)
{
	__u64 *v = bpf_map_lookup_elem(&ctr, &k);

	if (v)
		(*v)++;
}

static __u32 rec_len(struct task_struct *p)
{
	struct mm_struct *mm = BPF_CORE_READ(p, mm);
	__u64 n = BPF_CORE_READ(mm, arg_end) - BPF_CORE_READ(mm, arg_start);

	if (n > ARGV_MAX)
		n = ARGV_MAX;
	return (64 + (__u32)n + 7) & ~7u;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(fixed, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct rec *r = bpf_ringbuf_reserve(&rb_fixed, MAXREC, 0);

	if (!r) {
		bump(3);
		return 0;
	}
	r->mode = 0;
	r->len = rec_len(p);
	r->tgid = bpf_get_current_pid_tgid() >> 32;
	bpf_ringbuf_submit(r, 0);
	bump(0);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(output, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	__u32 zero = 0, len = rec_len(p);
	struct rec *r = bpf_map_lookup_elem(&scratch, &zero);

	if (!r)
		return 0;
	r->mode = 1;
	r->len = len;
	r->tgid = bpf_get_current_pid_tgid() >> 32;
	if (len > MAXREC)
		len = MAXREC;
	if (len < sizeof(*r))
		len = sizeof(*r);
	if (bpf_ringbuf_output(&rb_output, r, len, 0)) {
		bump(4);
		return 0;
	}
	bump(1);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(dynptr, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct bpf_dynptr d;
	struct rec r = { .mode = 2 };
	__u32 len = rec_len(p);

	r.len = len;
	r.tgid = bpf_get_current_pid_tgid() >> 32;
	if (len > MAXREC)
		len = MAXREC;
	if (bpf_ringbuf_reserve_dynptr(&rb_dynptr, len, 0, &d)) {
		bpf_ringbuf_discard_dynptr(&d, 0);
		bump(5);
		return 0;
	}
	bpf_dynptr_write(&d, 0, &r, sizeof(r), 0);
	bpf_ringbuf_submit_dynptr(&d, 0);
	bump(2);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
