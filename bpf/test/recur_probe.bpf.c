// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * recur_probe: which hook and wake-up design keeps the kernel from skipping our programs
 * (E-0089). On 7.0 a tp_btf program runs preemptible, and the kernel's per-CPU, per-program
 * recursion guard skips the program for any other task that hits the same tracepoint on that
 * CPU meanwhile, counting only bpf_prog_info.recursion_misses. Variants, one loaded at a time:
 *   btf_*   tp_btf, as the spine is built today
 *   btfp_*  tp_btf with the body inside bpf_preempt_disable()/enable()
 *   tp_*    classic tracepoint/: the perf path runs with preemption off (include/trace/perf.h)
 * Wake-up policy (rodata wake_mode): 0 every record wakes the reader (the spine today),
 * 1 never (BPF_RB_NO_WAKEUP; the reader polls on a timer, as Falco's modern probe does),
 * 2 only when the ring holds more than adaptive_bytes (BPF_RB_FORCE_WAKEUP).
 * Each body does the spine EXEC's work: read the argv into per-CPU scratch, then output it.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define ARGV_MAX 256
enum { K_EXEC = 0, K_EXIT = 1, C_OUT_FAIL = 2, C_N = 3 };

struct rec {
	__u32 tgid, ppid, kind, argv_len;
	char argv[ARGV_MAX];
};

const volatile __u32 harness_tgid;
const volatile __u32 wake_mode;
const volatile __u64 adaptive_bytes;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 << 20);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rec);
} scratch SEC(".maps");

/* [0] our children's execs the program ran for, [1] their exits, [2] ring output failures */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, C_N);
	__type(key, __u32);
	__type(value, __u64);
} cnt SEC(".maps");

extern void bpf_preempt_disable(void) __ksym;
extern void bpf_preempt_enable(void) __ksym;

static __always_inline void inc(__u32 k)
{
	__u64 *v = bpf_map_lookup_elem(&cnt, &k);

	if (v)
		(*v)++;
}

static __always_inline __u64 flags(void)
{
	if (wake_mode == 1)
		return BPF_RB_NO_WAKEUP;
	if (wake_mode == 2)
		return bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA) > adaptive_bytes ? BPF_RB_FORCE_WAKEUP
										   : BPF_RB_NO_WAKEUP;
	return 0;
}

static __always_inline int work(__u32 kind)
{
	struct task_struct *t = bpf_get_current_task_btf();
	__u32 zero = 0, ppid = BPF_CORE_READ(t, real_parent, tgid);
	struct rec *r;

	if (ppid == harness_tgid)
		inc(kind);
	r = bpf_map_lookup_elem(&scratch, &zero);
	if (!r)
		return 0;
	r->tgid = t->tgid;
	r->ppid = ppid;
	r->kind = kind;
	r->argv_len = 0;
	if (kind == K_EXEC) {
		unsigned long a = BPF_CORE_READ(t, mm, arg_start), e = BPF_CORE_READ(t, mm, arg_end);
		__u32 n = e > a ? (__u32)(e - a) : 0;

		if (n > ARGV_MAX)
			n = ARGV_MAX;
		if (n && !bpf_probe_read_user(r->argv, n & (ARGV_MAX - 1), (void *)a))
			r->argv_len = n;
	}
	if (bpf_ringbuf_output(&rb, r, sizeof(*r), flags()))
		inc(C_OUT_FAIL);
	return 0;
}

static __always_inline int work_np(__u32 kind)
{
	int ret;

	bpf_preempt_disable();
	ret = work(kind);
	bpf_preempt_enable();
	return ret;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(btf_exec, struct task_struct *p) { return work(K_EXEC); }
SEC("tp_btf/sched_process_exit")
int BPF_PROG(btf_exit, struct task_struct *p) { return work(K_EXIT); }

SEC("tp_btf/sched_process_exec")
int BPF_PROG(btfp_exec, struct task_struct *p) { return work_np(K_EXEC); }
SEC("tp_btf/sched_process_exit")
int BPF_PROG(btfp_exit, struct task_struct *p) { return work_np(K_EXIT); }

SEC("tracepoint/sched/sched_process_exec")
int tp_exec(void *ctx) { return work(K_EXEC); }
SEC("tracepoint/sched/sched_process_exit")
int tp_exit(void *ctx) { return work(K_EXIT); }

char LICENSE[] SEC("license") = "Dual BSD/GPL";
