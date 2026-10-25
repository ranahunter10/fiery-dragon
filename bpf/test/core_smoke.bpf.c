// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * core_smoke.bpf.c: build-scaffolding smoke test (Phase 1, step 1).
 *
 * Proves, end to end, the pieces every spine program will use:
 *  - kernel types from bpf/vmlinux/vmlinux.h (ADR-0002);
 *  - a CO-RE read of task->group_leader->start_boottime and task->tgid,
 *    the process identity of ADR-0009;
 *  - tp_btf/sched_process_exec (ADR-0003);
 *  - a BPF ring buffer with a counted reserve failure (ADR-0006).
 * It is not the spine: no record format, no argv. Replaced in step 3.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct smoke_event {
	__u64 start_ns;   /* group_leader->start_boottime */
	__u32 tgid;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} smoke_rb SEC(".maps");

__u64 smoke_seen = 0;             /* every exec the program saw */
__u64 smoke_reserve_failed = 0;   /* execs not emitted because the ring was full */

SEC("tp_btf/sched_process_exec")
int BPF_PROG(smoke_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct smoke_event *e;

	__sync_fetch_and_add(&smoke_seen, 1);
	e = bpf_ringbuf_reserve(&smoke_rb, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&smoke_reserve_failed, 1);
		return 0;
	}
	e->start_ns = BPF_CORE_READ(p, group_leader, start_boottime);
	e->tgid = BPF_CORE_READ(p, tgid);
	e->pad = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
