// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * hook_cost: the same trivial body behind the two hook types ADR-0020 chooses between, so a
 * difference in cost is the hook path's alone (ADR-0020 confirmation 5, ADR-0018 rule 2):
 *   tracepoint/  the classic perf path: it fills the tracepoint's own record (for exec, the
 *                filename) and runs the program with preemption off (include/trace/perf.h)
 *   tp_btf/      the BTF raw tracepoint: the program gets the raw arguments, preemptible on 7.0
 * Each body counts one hit if the event is the harness's own (rename) or its child's (exec),
 * so every arm's count can be checked against the number of events it caused.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u32 harness_tgid;

enum { H_TP_RENAME, H_BTF_RENAME, H_TP_EXEC, H_BTF_EXEC, H_N };

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, H_N);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

static __always_inline int hit(__u32 k, int by_parent)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	__u32 tgid = by_parent ? BPF_CORE_READ(t, real_parent, tgid) : BPF_CORE_READ(t, tgid);
	__u64 *v;

	if (tgid != harness_tgid)
		return 0;
	v = bpf_map_lookup_elem(&hits, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
	return 0;
}

SEC("tracepoint/task/task_rename")
int tp_rename(void *ctx) { return hit(H_TP_RENAME, 0); }

SEC("tp_btf/task_rename")
int btf_rename(__u64 *ctx) { return hit(H_BTF_RENAME, 0); }

SEC("tracepoint/sched/sched_process_exec")
int tp_exec(void *ctx) { return hit(H_TP_EXEC, 1); }

SEC("tp_btf/sched_process_exec")
int btf_exec(__u64 *ctx) { return hit(H_BTF_EXEC, 1); }
