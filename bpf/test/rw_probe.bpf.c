// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * rw_probe: which hook type for slice B's read/write paths survives a read/write storm without
 * the kernel skipping it, and at what cost (STATE decisions taken 15.5, research note
 * 2026-11-06-dataflow-slice-b). Each variant counts the probe's own process's calls of vfs_read
 * and vfs_write, at entry and exit where the hook has both:
 *
 *   A  fexit/vfs_read, fexit/vfs_write  preemptible on 7.0, per-program guard
 *                                       (kernel/bpf/trampoline.c __bpf_prog_enter_recur)
 *   B  kprobe.multi + kretprobe.multi   fprobe, non-preemptible, the bpf_prog_active guard
 *                                       (kernel/trace/bpf_trace.c kprobe_multi_link_prog_run)
 *   C  kprobe.session                   the same path, entry and exit in one program
 *
 * The probe attaches one variant at a time. ring_mode 1 also writes a ring record per call with
 * a forced wake-up: the stress E-0090 found drove the spine's skips (3.3% vs 0.02%).
 * Counters are plain .bss words, read through the skeleton's mapping after detach.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

extern bool bpf_session_is_return(void *ctx) __ksym;   /* v7.0 kernel/trace/bpf_trace.c L3339: takes ctx */

const volatile __u32 target_tgid = 0;
const volatile __u32 ring_mode = 0;

enum { H_A_READ, H_A_WRITE, H_B, H_C, H__N };

__u64 seen_entry[H__N];
__u64 seen_exit[H__N];
__u64 ring_failed;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} rb SEC(".maps");

struct rec {
	__u32 hook, tid;
	__s64 ret;
};

static __always_inline int ours(void)
{
	return (__u32)(bpf_get_current_pid_tgid() >> 32) == target_tgid;
}

static __always_inline void out(__u32 hook, __s64 ret)
{
	struct rec r = { .hook = hook, .tid = (__u32)bpf_get_current_pid_tgid(), .ret = ret };

	if (ring_mode && bpf_ringbuf_output(&rb, &r, sizeof(r), BPF_RB_FORCE_WAKEUP))
		__sync_fetch_and_add(&ring_failed, 1);
}

SEC("fexit/vfs_read")
int BPF_PROG(a_read, struct file *f, char *buf, size_t n, loff_t *pos, ssize_t ret)
{
	if (ours()) {
		__sync_fetch_and_add(&seen_exit[H_A_READ], 1);
		out(H_A_READ, ret);
	}
	return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(a_write, struct file *f, const char *buf, size_t n, loff_t *pos, ssize_t ret)
{
	if (ours()) {
		__sync_fetch_and_add(&seen_exit[H_A_WRITE], 1);
		out(H_A_WRITE, ret);
	}
	return 0;
}

/* B and C attach by symbol list from userspace (vfs_read, vfs_write), so no target in SEC() */
SEC("kprobe.multi")
int b_entry(struct pt_regs *ctx)
{
	if (ours())
		__sync_fetch_and_add(&seen_entry[H_B], 1);
	return 0;
}

SEC("kretprobe.multi")
int b_exit(struct pt_regs *ctx)
{
	if (ours()) {
		__sync_fetch_and_add(&seen_exit[H_B], 1);
		out(H_B, (__s64)PT_REGS_RC(ctx));
	}
	return 0;
}

SEC("kprobe.session")
int c_session(struct pt_regs *ctx)
{
	if (!ours())
		return 1;                       /* 1 at entry: skip the return half */
	if (!bpf_session_is_return(ctx)) {
		__sync_fetch_and_add(&seen_entry[H_C], 1);
		return 0;                       /* 0 at entry: run the return half too */
	}
	__sync_fetch_and_add(&seen_exit[H_C], 1);
	out(H_C, (__s64)PT_REGS_RC(ctx));
	return 0;
}
