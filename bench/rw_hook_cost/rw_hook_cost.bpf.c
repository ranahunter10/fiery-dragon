// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * rw_hook_cost: the same trivial body behind each hook type slice B could use on the read path,
 * so a difference in cost is the hook path's alone (ADR-0005/ADR-0015 decision 1a, N5;
 * ADR-0018 rule 2). Every arm hooks vfs_read and counts one hit per call made by the harness:
 *   fentry       BPF trampoline at entry (preemptible on 7.0: can be skipped for another task)
 *   fexit        trampoline at return, with the return value (same skip property)
 *   kpm          kprobe.multi, entry only (fprobe, preemption off)
 *   pair         kprobe.multi at entry + kretprobe.multi at return, two links; the entry keeps
 *                the file pointer for the return in a hash keyed by thread, as two links must
 *   session      kprobe.session, one link: entry and return share an 8-byte per-call cookie
 * The pair and session arms count at the return, where slice B would write its record, and
 * count a return whose entry left nothing (pair: no stash; session: an empty cookie).
 * Two more programs check that a kprobe.session and a fentry can sit on one function at once
 * (security_file_open, ADR-0015 rule 6; design check O2).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* bpf_session_cookie(ctx) and bpf_session_is_return(ctx) come from vmlinux.h: on 7.0 they take ctx */

const volatile __u32 harness_tgid;

enum { H_FENTRY, H_FEXIT, H_KPM, H_PAIR, H_SESSION, H_PAIR_NOSTASH, H_SESSION_NOCOOKIE, H_PAIR_STASH_FULL,
       H_OPEN_SESSION, H_OPEN_FENTRY, H_N };

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, H_N);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

/* the pair arm's entry-to-return stash, keyed by thread id (what a two-link design needs) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} stash SEC(".maps");

static __always_inline int ours(void)
{
	return (__u32)(bpf_get_current_pid_tgid() >> 32) == harness_tgid;
}

static __always_inline void count(__u32 k)
{
	__u64 *v = bpf_map_lookup_elem(&hits, &k);

	if (v)
		__sync_fetch_and_add(v, 1);
}

SEC("fentry/vfs_read")
int BPF_PROG(rd_fentry, struct file *file)
{
	if (ours() && file)
		count(H_FENTRY);
	return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(rd_fexit, struct file *file, char *buf, size_t count_, loff_t *pos, ssize_t ret)
{
	if (ours() && file && ret >= 0)
		count(H_FEXIT);
	return 0;
}

SEC("kprobe.multi/vfs_read")
int rd_kpm(struct pt_regs *ctx)
{
	if (ours() && PT_REGS_PARM1(ctx))
		count(H_KPM);
	return 0;
}

SEC("kprobe.multi/vfs_read")
int rd_pair_entry(struct pt_regs *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 file = PT_REGS_PARM1(ctx);

	if (!ours())
		return 0;
	if (bpf_map_update_elem(&stash, &tid, &file, BPF_ANY))
		count(H_PAIR_STASH_FULL);
	return 0;
}

SEC("kretprobe.multi/vfs_read")
int rd_pair_return(struct pt_regs *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *file;

	if (!ours())
		return 0;
	file = bpf_map_lookup_elem(&stash, &tid);
	if (!file || !*file) {
		count(H_PAIR_NOSTASH);
		return 0;
	}
	if ((long)PT_REGS_RC(ctx) >= 0)
		count(H_PAIR);
	bpf_map_delete_elem(&stash, &tid);
	return 0;
}

SEC("kprobe.session/vfs_read")
int rd_session(struct pt_regs *ctx)
{
	__u64 *cookie;

	if (!bpf_session_is_return(ctx)) {
		if (!ours())
			return 1;               /* not ours: the return run is skipped */
		cookie = bpf_session_cookie(ctx);
		*cookie = PT_REGS_PARM1(ctx);
		return 0;
	}
	cookie = bpf_session_cookie(ctx);
	if (!*cookie) {
		count(H_SESSION_NOCOOKIE);
		return 0;
	}
	if ((long)PT_REGS_RC(ctx) >= 0)
		count(H_SESSION);
	return 0;
}

SEC("kprobe.session/security_file_open")
int open_session(struct pt_regs *ctx)
{
	if (!bpf_session_is_return(ctx))
		return ours() ? 0 : 1;
	count(H_OPEN_SESSION);
	return 0;
}

SEC("fentry/security_file_open")
int BPF_PROG(open_fentry, struct file *file)
{
	if (ours() && file)
		count(H_OPEN_FENTRY);
	return 0;
}
