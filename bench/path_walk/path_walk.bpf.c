// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * path_walk: the dentry walk of bpf/include/p15_dpath.h against the kernel's own bpf_d_path, on the
 * same opens, and what each costs (bench/path_walk/README.md, gate 2 of STATE decision 28).
 *
 *   fentry/security_file_open          for the harness's own process: bpf_d_path and the walk on the
 *                                       same struct file, both timed, one sample record to the ring
 *   kprobe.session/security_file_open  for the harness's own process: the walk alone, timed, where
 *                                       production would run it (non-preemptible; no bpf_d_path)
 * The harness is one thread (it pins itself), so the fentry's per-CPU scratch is never shared.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "p15_dpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define BUF (P15_DP_BUF + 256)

struct pw_sample {
	__u32 dpath_len;     /* bpf_d_path's length without the NUL, or 0 */
	__s32 dpath_rc;      /* its return: length with the NUL, or -errno */
	__u32 walk_len;
	__u32 walk_flags;
	__u32 moved;         /* a rename or mount sequence moved between bpf_d_path and the walk's end:
	                        the two read the tree at different times, so they are not compared */
	__u32 pad;
	__u64 dpath_ns, walk_ns;
	char dpath[BUF];
	char walk[BUF];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct p15_dp_scratch);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct p15_dp_scratch);
} kscratch SEC(".maps");   /* the kprobe's own: it never shares the fentry's */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[BUF]);
} kbuf SEC(".maps");

__u32 target_tgid;
__u32 emit;               /* 1: send each fentry sample; 0: time only (the timing rounds) */
__u64 f_runs, f_dpath_ns, f_walk_ns, f_lost;
__u64 k_runs, k_walk_ns, k_flags_or;

static __always_inline int mine(void)
{
	return (__u32)(bpf_get_current_pid_tgid() >> 32) == target_tgid;
}

SEC("fentry/security_file_open")
int BPF_PROG(pw_fentry, struct file *file)
{
	struct p15_dp_scratch *s;
	struct pw_sample *r;
	__u32 zero = 0;
	__u64 t0, t1, t2;
	__u32 rs, ms;
	long n;

	if (!mine())
		return 0;
	s = bpf_map_lookup_elem(&scratch, &zero);
	r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
	if (!s || !r) {
		if (r)
			bpf_ringbuf_discard(r, 0);
		__sync_fetch_and_add(&f_lost, 1);
		return 0;
	}
	rs = p15_dp_seq(&rename_lock);
	ms = p15_dp_seq(&mount_lock);
	t0 = bpf_ktime_get_ns();
	n = bpf_d_path(&file->f_path, r->dpath, P15_DP_BUF);
	t1 = bpf_ktime_get_ns();
	r->walk_len = p15_dpath(&file->f_path, r->walk, s, &r->walk_flags);
	t2 = bpf_ktime_get_ns();
	r->moved = (rs & 1) || (ms & 1) || rs != p15_dp_seq(&rename_lock) || ms != p15_dp_seq(&mount_lock);
	r->pad = 0;
	r->dpath_rc = (__s32)n;
	r->dpath_len = n > 0 ? (__u32)(n - 1) : 0;
	r->dpath_ns = t1 - t0;
	r->walk_ns = t2 - t1;
	__sync_fetch_and_add(&f_runs, 1);
	__sync_fetch_and_add(&f_dpath_ns, t1 - t0);
	__sync_fetch_and_add(&f_walk_ns, t2 - t1);
	if (emit)
		bpf_ringbuf_submit(r, 0);
	else
		bpf_ringbuf_discard(r, BPF_RB_NO_WAKEUP);
	return 0;
}

SEC("kprobe.session/security_file_open")
int pw_session(struct pt_regs *ctx)
{
	struct file *file;
	struct p15_dp_scratch *s;
	__u32 zero = 0, flags = 0;
	char *buf;
	__u64 t0;

	if (bpf_session_is_return(ctx) || !mine())
		return 1;   /* entry only: no return run */
	file = bpf_core_cast((void *)PT_REGS_PARM1(ctx), struct file);
	s = bpf_map_lookup_elem(&kscratch, &zero);
	buf = bpf_map_lookup_elem(&kbuf, &zero);
	if (!s || !buf)
		return 1;
	t0 = bpf_ktime_get_ns();
	p15_dpath(&file->f_path, buf, s, &flags);
	__sync_fetch_and_add(&k_walk_ns, bpf_ktime_get_ns() - t0);
	__sync_fetch_and_add(&k_runs, 1);
	__sync_fetch_and_or(&k_flags_or, flags);
	return 1;
}
