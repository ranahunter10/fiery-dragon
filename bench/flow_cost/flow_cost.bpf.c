// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * flow_cost: what step 2b's read hook costs per call on vfs_read with each way of keeping FLOW's
 * start time (step 2b design checks §2 and §4, decision waiting 13). Every arm is a
 * kprobe.session on vfs_read for the harness's own calls; the cookie keeps the file pointer:
 *   session   the empty session, as rw_hook_cost's session arm (E-0138's anchor)
 *   ts        option A: task storage keeps {file, entry time}; the return checks the file
 *   end_rec   option D: the return writes a 96-byte FLOW (schema/records.toml) with its end time
 *             only, flagged START_UNKNOWN
 *   ts_rec    option A with the record: FLOW with first_ts from task storage
 * The record arms reserve, fill and submit on a ring buffer without a wakeup; the harness drains
 * it from another CPU, as p15d's drain does. No file map, no marks: those are the same for A and
 * D and are measured with step 2b's programs.
 * Counters (hits[]): one per return of each arm; a start time lost (no storage entry, or one
 * for another file: a nested call); a failed storage creation; a failed ring reservation.
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "p15_records.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u32 harness_tgid;

enum { H_SESSION, H_TS, H_END_REC, H_TS_REC, H_NOCOOKIE, H_TS_LOST, H_TS_CREATE_FAILED, H_RESERVE_FAILED, H_N };

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, H_N);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

/* option A's per-task state: the file of the call in progress and its entry time */
struct start {
	__u64 file;
	__u64 ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct start);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 << 20);
} flows SEC(".maps");

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

/* the entry run of every arm: not ours -> skip the return; else the file in the cookie */
static __always_inline int entry(struct pt_regs *ctx, int keep_start)
{
	__u64 *cookie = bpf_session_cookie(ctx);
	struct start *s;

	if (!ours())
		return 1;
	*cookie = PT_REGS_PARM1(ctx);
	if (keep_start) {
		s = bpf_task_storage_get(&starts, bpf_get_current_task_btf(), 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (!s) {
			count(H_TS_CREATE_FAILED);
			return 0;
		}
		s->file = *cookie;
		s->ts = bpf_ktime_get_boot_ns();
	}
	return 0;
}

/* option A at the return: the entry time if the stored file is this call's, else 0 (counted) */
static __always_inline __u64 start_of(__u64 file)
{
	struct start *s = bpf_task_storage_get(&starts, bpf_get_current_task_btf(), 0, 0);

	if (!s || s->file != file) {
		count(H_TS_LOST);
		return 0;
	}
	s->file = 0;                    /* used: a later return without its entry cannot match it */
	return s->ts;
}

static __always_inline void emit(__u64 first, __u64 now, long ret)
{
	struct p15_flow_v1 *r = bpf_ringbuf_reserve(&flows, sizeof(*r), 0);
	struct task_struct *t = bpf_get_current_task_btf();
	__u64 id = bpf_get_current_pid_tgid();

	if (!r) {
		count(H_RESERVE_FAILED);
		return;
	}
	r->h.type = P15_T_FLOW;
	r->h.version = 1;
	r->h.len = sizeof(*r);
	r->h.flags = 0;
	r->h.ts_ns = now;
	r->h.tgid = (__u32)(id >> 32);
	r->h.tid = (__u32)id;
	r->h.start_ns = BPF_CORE_READ(t, group_leader, start_boottime);
	r->fid = 0;
	r->obj = 0;
	r->first_ts = first ? first : now;
	r->last_ts = now;
	r->bytes = (__u64)ret;
	r->count = 1;
	r->fflags = first ? 0 : P15_FF_START_UNKNOWN;
	r->kind = P15_FLOW_KIND_READ;
	r->reason = P15_FLOW_REASON_SINGLE;
	r->facts_full = 0;
	r->facts_len = 0;
	__builtin_memset(r->_pad, 0, sizeof(r->_pad));
	bpf_ringbuf_submit(r, BPF_RB_NO_WAKEUP);
}

/* the return run's common part: the file from the cookie, or 0 (counted) */
static __always_inline __u64 cookie_file(struct pt_regs *ctx)
{
	__u64 f = *bpf_session_cookie(ctx);

	if (!f)
		count(H_NOCOOKIE);
	return f;
}

SEC("kprobe.session/vfs_read")
int rd_session(struct pt_regs *ctx)
{
	if (!bpf_session_is_return(ctx))
		return entry(ctx, 0);
	if (cookie_file(ctx) && (long)PT_REGS_RC(ctx) > 0)
		count(H_SESSION);
	return 0;
}

SEC("kprobe.session/vfs_read")
int rd_ts(struct pt_regs *ctx)
{
	__u64 f;

	if (!bpf_session_is_return(ctx))
		return entry(ctx, 1);
	f = cookie_file(ctx);
	if (f && start_of(f) && (long)PT_REGS_RC(ctx) > 0)
		count(H_TS);
	return 0;
}

SEC("kprobe.session/vfs_read")
int rd_end_rec(struct pt_regs *ctx)
{
	long ret;

	if (!bpf_session_is_return(ctx))
		return entry(ctx, 0);
	ret = (long)PT_REGS_RC(ctx);
	if (cookie_file(ctx) && ret > 0) {
		emit(0, bpf_ktime_get_boot_ns(), ret);
		count(H_END_REC);
	}
	return 0;
}

SEC("kprobe.session/vfs_read")
int rd_ts_rec(struct pt_regs *ctx)
{
	__u64 f, first;
	long ret;

	if (!bpf_session_is_return(ctx))
		return entry(ctx, 1);
	ret = (long)PT_REGS_RC(ctx);
	f = cookie_file(ctx);
	if (!f || ret <= 0)
		return 0;
	first = start_of(f);
	emit(first, bpf_ktime_get_boot_ns(), ret);
	count(H_TS_REC);
	return 0;
}
