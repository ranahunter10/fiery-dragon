// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * prim_cost: what the kernel-side building blocks of a capture record cost on this host, each
 * timed alone in a loop inside one BPF program (bench/prim_cost/README.md). The program is a
 * SEC("syscall") program run with BPF_PROG_RUN: no hook, so no hook-path cost is in the numbers.
 *
 * One run does `iters` iterations of the primitive chosen by `which` and reports the ns it took
 * (bpf_ktime_get_ns around the loop) and how many iterations did what they should.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

enum { P_EMPTY, P_RING_96, P_RING_DISCARD_96, P_RING_OUTPUT_96, P_HASH_LOOKUP, P_HASH_UPDATE_DELETE, P_COUNTER,
       P_PERCPU_COPY_96, P_KTIME, P_N };

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);          /* the daemon's default bulk ring */
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);                    /* the open-file map's default size */
	__type(key, __u64);
	__type(value, __u64[4]);                       /* 32 bytes: the size class of our entries */
} hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[4096]);
} scratch SEC(".maps");

__u64 counter;
__u32 which, iters;
__u64 out_ns, out_ok;
__u8 rec[96];

struct ctx {
	__u64 ok;
	__u8 *buf;
};

static long one(__u64 i, void *vctx)
{
	struct ctx *c = vctx;
	__u64 key = i & 0xfff, val[4] = { i, 0, 0, 0 };
	void *p;

	switch (which) {
	case P_EMPTY:
		c->ok++;
		break;
	case P_RING_96:              /* reserve, fill, submit without a wake-up: what a record costs the ring */
		p = bpf_ringbuf_reserve(&rb, 96, 0);
		if (p) {
			__builtin_memcpy(p, rec, 96);
			bpf_ringbuf_submit(p, BPF_RB_NO_WAKEUP);
			c->ok++;
		}
		break;
	case P_RING_DISCARD_96:      /* the reservation alone (the record is discarded, so the ring never fills) */
		p = bpf_ringbuf_reserve(&rb, 96, 0);
		if (p) {
			bpf_ringbuf_discard(p, BPF_RB_NO_WAKEUP);
			c->ok++;
		}
		break;
	case P_RING_OUTPUT_96:       /* the copying API, as used from a scratch buffer */
		if (!bpf_ringbuf_output(&rb, rec, 96, BPF_RB_NO_WAKEUP))
			c->ok++;
		break;
	case P_HASH_LOOKUP:
		if (bpf_map_lookup_elem(&hash, &key))
			c->ok++;
		break;
	case P_HASH_UPDATE_DELETE:   /* an entry made and removed: one open-file entry's life */
		key = 0x100000 + i;
		if (!bpf_map_update_elem(&hash, &key, val, BPF_NOEXIST) && !bpf_map_delete_elem(&hash, &key))
			c->ok++;
		break;
	case P_COUNTER:
		__sync_fetch_and_add(&counter, 1);
		c->ok++;
		break;
	case P_PERCPU_COPY_96:       /* a record appended to a per-CPU buffer: the first level of a two-level design */
		if (c->buf) {
			__builtin_memcpy(c->buf + ((i * 96) & 0xfff & ~0x7f), rec, 96);
			c->ok++;
		}
		break;
	case P_KTIME:
		if (bpf_ktime_get_boot_ns())
			c->ok++;
		break;
	}
	return 0;
}

SEC("syscall")
int prim_run(void *unused)
{
	struct ctx c = { 0 };
	__u32 zero = 0;
	__u64 t0;

	c.buf = bpf_map_lookup_elem(&scratch, &zero);
	t0 = bpf_ktime_get_ns();
	bpf_loop(iters, one, &c, 0);
	out_ns = bpf_ktime_get_ns() - t0;
	out_ok = c.ok;
	return 0;
}

/* fill the lookup keys once */
SEC("syscall")
int prim_fill(void *unused)
{
	__u64 val[4] = { 1, 0, 0, 0 };

	for (__u64 k = 0; k < 0x1000; k++)
		bpf_map_update_elem(&hash, &k, val, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
