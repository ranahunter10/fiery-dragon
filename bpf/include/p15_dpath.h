/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * p15_dpath.h: a file's path by walking its dentries and mounts, the way the kernel's d_path does
 * (fs/d_path.c v7.0: d_path L265-292, prepend_path L155-196, __prepend_path L101-139), for a
 * program that cannot call bpf_d_path (a kprobe: bpf_d_path is offered only to tracing programs on
 * allowlisted functions, kernel/trace/bpf_trace.c L931-958).
 *
 * What it does like d_path:
 *   - the root is the reading task's fs->root, so a chrooted task's path is relative to its root;
 *   - a mount's root crosses to its mountpoint in the parent mount, until the task's root or a
 *     mount that is its own parent (the namespace's root: flag P15_DP_NOT_UNDER_ROOT);
 *   - an unlinked dentry gets " (deleted)";
 *   - a dentry whose d_op has d_dname (pipes, sockets, anon inodes) is not walked:
 *     d_path would ask the filesystem for a made-up name, which a BPF program cannot. Flag
 *     P15_DP_DNAME, no path; ADR-0027 names such files by their open file, not their path.
 * What it does that d_path does by retrying:
 *   - d_path re-walks while the rename or mount sequence counter moved (prepend_path's
 *     read_seqbegin_or_lock). A BPF program cannot take the lock, so the walk reads both counters
 *     before and after, retries once, and flags P15_DP_RACED if they moved again. Neither Tetragon
 *     (bpf/lib/bpf_d_path.h at 63332a1) nor Tracee (pkg/ebpf/c/common/filesystem.h at 2f9dc40)
 *     reads them (R-043, checked 2026-11-12): a path built across a rename can be one that never
 *     existed, silently.
 * Bounds: at most P15_DP_STEPS dentries and mount crossings, at most P15_DP_COMPS components, names
 * cut at NAME_MAX, the whole cut at P15_DP_BUF - 1; any cut is P15_DP_TRUNCATED.
 *
 * The walk needs P15_DP_COMPS * 16 bytes of scratch: the caller passes a per-CPU slot, so it must
 * run where it cannot be preempted (a kprobe), or own the slot.
 */
#ifndef P15_DPATH_H
#define P15_DPATH_H

/* The constants and flags are shared with user space (bench/path_walk/path_walk.c); the walk is BPF only. */
#define P15_DP_STEPS 128         /* dentries plus mount crossings */
#define P15_DP_COMPS 64          /* path components kept */
#define P15_DP_BUF 4096          /* PATH_MAX, the same cut as bpf_d_path's */
#define P15_DP_NAME_MAX 255

#define P15_DP_TRUNCATED (1u << 0)        /* a bound was reached: the path is a cut */
#define P15_DP_RACED (1u << 1)            /* a rename or mount moved during both tries */
#define P15_DP_DNAME (1u << 2)            /* the filesystem names it (d_dname): no path */
#define P15_DP_DELETED (1u << 3)          /* " (deleted)" was appended */
#define P15_DP_NOT_UNDER_ROOT (1u << 4)   /* reached the namespace's root, not the task's root */
#define P15_DP_ESCAPED (1u << 5)          /* a dentry that is its own parent before the root */
#define P15_DP_NO_SEQ (1u << 6)           /* the sequence counters' addresses are unknown */
#define P15_DP_NO_ROOT (1u << 7)          /* the task has no fs (an exiting kernel thread) */
#define P15_DP_RETRIED (1u << 8)          /* the first try raced; the second did not */

#ifdef __bpf__
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

extern const void rename_lock __ksym __weak;
extern const void mount_lock __ksym __weak;

struct p15_dp_comp {
	__u64 name;
	__u32 len;
	__u32 pad;
};

struct p15_dp_scratch {
	struct p15_dp_comp c[P15_DP_COMPS];
};

struct p15_dp_walk {
	__u64 dentry, mnt, root_dentry, root_mnt;   /* struct dentry *, struct mount *, as numbers */
	__u64 mnt_off;                               /* offsetof(struct mount, mnt) */
	struct p15_dp_scratch *s;
	__u32 n, flags, done;
};

static __always_inline __u32 p15_dp_seq(const void *lock)
{
	__u32 v = 1;   /* "odd": unreadable counts as raced */

	if (lock)
		bpf_probe_read_kernel(&v, sizeof(v),
				      (const char *)lock + bpf_core_field_offset(struct seqlock, seqcount.seqcount.sequence));
	return v;
}

/* One dentry or one mount crossing (__prepend_path's loop body). */
static long p15_dp_step(__u64 i, void *vw)
{
	struct p15_dp_walk *w = vw;
	struct dentry *d = bpf_core_cast((void *)w->dentry, struct dentry);
	struct mount *m = bpf_core_cast((void *)w->mnt, struct mount);
	__u64 parent;

	if (w->dentry == w->root_dentry && w->mnt + w->mnt_off == w->root_mnt) {
		w->done = 1;
		return 1;
	}
	if (w->dentry == (__u64)m->mnt.mnt_root) {
		__u64 mp = (__u64)m->mnt_parent;

		if (mp != w->mnt) {
			w->dentry = (__u64)m->mnt_mountpoint;
			w->mnt = mp;
			return 0;
		}
		w->flags |= P15_DP_NOT_UNDER_ROOT;   /* d_path writes it from that root, as we do */
		w->done = 1;
		return 1;
	}
	parent = (__u64)d->d_parent;
	if (parent == w->dentry) {
		w->flags |= P15_DP_ESCAPED;
		w->done = 1;
		return 1;
	}
	if (w->n >= P15_DP_COMPS) {
		w->flags |= P15_DP_TRUNCATED;
		w->done = 1;
		return 1;
	}
	{
		__u32 k = w->n & (P15_DP_COMPS - 1);

		w->s->c[k].name = (__u64)d->d_name.name;
		w->s->c[k].len = d->d_name.len;
		w->n++;
	}
	w->dentry = parent;
	return 0;
}

struct p15_dp_out {
	struct p15_dp_scratch *s;
	char *buf;
	__u32 n, off, flags;
};

/* The components root first: "/" and the name, each copy bounded for the verifier. */
static long p15_dp_put(__u64 i, void *vo)
{
	struct p15_dp_out *o = vo;
	__u32 k = (o->n - 1 - (__u32)i) & (P15_DP_COMPS - 1);
	__u32 len = o->s->c[k].len;

	if (len > P15_DP_NAME_MAX) {
		len = P15_DP_NAME_MAX;
		o->flags |= P15_DP_TRUNCATED;
	}
	if (o->off + 1 + len >= P15_DP_BUF) {
		o->flags |= P15_DP_TRUNCATED;
		return 1;
	}
	o->buf[o->off & (P15_DP_BUF - 1)] = '/';
	o->off++;
	if (len && bpf_probe_read_kernel(o->buf + (o->off & (P15_DP_BUF - 1)), len & P15_DP_NAME_MAX,
					 (const void *)o->s->c[k].name))
		o->flags |= P15_DP_TRUNCATED;
	o->off += len;
	return 0;
}

static __always_inline __u32 p15_dp_try(struct p15_dp_walk *w, __u64 dentry, __u64 mnt)
{
	w->dentry = dentry;
	w->mnt = mnt;
	w->n = 0;
	w->done = 0;
	bpf_loop(P15_DP_STEPS, p15_dp_step, w, 0);
	if (!w->done)
		w->flags |= P15_DP_TRUNCATED;
	return w->n;
}

/*
 * The path of `path` (struct path *, any BTF pointer or a cast one) into buf (P15_DP_BUF + 256 bytes:
 * the verifier bounds each copy by its mask, not by the bytes left),
 * NUL-terminated. Returns the length without the NUL; *flags gets P15_DP_*. buf holds "" when
 * P15_DP_DNAME or P15_DP_NO_ROOT is set.
 */
static __always_inline __u32 p15_dpath(const struct path *path, char *buf, struct p15_dp_scratch *s, __u32 *flags)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct fs_struct *fs = t->fs;
	struct dentry *d = path->dentry;
	struct p15_dp_walk w = { .s = s, .mnt_off = bpf_core_field_offset(struct mount, mnt) };
	struct p15_dp_out o = { .s = s, .buf = buf };
	__u32 rs0, ms0, rs1, ms1;
	int tries;

	buf[0] = 0;
	if (d->d_op && d->d_op->d_dname && (d != d->d_parent || d != path->mnt->mnt_root)) {
		*flags = P15_DP_DNAME;
		return 0;
	}
	if (!fs) {
		*flags = P15_DP_NO_ROOT;
		return 0;
	}
	w.root_dentry = (__u64)fs->root.dentry;
	w.root_mnt = (__u64)fs->root.mnt;
	if (!&rename_lock || !&mount_lock)
		w.flags |= P15_DP_NO_SEQ;
	for (tries = 0; tries < 2; tries++) {
		rs0 = p15_dp_seq(&rename_lock);
		ms0 = p15_dp_seq(&mount_lock);
		w.flags &= ~(P15_DP_TRUNCATED | P15_DP_NOT_UNDER_ROOT | P15_DP_ESCAPED);
		p15_dp_try(&w, (__u64)d, (__u64)path->mnt - w.mnt_off);
		rs1 = p15_dp_seq(&rename_lock);
		ms1 = p15_dp_seq(&mount_lock);
		if (!(rs0 & 1) && !(ms0 & 1) && rs0 == rs1 && ms0 == ms1)
			break;
		if (tries == 0)
			w.flags |= P15_DP_RETRIED;
	}
	if (tries == 2) {
		w.flags &= ~P15_DP_RETRIED;
		w.flags |= P15_DP_RACED;
	}
	o.n = w.n;
	o.flags = w.flags;
	if (w.n == 0) {
		buf[0] = '/';
		o.off = 1;
	} else {
		bpf_loop(w.n, p15_dp_put, &o, 0);
	}
	/* d_unlinked(): unhashed and not a root (include/linux/dcache.h) */
	if (!d->d_hash.pprev && d != d->d_parent && o.off + 10 < P15_DP_BUF) {
		static const char del[] = " (deleted)";

		for (int i = 0; i < 10; i++)
			buf[(o.off + i) & (P15_DP_BUF - 1)] = del[i];
		o.off += 10;
		o.flags |= P15_DP_DELETED;
	}
	buf[o.off & (P15_DP_BUF - 1)] = 0;
	*flags = o.flags;
	return o.off;
}

#endif /* __bpf__ */
#endif
