// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * sliceb_probe.bpf.c: the step 2a dry run (ADR-0015 rules 1-9, STATE decision 19). Every
 * mechanism the production identity programs will use, on the target kernel, for the harness
 * process only:
 *   fentry/security_file_open         OPEN with bpf_d_path into a per-call claimed scratch slot,
 *                                      copied to the ring at its exact size; a full-size record
 *                                      when no slot is free; BACKING for an FMODE_BACKING file
 *   kprobe.session/security_file_open  entry registers the open file, the return writes only
 *                                      OPEN_VERDICT (denied) or OPEN with PATH_MISSING (no fentry)
 *   kprobe.multi/security_file_free    CLOSE (NEVER_OPENED, KTHREAD) and the entry's deletion
 *   kprobe.multi/security_inode_free   the object entry's deletion
 *   iter/task_file                     the snapshot's FD pass with bpf_d_path
 * plus the btrfs subvolume read compiled out by CO-RE when btrfs's BTF is absent, and the
 * overlay backing_file read. Counters: sliceb_probe.h; every early return has one.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sliceb_probe.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ENAMETOOLONG 36
#define EEXIST 17
#define PF_KTHREAD 0x00200000   /* include/linux/sched.h */

const volatile __u32 harness_tgid;

__u64 next_id;            /* the run's id counter (ADR-0015 rule 1): ids 1, 2, 3, ... */
__u32 force_claim_fail;   /* test switch: no scratch slot is claimed, so the full-size path runs */
__u32 btrfs_btf;          /* 1 if the btrfs subvolume read survived CO-RE at load */

/* open-file entry state bits */
#define ST_SESSION_ENTRY (1u << 0)
#define ST_FENTRY_RAN (1u << 1)

struct file_ent {
	__u64 fid;
	__u64 obj;
	__u64 inode;   /* the inode address, checked on every lookup (rule 9) */
	__u32 state;
	__u32 pad;
};

struct obj_ent {
	__u64 obj;
	__u64 ino;
	__u32 dev;
	__u32 gen;
	__u32 facts_written;   /* set after a record carrying the facts was submitted (decision 19.7) */
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct file_ent);
} files SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct obj_ent);
} objs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 << 20);
} ring SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, H_N);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

struct sbp_slot {
	__u32 busy;
	__u32 pad;
	struct sbp_rec rec;
};

/* fentry runs preemptible with migration off: a slot is this CPU's, and a task preempting
 * another on the CPU claims a different slot (the lesson of E-0097). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SBP_SLOTS);
	__type(key, __u32);
	__type(value, struct sbp_slot);
} scratch SEC(".maps");

/* the FD pass's buffer: the iterator runs one at a time (the harness reads it from one thread) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sbp_rec);
} iter_buf SEC(".maps");

/* btrfs is a module: its types are matched against the module's BTF, if it was loaded at load
 * time (ADR-0015 rule 2; design check V6). Only the members read are declared. */
struct btrfs_key___p15 {
	__u64 objectid;
} __attribute__((preserve_access_index));

struct btrfs_root___p15 {
	struct btrfs_key___p15 root_key;
} __attribute__((preserve_access_index));

struct btrfs_inode___p15 {
	struct btrfs_root___p15 *root;
	struct inode vfs_inode;
} __attribute__((preserve_access_index));

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

static __always_inline __u64 new_id(void)
{
	return __sync_fetch_and_add(&next_id, 1) + 1;
}

static __always_inline void read_facts(struct inode *inode, struct sbp_facts *f, __u32 *fflags)
{
	f->ino = BPF_CORE_READ(inode, i_ino);
	f->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	f->gen = BPF_CORE_READ(inode, i_generation);
	f->mode = BPF_CORE_READ(inode, i_mode);
	f->fs_magic = (__u32)BPF_CORE_READ(inode, i_sb, s_magic);
	f->nlink = BPF_CORE_READ(inode, __i_nlink);
	f->subvol = 0;
	f->pad = 0;
	if (f->fs_magic != SBP_BTRFS_MAGIC)
		return;
	if (bpf_core_type_exists(struct btrfs_inode___p15)) {
		struct btrfs_inode___p15 *bi =
			(void *)((char *)inode - bpf_core_field_offset(struct btrfs_inode___p15, vfs_inode));

		f->subvol = BPF_CORE_READ(bi, root, root_key.objectid);
		btrfs_btf = 1;
	} else {
		*fflags |= SBP_F_SUBVOL_UNKNOWN;
	}
}

/* The object id of inode (rule 1), registering it if new. *ep is the entry, or NULL when the map
 * is full (the id is then fresh and unregistered, counted). OBJ_NEW in *fflags if the facts were
 * not yet written. */
static __always_inline __u64 obj_of(struct inode *inode, const struct sbp_facts *f, __u32 *fflags, __u32 newflag,
				    struct obj_ent **ep)
{
	__u64 key = (__u64)inode;
	struct obj_ent *e = bpf_map_lookup_elem(&objs, &key);
	long rc;

	if (e && (e->ino != f->ino || e->dev != f->dev || e->gen != f->gen)) {
		count(H_OBJ_STALE);
		bpf_map_delete_elem(&objs, &key);
		e = NULL;
	}
	if (!e) {
		struct obj_ent n = { .obj = new_id(), .ino = f->ino, .dev = f->dev, .gen = f->gen };

		rc = bpf_map_update_elem(&objs, &key, &n, BPF_NOEXIST);
		if (rc == -EEXIST) {
			count(H_OBJ_RACE);
		} else if (rc) {
			count(H_OBJ_MAP_FULL);
			*ep = NULL;
			*fflags |= newflag;
			return n.obj;
		}
		e = bpf_map_lookup_elem(&objs, &key);
		if (!e) {
			count(H_OBJ_MAP_FULL);   /* deleted between insert and lookup: a free raced us */
			*ep = NULL;
			*fflags |= newflag;
			return n.obj;
		}
	}
	if (!e->facts_written)
		*fflags |= newflag;
	*ep = e;
	return e->obj;
}

/* After the record carrying OBJ_NEW was submitted: mark the facts written. A second writer that
 * also carried them is counted (decision 19.7: twice is allowed, never zero times). */
static __always_inline void facts_done(struct obj_ent *e, __u32 fflags, __u32 newflag)
{
	if (e && (fflags & newflag) && __sync_val_compare_and_swap(&e->facts_written, 0, 1) != 0)
		count(H_FACTS_DUP);
}

/* The open-file entry of file (rule 1), created if absent. NULL when the map is full (counted). */
static __always_inline struct file_ent *file_ent_get(struct file *file, struct inode *inode, __u64 obj, int *created)
{
	__u64 key = (__u64)file;
	struct file_ent *e = bpf_map_lookup_elem(&files, &key);
	long rc;

	*created = 0;
	if (e && e->inode != (__u64)inode) {
		count(H_FILE_STALE);
		bpf_map_delete_elem(&files, &key);
		e = NULL;
	}
	if (e)
		return e;
	{
		struct file_ent n = { .fid = new_id(), .obj = obj, .inode = (__u64)inode };

		rc = bpf_map_update_elem(&files, &key, &n, BPF_NOEXIST);
		if (rc == -EEXIST)
			count(H_FILE_RACE);
		else if (rc) {
			count(H_FILE_MAP_FULL);
			return NULL;
		} else {
			*created = 1;
		}
	}
	e = bpf_map_lookup_elem(&files, &key);
	if (!e)
		count(H_FILE_MAP_FULL);
	return e;
}

static __always_inline void fill_hdr(struct sbp_rec *r, __u16 type)
{
	struct task_struct *t = bpf_get_current_task_btf();
	__u64 pt = bpf_get_current_pid_tgid();

	r->type = type;
	r->tgid = pt >> 32;
	r->tid = (__u32)pt;
	if (BPF_CORE_READ(t, flags) & PF_KTHREAD)
		r->fflags |= SBP_F_KTHREAD;
}

static __always_inline void zero_fixed(struct sbp_rec *r)
{
	__builtin_memset(r, 0, SBP_FIXED);
}

/* The path of file into r->path (rule 6): the kernel's d_path; the dentry name with TRUNCATED
 * when it does not fit; empty with PATH_ERROR otherwise. Returns the bytes written. */
static __always_inline __u32 fill_path(struct sbp_rec *r, struct file *file)
{
	long n = bpf_d_path(&file->f_path, r->path, SBP_PATH_MAX);

	if (n > 0)
		return (__u32)(n - 1) & (SBP_PATH_MAX - 1);
	if (n == -ENAMETOOLONG) {
		const unsigned char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
		long m = bpf_probe_read_kernel_str(r->path, SBP_NAME_MAX, name);

		r->fflags |= SBP_F_TRUNCATED;
		count(H_TRUNCATED);
		return m > 0 ? (__u32)(m - 1) & (SBP_NAME_MAX - 1) : 0;
	}
	r->fflags |= SBP_F_PATH_ERROR;
	r->path_err = (__s32)n;
	count(H_PATH_ERROR);
	return 0;
}

/* OPEN's body, the same whether r is a claimed slot or a full-size ring reservation. */
static __always_inline void fill_open(struct sbp_rec *r, struct file *file, struct inode *inode, struct obj_ent **oe,
				      struct file_ent **fe)
{
	int created;

	zero_fixed(r);
	fill_hdr(r, SBP_OPEN);
	read_facts(inode, &r->facts, &r->fflags);
	r->obj = obj_of(inode, &r->facts, &r->fflags, SBP_F_OBJ_NEW, oe);
	*fe = file_ent_get(file, inode, r->obj, &created);
	r->fid = *fe ? (*fe)->fid : 0;
	r->f_flags = BPF_CORE_READ(file, f_flags);
	r->f_mode = BPF_CORE_READ(file, f_mode);
	r->path_len = fill_path(r, file);
}

static __always_inline void opened(struct file_ent *fe, struct obj_ent *oe, __u32 fflags)
{
	count(H_OPEN_EMITTED);
	facts_done(oe, fflags, SBP_F_OBJ_NEW);
	(void)fe;
}

/* BACKING (rule 4): the backing file's object and the overlay object it stands for. */
static __always_inline int write_backing(struct file *file, struct inode *inode)
{
	struct backing_file *bf = (void *)((char *)file - bpf_core_field_offset(struct backing_file, file));
	struct inode *uinode = BPF_CORE_READ(bf, user_path.dentry, d_inode);
	struct obj_ent *oe, *oe2;
	struct file_ent *fe;
	struct sbp_rec *r;
	int created;

	r = bpf_ringbuf_reserve(&ring, SBP_FIXED, 0);
	if (!r) {
		count(H_RESERVE_FAILED);
		return 0;
	}
	zero_fixed(r);
	fill_hdr(r, SBP_BACKING);
	r->len = SBP_FIXED;
	read_facts(inode, &r->facts, &r->fflags);
	r->obj = obj_of(inode, &r->facts, &r->fflags, SBP_F_OBJ_NEW, &oe);
	if (uinode) {
		read_facts(uinode, &r->facts2, &r->fflags);
		r->obj2 = obj_of(uinode, &r->facts2, &r->fflags, SBP_F_OBJ2_NEW, &oe2);
	} else {
		oe2 = NULL;
	}
	fe = file_ent_get(file, inode, r->obj, &created);
	r->fid = fe ? fe->fid : 0;
	r->f_flags = BPF_CORE_READ(file, f_flags);
	r->f_mode = BPF_CORE_READ(file, f_mode);
	{
		__u32 fl = r->fflags;

		bpf_ringbuf_submit(r, 0);
		count(H_BACKING_EMITTED);
		facts_done(oe, fl, SBP_F_OBJ_NEW);
		facts_done(oe2, fl, SBP_F_OBJ2_NEW);
	}
	if (fe)
		__sync_fetch_and_or(&fe->state, ST_FENTRY_RAN);
	return 0;
}

static __always_inline struct sbp_slot *claim(void)
{
	if (force_claim_fail)
		return NULL;
	for (__u32 k = 0; k < SBP_SLOTS; k++) {
		struct sbp_slot *s = bpf_map_lookup_elem(&scratch, &k);

		if (s && __sync_val_compare_and_swap(&s->busy, 0, 1) == 0)
			return s;
	}
	return NULL;
}

SEC("fentry/security_file_open")
int BPF_PROG(sbp_open_fentry, struct file *file)
{
	struct inode *inode;
	struct obj_ent *oe;
	struct file_ent *fe;
	struct sbp_slot *s;
	__u32 fflags;

	if (!ours())
		return 0;
	count(H_FENTRY_RUNS);
	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;
	if (BPF_CORE_READ(file, f_mode) & SBP_FMODE_BACKING)
		return write_backing(file, inode);

	s = claim();
	if (s) {
		struct sbp_rec *r = &s->rec;
		__u32 size;
		long rc;

		fill_open(r, file, inode, &oe, &fe);
		size = SBP_FIXED + r->path_len;
		if (size > sizeof(*r))
			size = sizeof(*r);
		r->len = size;
		fflags = r->fflags;
		rc = bpf_ringbuf_output(&ring, r, size, 0);
		asm volatile("" ::: "memory");
		s->busy = 0;
		if (rc)
			count(H_OUTPUT_FAILED);
		else
			opened(fe, oe, fflags);
	} else {
		struct sbp_rec *r;

		count(H_CLAIM_FAILED);
		r = bpf_ringbuf_reserve(&ring, sizeof(*r), 0);
		if (!r) {
			count(H_RESERVE_FAILED);
			return 0;
		}
		fill_open(r, file, inode, &oe, &fe);
		r->fflags |= SBP_F_FULL_SIZE;
		r->len = sizeof(*r);
		fflags = r->fflags;
		bpf_ringbuf_submit(r, 0);
		opened(fe, oe, fflags);
	}
	if (fe) {
		if (fe->state & ST_SESSION_ENTRY)
			count(H_SESSION_FIRST);
		__sync_fetch_and_or(&fe->state, ST_FENTRY_RAN);
	}
	return 0;
}

/* A record from the session return, without a path: OPEN with PATH_MISSING, or OPEN_VERDICT. */
static __always_inline void session_write(struct file *file, struct file_ent *fe, __u16 type, int verdict)
{
	struct sbp_rec *r = bpf_ringbuf_reserve(&ring, SBP_FIXED, 0);
	struct inode *inode;
	struct obj_ent *oe = NULL;

	if (!r) {
		count(H_RESERVE_FAILED);
		return;
	}
	zero_fixed(r);
	fill_hdr(r, type);
	r->len = SBP_FIXED;
	r->fid = fe->fid;
	r->verdict = verdict;
	if (type == SBP_OPEN) {
		inode = BPF_CORE_READ(file, f_inode);
		r->fflags |= SBP_F_PATH_MISSING;
		read_facts(inode, &r->facts, &r->fflags);
		r->obj = obj_of(inode, &r->facts, &r->fflags, SBP_F_OBJ_NEW, &oe);
		r->f_flags = BPF_CORE_READ(file, f_flags);
		r->f_mode = BPF_CORE_READ(file, f_mode);
	} else {
		r->obj = fe->obj;
	}
	{
		__u32 fl = r->fflags;

		bpf_ringbuf_submit(r, 0);
		facts_done(oe, fl, SBP_F_OBJ_NEW);
	}
}

SEC("kprobe.session/security_file_open")
int sbp_open_session(struct pt_regs *ctx)
{
	__u64 *cookie = bpf_session_cookie(ctx);
	struct file *file;
	struct file_ent *fe;
	__u64 key;
	int ret;

	if (!bpf_session_is_return(ctx)) {
		struct inode *inode;
		struct sbp_facts f = {};
		struct obj_ent *oe;
		__u32 fl = 0;
		int created;

		if (!ours())
			return 1;   /* not the harness: no return run */
		count(H_SESSION_ENTRY);
		file = (struct file *)PT_REGS_PARM1(ctx);
		*cookie = (__u64)file;
		inode = BPF_CORE_READ(file, f_inode);
		if (!inode)
			return 0;
		read_facts(inode, &f, &fl);
		fe = file_ent_get(file, inode, obj_of(inode, &f, &fl, SBP_F_OBJ_NEW, &oe), &created);
		if (fe) {
			if (fe->state & ST_FENTRY_RAN)
				count(H_FENTRY_FIRST);
			__sync_fetch_and_or(&fe->state, ST_SESSION_ENTRY);
		}
		return 0;
	}
	count(H_SESSION_RETURN);
	key = *cookie;
	if (!key) {
		count(H_NOCOOKIE);
		return 0;
	}
	file = (struct file *)key;
	fe = bpf_map_lookup_elem(&files, &key);
	if (!fe) {
		count(H_RET_NO_ENTRY);
		return 0;
	}
	ret = (int)PT_REGS_RC(ctx);
	if (!(fe->state & ST_FENTRY_RAN)) {
		count(H_MISSING);
		session_write(file, fe, SBP_OPEN, ret);
	} else if (ret) {
		count(H_VERDICT);
		session_write(file, fe, SBP_VERDICT, ret);
	} else {
		count(H_COMMON);
	}
	return 0;
}

SEC("kprobe.multi/security_file_free")
int sbp_file_free(struct pt_regs *ctx)
{
	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
	__u64 key = (__u64)file;
	struct file_ent *fe = bpf_map_lookup_elem(&files, &key);
	struct sbp_rec *r;

	if (!fe) {
		count(H_FREE_UNREGISTERED);
		return 0;
	}
	r = bpf_ringbuf_reserve(&ring, SBP_FIXED, 0);
	if (r) {
		zero_fixed(r);
		fill_hdr(r, SBP_CLOSE);
		r->len = SBP_FIXED;
		r->fid = fe->fid;
		r->obj = fe->obj;
		r->f_mode = BPF_CORE_READ(file, f_mode);
		if (!(r->f_mode & SBP_FMODE_OPENED))
			r->fflags |= SBP_F_NEVER_OPENED;
		bpf_ringbuf_submit(r, 0);
		count(H_CLOSE);
	} else {
		count(H_CLOSE_LOST);
	}
	bpf_map_delete_elem(&files, &key);
	return 0;
}

SEC("kprobe.multi/security_inode_free")
int sbp_inode_free(struct pt_regs *ctx)
{
	__u64 key = PT_REGS_PARM1(ctx);

	if (!bpf_map_delete_elem(&objs, &key))
		count(H_INODE_FREE_HIT);
	return 0;
}

SEC("iter/task_file")
int sbp_fd_iter(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	struct inode *inode;
	struct obj_ent *oe;
	struct file_ent *fe;
	struct sbp_rec *r;
	__u32 zero = 0, size;
	int created;

	if (!task || !file || task->tgid != harness_tgid)
		return 0;
	r = bpf_map_lookup_elem(&iter_buf, &zero);
	if (!r)
		return 0;
	inode = file->f_inode;
	if (!inode)
		return 0;
	zero_fixed(r);
	fill_hdr(r, SBP_FD);
	r->tgid = task->tgid;      /* the descriptor's owner, not the reader */
	r->tid = task->pid;
	r->fd = ctx->fd;
	read_facts(inode, &r->facts, &r->fflags);
	r->obj = obj_of(inode, &r->facts, &r->fflags, SBP_F_OBJ_NEW, &oe);
	fe = file_ent_get(file, inode, r->obj, &created);
	if (fe && !created)
		count(H_FD_DUP);
	r->fid = fe ? fe->fid : 0;
	r->f_flags = file->f_flags;
	r->f_mode = file->f_mode;
	r->pos = file->f_pos;
	r->path_len = fill_path(r, file);
	size = SBP_FIXED + r->path_len;
	if (size > sizeof(*r))
		size = sizeof(*r);
	r->len = size;
	if (bpf_seq_write(seq, r, size)) {
		count(H_FD_WRITE_FAILED);
		return 0;
	}
	count(H_FD_ROWS);
	facts_done(oe, r->fflags, SBP_F_OBJ_NEW);
	return 0;
}
