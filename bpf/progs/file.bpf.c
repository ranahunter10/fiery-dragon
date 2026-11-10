// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * file.bpf.c: file identity (ADR-0015 rules 1-9, ADR-0027, STATE decision 19), proven by the step 2a
 * dry run (bpf/test/sliceb_probe, E-0145, E-0146):
 *   fentry/security_file_open          OPEN with bpf_d_path, built in a per-call claimed scratch slot
 *                                       and copied to the bulk ring at its exact size; a full-size,
 *                                       zeroed reservation when no slot is free; BACKING instead for an
 *                                       FMODE_BACKING file (overlayfs)
 *   kprobe.session/security_file_open  entry: registers the open file and its object, so both programs
 *                                       name one fid whichever runs first; return: OPEN_VERDICT if the
 *                                       LSM denied, OPEN with PATH_MISSING if the fentry did not run
 *   kprobe.multi/security_file_free    CLOSE (NEVER_OPENED, KTHREAD) and the open-file entry's end
 *   kprobe.multi/security_inode_free   the object entry's end
 * Opens are not filtered (decision 19.3). Records go to the bulk ring this object owns; NET reuses it
 * (decision 19.4). Counters: bpf/include/p15_file.h, one per early return.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "p15_counters.h"
#include "p15_file.h"
#include "p15_records.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ENAMETOOLONG 36
#define EEXIST 17
#define PF_KTHREAD 0x00200000   /* include/linux/sched.h */

/* The bulk ring (ADR-0004 rule 4), 4 MiB by default; the loader sizes it before load. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 << 20);
} bulk_rb SEC(".maps");

const volatile __u64 file_wake_bytes = 1 << 20;   /* the ring's high-water mark (ADR-0020 rule 2) */

/* The identity counters (ADR-0026 rows, named slots: p15_file.h). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, P15_CTR_ENTRIES(0));
	__type(key, __u32);
	__type(value, __u64);
} file_counters SEC(".maps");
const volatile __u32 file_counters_ncpu = 0;

__u64 next_id;   /* the run's id counter (rule 1): 1, 2, 3, ...; shared by objects and open files */

/* The facts epoch. An object's facts are written once per epoch. p15d adds one (through the mapped
 * .data, no system call: ADR-0026) after its load-time self-tests, whose reader throws away every
 * record it takes: without it, an object first opened by any process during the self-tests would
 * have its facts marked written and never appear in the WAL (E-0151). */
volatile __u32 facts_epoch = 1;

#define ST_SESSION_ENTRY (1u << 0)
#define ST_FENTRY_RAN (1u << 1)

struct file_ent {
	__u64 fid;
	__u64 obj;
	__u64 inode;   /* the inode address, compared on every lookup (rule 9) */
	__u32 state;
	__u32 pad;
};

struct obj_ent {
	__u64 obj;
	__u64 ino;
	__u32 dev;
	__u32 gen;
	__u32 facts_epoch;     /* the epoch in which a record carrying the facts was submitted; 0: never
				* (decision 19.7) */
	__u32 pad;
};

/* Plain preallocated hashes, not LRU (rule 9): a full map is counted, never evicted silently. The
 * loader sets the sizes (decision 19.6). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, P15_FILE_MAP_DEFAULT);
	__type(key, __u64);
	__type(value, struct file_ent);
} files SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, P15_OBJ_MAP_DEFAULT);
	__type(key, __u64);
	__type(value, struct obj_ent);
} objs SEC(".maps");

/* The OPEN being built, whole: fixed part, optional facts, path, and room for the padding. */
#define OPEN_BUF (P15_OPEN_MAX_SIZE + 8)

struct path_slot {
	__u32 busy;
	__u32 pad;
	__u8 rec[OPEN_BUF];
};

/* The fentry runs preemptible with migration off: a slot is this CPU's for the call, and a task
 * preempting another on the CPU claims another slot (E-0097; dry run case claim_fail). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, P15_PATH_SLOTS);
	__type(key, __u32);
	__type(value, struct path_slot);
} path_scratch SEC(".maps");

/* btrfs is a module: matched against its BTF if it was loaded at load time (rule 2, V6). */
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

static __always_inline void count_add(__u32 slot, __u64 v)
{
	__u32 row = bpf_get_smp_processor_id(), k;
	__u64 *c;

	if (row > file_counters_ncpu)
		row = file_counters_ncpu;   /* a CPU at or above ncpu: the last row */
	k = P15_CTR_SLOT(row, slot);
	c = bpf_map_lookup_elem(&file_counters, &k);
	/* atomic: the fentry is preemptible, so two programs may interleave on one CPU (E-0097) */
	if (c)
		__sync_fetch_and_add(c, v);
}

static __always_inline void count(__u32 slot)
{
	count_add(slot, 1);
}

static __always_inline __u64 new_id(void)
{
	return __sync_fetch_and_add(&next_id, 1) + 1;
}

static __always_inline __u64 wake(void)
{
	return bpf_ringbuf_query(&bulk_rb, BPF_RB_AVAIL_DATA) > file_wake_bytes ? BPF_RB_FORCE_WAKEUP
										: BPF_RB_NO_WAKEUP;
}

static __always_inline int kthread(void)
{
	struct task_struct *t = bpf_get_current_task_btf();

	return !!(BPF_CORE_READ(t, flags) & PF_KTHREAD);
}

static __always_inline void fill_hdr(struct p15_hdr *h, __u16 type, __u16 version)
{
	struct task_struct *t = bpf_get_current_task_btf();

	h->type = type;
	h->version = version;
	h->flags = 0;
	h->ts_ns = bpf_ktime_get_boot_ns();
	h->tgid = BPF_CORE_READ(t, tgid);
	h->tid = BPF_CORE_READ(t, pid);
	h->start_ns = BPF_CORE_READ(t, group_leader, start_boottime);
}

static __always_inline void read_facts(struct inode *inode, struct p15_part_objfacts *f)
{
	f->ino = BPF_CORE_READ(inode, i_ino);
	f->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	f->gen = BPF_CORE_READ(inode, i_generation);
	f->mode = BPF_CORE_READ(inode, i_mode);
	f->fs_magic = (__u32)BPF_CORE_READ(inode, i_sb, s_magic);
	f->nlink = BPF_CORE_READ(inode, __i_nlink);
	f->subvol = 0;
	f->seen = P15_SEEN_OPEN;
	f->oflags = 0;
	if (f->fs_magic != P15_BTRFS_MAGIC)
		return;
	if (bpf_core_type_exists(struct btrfs_inode___p15)) {
		struct btrfs_inode___p15 *bi =
			(void *)((char *)inode - bpf_core_field_offset(struct btrfs_inode___p15, vfs_inode));

		f->subvol = BPF_CORE_READ(bi, root, root_key.objectid);
	} else {
		f->oflags = P15_OFL_SUBVOL_UNKNOWN;
		count(P15_FC_SUBVOL_UNKNOWN);
	}
}

/* The object id of inode (rule 1), registered if new. *ep: its entry, or NULL when the map is full
 * (the id is then fresh and unregistered, the facts go inline). *carry: the record must carry the
 * facts (not written yet, or no entry). */
static __always_inline __u64 obj_of(struct inode *inode, const struct p15_part_objfacts *f, struct obj_ent **ep,
				    int *carry)
{
	__u64 key = (__u64)inode;
	struct obj_ent *e = bpf_map_lookup_elem(&objs, &key);
	long rc;

	if (e && (e->ino != f->ino || e->dev != f->dev || e->gen != f->gen)) {
		count(P15_FC_OBJ_STALE);
		if (!bpf_map_delete_elem(&objs, &key))
			count_add(P15_FC_OBJS_LIVE, (__u64)-1);
		e = NULL;
	}
	if (!e) {
		struct obj_ent n = { .obj = new_id(), .ino = f->ino, .dev = f->dev, .gen = f->gen };

		rc = bpf_map_update_elem(&objs, &key, &n, BPF_NOEXIST);
		if (!rc)
			count(P15_FC_OBJS_LIVE);
		else if (rc == -EEXIST)
			count(P15_FC_OBJ_RACE);
		e = bpf_map_lookup_elem(&objs, &key);
		if (!e) {
			count(P15_FC_OBJ_MAP_FULL);   /* full, or freed in between */
			*ep = NULL;
			*carry = 1;
			return n.obj;
		}
	}
	*ep = e;
	*carry = e->facts_epoch != facts_epoch;
	return e->obj;
}

/* After the record carrying the facts was submitted (decision 19.7). */
static __always_inline void facts_done(struct obj_ent *e, int carried)
{
	__u32 cur = facts_epoch, old;

	if (!e || !carried)
		return;
	old = e->facts_epoch;
	/* compare-and-swap, the atomic the dry run proved on the target (E-0146) */
	if (old == cur || __sync_val_compare_and_swap(&e->facts_epoch, old, cur) != old)
		count(P15_FC_FACTS_DUP);
}

/* The open-file entry of file (rule 1), created if absent; NULL when the map is full (counted). */
static __always_inline struct file_ent *file_ent_get(struct file *file, struct inode *inode, __u64 obj)
{
	__u64 key = (__u64)file;
	struct file_ent *e = bpf_map_lookup_elem(&files, &key);
	long rc;

	if (e && e->inode != (__u64)inode) {
		count(P15_FC_FILE_STALE);
		if (!bpf_map_delete_elem(&files, &key))
			count_add(P15_FC_FILES_LIVE, (__u64)-1);
		e = NULL;
	}
	if (e)
		return e;
	{
		struct file_ent n = { .fid = new_id(), .obj = obj, .inode = (__u64)inode };

		rc = bpf_map_update_elem(&files, &key, &n, BPF_NOEXIST);
		if (!rc)
			count(P15_FC_FILES_LIVE);
		else if (rc == -EEXIST)
			count(P15_FC_FILE_RACE);
	}
	e = bpf_map_lookup_elem(&files, &key);
	if (!e)
		count(P15_FC_FILE_MAP_FULL);
	return e;
}

/* OPEN into buf (a claimed slot, or a full-size reservation zeroed by the caller): fixed part, the
 * facts when they must travel, the path. Returns the record's length padded to 8. With zero_pad the
 * padding bytes after the path are zeroed (a slot holds whatever its last record left). */
static __always_inline __u32 build_open(__u8 *buf, struct file *file, struct inode *inode, struct obj_ent **oe,
					struct file_ent **fe, int *carried, int zero_pad)
{
	struct p15_open *r = (void *)buf;
	struct p15_part_objfacts f;
	__u32 off = sizeof(struct p15_open), plen, len;
	long n;

	__builtin_memset(r, 0, sizeof(*r));
	fill_hdr(&r->h, P15_T_OPEN, P15_OPEN_VERSION);
	read_facts(inode, &f);
	r->obj = obj_of(inode, &f, oe, carried);
	*fe = file_ent_get(file, inode, r->obj);
	r->fid = *fe ? (*fe)->fid : new_id();
	r->f_flags = BPF_CORE_READ(file, f_flags);
	r->f_mode = BPF_CORE_READ(file, f_mode);
	if (kthread()) {
		r->fflags |= P15_FF_KTHREAD;
		count(P15_FC_KTHREAD_OPEN);
	}
	if (*carried) {
		__builtin_memcpy(buf + off, &f, sizeof(f));
		r->fflags |= P15_FF_OBJ_NEW;
		r->facts_len = r->facts_full = sizeof(f);
		off += sizeof(f);
	}
	/* bpf_d_path (allowed on security_file_open, K10): the kernel's own path */
	n = bpf_d_path(&file->f_path, (char *)(buf + off), P15_PATH_MAX);
	if (n > 0) {
		plen = (__u32)(n - 1) & (P15_PATH_MAX - 1);
		r->path_full = plen;
	} else if (n == -ENAMETOOLONG) {
		const unsigned char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
		long m = bpf_probe_read_kernel_str(buf + off, 256, name);

		plen = m > 0 ? (__u32)(m - 1) & 255 : 0;
		r->path_full = P15_LEN_UNKNOWN;
		r->h.flags |= P15_F_TRUNCATED;
		count(P15_FC_OPEN_TRUNCATED);
	} else {
		plen = 0;
		r->path_full = 0;
		r->fflags |= P15_FF_PATH_ERROR;
		r->path_err = (__s32)n;
		count(P15_FC_OPEN_PATH_ERROR);
	}
	r->path_len = plen;
	len = off + plen;
	if (zero_pad) {
		__u32 end = (len + 7) & ~7u;

		for (__u32 i = 0; i < 8; i++) {
			__u32 p = len + i;

			if (p < end && p < OPEN_BUF)
				buf[p] = 0;
		}
	}
	len = (len + 7) & ~7u;
	r->h.len = len;
	return len;
}

/* Zero a full-size OPEN reservation 8 bytes at a time: a memset this large is not inlined by
 * clang for BPF, and a bounded loop is one the verifier walks once per iteration (527). */
static __always_inline void zero_full(__u8 *r)
{
	for (__u32 i = 0; i < P15_OPEN_MAX_SIZE / 8; i++) {
		((__u64 *)r)[i] = 0;
		asm volatile("" ::: "memory");   /* keeps clang from turning the loop into a memset call */
	}
}

static __always_inline struct path_slot *claim(void)
{
	for (__u32 k = 0; k < P15_PATH_SLOTS; k++) {
		struct path_slot *s = bpf_map_lookup_elem(&path_scratch, &k);

		if (s && __sync_val_compare_and_swap(&s->busy, 0, 1) == 0)
			return s;
	}
	return NULL;
}

/* BACKING (rule 4): the real file and the overlay object it stands for. */
static __always_inline int write_backing(struct file *file, struct inode *inode)
{
	struct backing_file *bf = (void *)((char *)file - bpf_core_field_offset(struct backing_file, file));
	struct inode *uinode = BPF_CORE_READ(bf, user_path.dentry, d_inode);
	struct p15_part_objfacts f, uf;
	struct obj_ent *oe, *uoe = NULL;
	struct file_ent *fe;
	struct p15_backing *r;
	int carry, ucarry = 0;
	__u32 len = sizeof(*r);
	__u8 *tail;

	read_facts(inode, &f);
	r = bpf_ringbuf_reserve(&bulk_rb, P15_BACKING_MAX_SIZE, 0);
	if (!r) {
		count(P15_FC_BACKING_LOST);
		return 0;
	}
	__builtin_memset(r, 0, P15_BACKING_MAX_SIZE);
	fill_hdr(&r->h, P15_T_BACKING, P15_BACKING_VERSION);
	r->obj = obj_of(inode, &f, &oe, &carry);
	if (uinode) {
		read_facts(uinode, &uf);
		r->user_obj = obj_of(uinode, &uf, &uoe, &ucarry);
	} else {
		r->h.flags |= P15_F_READ_FAILED;
		count(P15_FC_BACKING_USER_UNREAD);
	}
	fe = file_ent_get(file, inode, r->obj);
	r->fid = fe ? fe->fid : new_id();
	r->f_flags = BPF_CORE_READ(file, f_flags);
	r->f_mode = BPF_CORE_READ(file, f_mode);
	if (kthread())
		r->fflags |= P15_FF_KTHREAD;
	tail = (__u8 *)(r + 1);
	if (carry) {
		__builtin_memcpy(tail, &f, sizeof(f));
		r->fflags |= P15_FF_OBJ_NEW;
		r->facts_len = r->facts_full = sizeof(f);
		len += sizeof(f);
	}
	if (ucarry) {
		__builtin_memcpy(carry ? tail + sizeof(f) : tail, &uf, sizeof(uf));
		r->fflags |= P15_FF_USER_OBJ_NEW;
		r->user_facts_len = r->user_facts_full = sizeof(uf);
		len += sizeof(uf);
	}
	r->h.len = len;
	/* reserved at the maximum: the reader takes h.len; the rest of the reservation is zero */
	bpf_ringbuf_submit(r, wake());
	count(P15_FC_BACKING_EMITTED);
	facts_done(oe, carry);
	facts_done(uoe, ucarry);
	if (fe)
		__sync_fetch_and_or(&fe->state, ST_FENTRY_RAN);
	return 0;
}

SEC("fentry/security_file_open")
int BPF_PROG(file_open_path, struct file *file)
{
	struct inode *inode;
	struct obj_ent *oe = NULL;
	struct file_ent *fe = NULL;
	struct path_slot *s;
	int carried = 0;
	__u32 len;

	count(P15_FC_FENTRY_RUN);
	inode = BPF_CORE_READ(file, f_inode);
	if (!inode) {
		count(P15_FC_FENTRY_NO_INODE);
		return 0;
	}
	if (BPF_CORE_READ(file, f_mode) & P15_FMODE_BACKING)
		return write_backing(file, inode);

	s = claim();
	if (s) {
		long rc;

		len = build_open(s->rec, file, inode, &oe, &fe, &carried, 1);
		if (len > P15_OPEN_MAX_SIZE)
			len = P15_OPEN_MAX_SIZE;
		rc = bpf_ringbuf_output(&bulk_rb, s->rec, len, wake());
		asm volatile("" ::: "memory");
		s->busy = 0;
		if (rc) {
			count(P15_FC_OPEN_LOST);
			carried = 0;
		} else {
			count(P15_FC_OPEN_EMITTED);
		}
	} else {
		__u8 *r = bpf_ringbuf_reserve(&bulk_rb, P15_OPEN_MAX_SIZE, 0);

		if (!r) {
			count(P15_FC_OPEN_LOST);
			return 0;
		}
		/* full size (rule 6): zeroed first, so every byte after the path is zero */
		zero_full(r);
		build_open(r, file, inode, &oe, &fe, &carried, 0);
		((struct p15_open *)r)->fflags |= P15_FF_FULL_SIZE;
		((struct p15_open *)r)->h.len = P15_OPEN_MAX_SIZE;
		bpf_ringbuf_submit(r, wake());
		count(P15_FC_OPEN_EMITTED);
		count(P15_FC_OPEN_FULL_SIZE);
	}
	facts_done(oe, carried);
	if (fe)
		__sync_fetch_and_or(&fe->state, ST_FENTRY_RAN);
	return 0;
}

/* The session return's records: OPEN with PATH_MISSING (and the facts if they must travel), or
 * OPEN_VERDICT. */
static __always_inline void write_missing(struct file *file, struct file_ent *fe, int verdict)
{
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	struct p15_part_objfacts f;
	struct obj_ent *oe;
	struct p15_open *r;
	int carry;
	__u32 len = sizeof(*r);

	r = bpf_ringbuf_reserve(&bulk_rb, sizeof(*r) + sizeof(f), 0);
	if (!r) {
		count(P15_FC_MISSING_LOST);
		return;
	}
	__builtin_memset(r, 0, sizeof(*r) + sizeof(f));
	fill_hdr(&r->h, P15_T_OPEN, P15_OPEN_VERSION);
	read_facts(inode, &f);
	r->obj = obj_of(inode, &f, &oe, &carry);
	r->fid = fe->fid;
	r->fflags = P15_FF_PATH_MISSING | (kthread() ? P15_FF_KTHREAD : 0);
	r->f_flags = BPF_CORE_READ(file, f_flags);
	r->f_mode = BPF_CORE_READ(file, f_mode);
	r->verdict = verdict;
	if (carry) {
		__builtin_memcpy(r + 1, &f, sizeof(f));
		r->fflags |= P15_FF_OBJ_NEW;
		r->facts_len = r->facts_full = sizeof(f);
		len += sizeof(f);
	}
	r->h.len = len;   /* the reservation is larger only by the facts it may not carry: zero */
	bpf_ringbuf_submit(r, wake());
	count(P15_FC_MISSING_EMITTED);
	facts_done(oe, carry);
}

static __always_inline void write_verdict(struct file_ent *fe, int verdict)
{
	struct p15_open_verdict *r = bpf_ringbuf_reserve(&bulk_rb, sizeof(*r), 0);

	if (!r) {
		count(P15_FC_VERDICT_LOST);
		return;
	}
	__builtin_memset(r, 0, sizeof(*r));
	fill_hdr(&r->h, P15_T_OPEN_VERDICT, P15_OPEN_VERDICT_VERSION);
	r->h.len = sizeof(*r);
	r->fid = fe->fid;
	r->verdict = verdict;
	r->fflags = kthread() ? P15_FF_KTHREAD : 0;
	bpf_ringbuf_submit(r, wake());
	count(P15_FC_VERDICT_EMITTED);
}

SEC("kprobe.session/security_file_open")
int file_open_session(struct pt_regs *ctx)
{
	__u64 *cookie = bpf_session_cookie(ctx);
	struct file_ent *fe;
	struct file *file;
	__u64 key;
	int ret;

	if (!bpf_session_is_return(ctx)) {
		struct p15_part_objfacts f;
		struct inode *inode;
		struct obj_ent *oe;
		int carry;

		count(P15_FC_SESSION_ENTRY);
		file = (struct file *)PT_REGS_PARM1(ctx);
		*cookie = (__u64)file;
		inode = BPF_CORE_READ(file, f_inode);
		if (!inode) {
			count(P15_FC_SESSION_NO_INODE);
			return 1;   /* no return run */
		}
		read_facts(inode, &f);
		fe = file_ent_get(file, inode, obj_of(inode, &f, &oe, &carry));
		if (fe)
			__sync_fetch_and_or(&fe->state, ST_SESSION_ENTRY);
		return 0;
	}
	count(P15_FC_SESSION_RETURN);
	key = *cookie;
	if (!key) {
		count(P15_FC_SESSION_NO_COOKIE);
		return 0;
	}
	fe = bpf_map_lookup_elem(&files, &key);
	if (!fe) {
		count(P15_FC_SESSION_NO_ENTRY);
		return 0;
	}
	ret = (int)PT_REGS_RC(ctx);
	if (!(fe->state & ST_FENTRY_RAN))
		write_missing((struct file *)key, fe, ret);
	else if (ret)
		write_verdict(fe, ret);
	else
		count(P15_FC_SESSION_COMMON);
	return 0;
}

SEC("kprobe.multi/security_file_free")
int file_free(struct pt_regs *ctx)
{
	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
	__u64 key = (__u64)file;
	struct file_ent *fe;
	struct p15_close *r;

	count(P15_FC_FREE_RUN);
	fe = bpf_map_lookup_elem(&files, &key);
	if (!fe) {
		count(P15_FC_FREE_UNREGISTERED);
		return 0;
	}
	r = bpf_ringbuf_reserve(&bulk_rb, sizeof(*r), 0);
	if (r) {
		__builtin_memset(r, 0, sizeof(*r));
		fill_hdr(&r->h, P15_T_CLOSE, P15_CLOSE_VERSION);
		r->h.len = sizeof(*r);
		r->fid = fe->fid;
		r->obj = fe->obj;
		r->f_mode = BPF_CORE_READ(file, f_mode);
		if (!(r->f_mode & P15_FMODE_OPENED))
			r->fflags |= P15_FF_NEVER_OPENED;
		if (kthread())
			r->fflags |= P15_FF_KTHREAD;
		bpf_ringbuf_submit(r, wake());
		count(P15_FC_CLOSE_EMITTED);
	} else {
		count(P15_FC_CLOSE_LOST);
	}
	if (!bpf_map_delete_elem(&files, &key))
		count_add(P15_FC_FILES_LIVE, (__u64)-1);
	return 0;
}

SEC("kprobe.multi/security_inode_free")
int file_inode_free(struct pt_regs *ctx)
{
	__u64 key = PT_REGS_PARM1(ctx);

	count(P15_FC_INODE_FREE_RUN);
	if (!bpf_map_delete_elem(&objs, &key)) {
		count(P15_FC_INODE_FREE_HIT);
		count_add(P15_FC_OBJS_LIVE, (__u64)-1);
	}
	return 0;
}
