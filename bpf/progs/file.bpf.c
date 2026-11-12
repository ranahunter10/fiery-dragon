// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * file.bpf.c: file identity (ADR-0015 rules 1-9, ADR-0027, STATE decision 19), proven by the step 2a
 * dry run (bpf/test/sliceb_probe, E-0145, E-0146):
 *   fentry/security_file_open          OPEN with bpf_d_path, built in a per-call claimed scratch slot
 *                                       and copied to the bulk ring at its exact size; a full-size,
 *                                       zeroed reservation when no slot is free; BACKING instead for an
 *                                       FMODE_BACKING file (overlayfs)
 *   kprobe.session/security_file_open  entry: registers the open file (its object is filled in by
 *                                       whichever program computes it), so both programs name one fid;
 *                                       return: OPEN_VERDICT if the LSM denied; if the fentry did not
 *                                       run (E-0189), OPEN with the walked path (PATH_WALKED, ADR-0029)
 *                                       and the facts, or BACKING for an overlay's real file
 *   kprobe.multi/security_file_free    CLOSE (NEVER_OPENED, KTHREAD) and the open-file entry's end
 *   kprobe.multi/security_inode_free   the object entry's end
 * Kernel fields are read with direct loads, not bpf_probe_read_kernel: the fentry's argument and
 * bpf_get_current_task_btf() are BTF pointers, and the kprobes cast theirs with bpf_core_cast; the
 * verifier turns each load into one exception-protected load instead of a helper call (E-0190).
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
#include "p15_snap.h"
#include "p15_prof.h"   /* empty unless -DP15_PROFILE (bench/open_sections) */
#include "p15_dpath.h"  /* the bounded dentry walk (ADR-0029) */

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

/* The session return's OPEN, built whole with the walked path (ADR-0029 rule 5): one slot per CPU,
 * no claim, because a kprobe.session program never runs twice at once on a CPU (a nested run is
 * skipped and counted in its missed). 256 bytes beyond OPEN_BUF: the walk bounds each copy by a
 * mask, not by the bytes left (p15_dpath.h). */
struct walk_slot {
	struct p15_dp_scratch dp;
	__u8 rec[OPEN_BUF + 256];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct walk_slot);
} walk_scratch SEC(".maps");

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
	return !!(bpf_get_current_task_btf()->flags & PF_KTHREAD);
}

static __always_inline void fill_hdr(struct p15_hdr *h, __u16 type, __u16 version)
{
	struct task_struct *t = bpf_get_current_task_btf();

	h->type = type;
	h->version = version;
	h->flags = 0;
	h->ts_ns = bpf_ktime_get_boot_ns();
	h->tgid = t->tgid;
	h->tid = t->pid;
	h->start_ns = t->group_leader->start_boottime;
}

static __always_inline void read_facts(struct inode *inode, struct p15_part_objfacts *f)
{
	struct super_block *sb = inode->i_sb;

	f->ino = inode->i_ino;
	f->dev = sb->s_dev;
	f->gen = inode->i_generation;
	f->mode = inode->i_mode;
	f->fs_magic = (__u32)sb->s_magic;
	f->nlink = inode->__i_nlink;
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

/* The open-file entry of the file at `key` (rule 1), created if absent; NULL when the map is full
 * (counted). *created: 1 if this call inserted it. obj 0 means "not computed yet": the session's
 * entry registers the file before anyone has read the inode's facts, and the first caller that has
 * the object fills it in (both compute the same id for one inode). */
static __always_inline struct file_ent *file_ent_get_key(__u64 key, struct inode *inode, __u64 obj, int *created)
{
	struct file_ent *e = bpf_map_lookup_elem(&files, &key);
	long rc;

	if (e && e->inode != (__u64)inode) {
		count(P15_FC_FILE_STALE);
		if (!bpf_map_delete_elem(&files, &key))
			count_add(P15_FC_FILES_LIVE, (__u64)-1);
		e = NULL;
	}
	if (e) {
		if (!e->obj && obj)
			e->obj = obj;
		return e;
	}
	{
		struct file_ent n = { .fid = new_id(), .obj = obj, .inode = (__u64)inode };

		rc = bpf_map_update_elem(&files, &key, &n, BPF_NOEXIST);
		if (!rc) {
			count(P15_FC_FILES_LIVE);
			*created = 1;
		} else if (rc == -EEXIST) {
			count(P15_FC_FILE_RACE);
		}
	}
	e = bpf_map_lookup_elem(&files, &key);
	if (!e)
		count(P15_FC_FILE_MAP_FULL);
	else if (!e->obj && obj)
		e->obj = obj;   /* lost the insert race to the session's entry */
	return e;
}

static __always_inline struct file_ent *file_ent_get_c(struct file *file, struct inode *inode, __u64 obj, int *created)
{
	return file_ent_get_key((__u64)file, inode, obj, created);
}

static __always_inline struct file_ent *file_ent_get(struct file *file, struct inode *inode, __u64 obj)
{
	int created = 0;

	return file_ent_get_key((__u64)file, inode, obj, &created);
}

/* OPEN into buf (a claimed slot, a full-size reservation zeroed by the caller, or the session
 * return's walk slot): fixed part, the facts when they must travel, the path. Returns the record's
 * length padded to 8. With zero_pad the padding bytes after the path are zeroed (a slot holds
 * whatever its last record left). dps NULL: the path is bpf_d_path's (the fentry); otherwise the
 * walk's, in dps's scratch (the session return, ADR-0029), and buf has 256 bytes beyond OPEN_BUF. */
static __always_inline __u32 build_open(__u8 *buf, struct file *file, struct inode *inode, struct obj_ent **oe,
					struct file_ent **fe, int *carried, int zero_pad, struct p15_dp_scratch *dps)
{
	struct p15_open *r = (void *)buf;
	struct p15_part_objfacts f;
	__u32 off = sizeof(struct p15_open), plen, len;
	long n;

	__builtin_memset(r, 0, sizeof(*r));
	PROF_T(t_hdr);
	fill_hdr(&r->h, P15_T_OPEN, P15_OPEN_VERSION);
	PROF_ADD(P15_PROF_OPEN_HDR, t_hdr);
	PROF_T(t_facts);
	read_facts(inode, &f);
	PROF_ADD(P15_PROF_OPEN_FACTS, t_facts);
	PROF_T(t_obj);
	r->obj = obj_of(inode, &f, oe, carried);
	PROF_ADD(P15_PROF_OPEN_OBJ, t_obj);
	PROF_T(t_file);
	*fe = file_ent_get(file, inode, r->obj);
	PROF_ADD(P15_PROF_OPEN_FILE, t_file);
	r->fid = *fe ? (*fe)->fid : new_id();
	r->f_flags = file->f_flags;
	r->f_mode = file->f_mode;
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
	if (dps) {
		/* the walk (ADR-0029 rules 1-3): the same string as bpf_d_path, or a flag that says why not */
		__u32 dpf = 0;

		plen = p15_dpath(&file->f_path, (char *)(buf + off), dps, &dpf) & (P15_PATH_MAX - 1);
		if ((dpf & P15_DP_NO_ROOT) || ((dpf & P15_DP_DNAME) && !(dpf & P15_DP_SYNTH))) {
			plen = 0;
			r->path_full = 0;
			r->fflags |= P15_FF_PATH_MISSING;
		} else {
			r->fflags |= P15_FF_PATH_WALKED;
			if (dpf & P15_DP_RACED)
				r->fflags |= P15_FF_PATH_RACED;
			if (dpf & P15_DP_TRUNCATED) {
				r->path_full = P15_LEN_UNKNOWN;
				r->h.flags |= P15_F_TRUNCATED;
			} else {
				r->path_full = plen;
			}
		}
		goto have_path;
	}
	/* bpf_d_path (allowed on security_file_open, K10): the kernel's own path */
	PROF_T(t_dpath);
	n = bpf_d_path(&file->f_path, (char *)(buf + off), P15_PATH_MAX);
	PROF_ADD(P15_PROF_OPEN_DPATH, t_dpath);
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
have_path:
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

/* BACKING (rule 4): the real file and the overlay object it stands for. From the fentry, or from the
 * session return when the fentry was skipped (ADR-0029 rule 4): each counts in its own slots. */
static __always_inline int write_backing(struct file *file, struct inode *inode, __u32 emitted, __u32 lost)
{
	struct backing_file *bf = (void *)((char *)file - bpf_core_field_offset(struct backing_file, file));
	/* bf is computed, not a BTF pointer: read through the helper, then cast for read_facts' direct
	 * loads. The NULL test is on the scalar: a cast pointer is one the verifier takes as non-NULL. */
	void *uraw = BPF_CORE_READ(bf, user_path.dentry, d_inode);
	struct inode *uinode = uraw ? bpf_core_cast(uraw, struct inode) : NULL;
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
		count(lost);
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
	r->f_flags = file->f_flags;
	r->f_mode = file->f_mode;
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
	count(emitted);
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

	PROF_T(t_empty);
	PROF_ADD(P15_PROF_EMPTY, t_empty);
	PROF_T(t_all);
	count(P15_FC_FENTRY_RUN);
	inode = file->f_inode;
	if (!inode) {
		count(P15_FC_FENTRY_NO_INODE);
		return 0;
	}
	if (file->f_mode & P15_FMODE_BACKING)
		return write_backing(file, inode, P15_FC_BACKING_EMITTED, P15_FC_BACKING_LOST);

	PROF_T(t_claim);
	s = claim();
	PROF_ADD(P15_PROF_OPEN_CLAIM, t_claim);
	if (s) {
		long rc;

		len = build_open(s->rec, file, inode, &oe, &fe, &carried, 1, NULL);
		if (len > P15_OPEN_MAX_SIZE)
			len = P15_OPEN_MAX_SIZE;
		PROF_T(t_out);
		rc = bpf_ringbuf_output(&bulk_rb, s->rec, len, wake());
		PROF_ADD(P15_PROF_OPEN_OUTPUT, t_out);
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
		build_open(r, file, inode, &oe, &fe, &carried, 0, NULL);
		((struct p15_open *)r)->fflags |= P15_FF_FULL_SIZE;
		((struct p15_open *)r)->h.len = P15_OPEN_MAX_SIZE;
		bpf_ringbuf_submit(r, wake());
		count(P15_FC_OPEN_EMITTED);
		count(P15_FC_OPEN_FULL_SIZE);
	}
	facts_done(oe, carried);
	if (fe)
		__sync_fetch_and_or(&fe->state, ST_FENTRY_RAN);
	PROF_ADD(P15_PROF_OPEN_ALL, t_all);
	return 0;
}

/* The session return's records: OPEN with PATH_MISSING (and the facts if they must travel), or
 * OPEN_VERDICT. */
static __always_inline void write_missing(struct file *file, struct file_ent *fe, int verdict)
{
	struct inode *inode = file->f_inode;
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
	if (!fe->obj)
		fe->obj = r->obj;   /* the session's entry left it for the program that reads the facts */
	r->fid = fe->fid;
	r->fflags = P15_FF_PATH_MISSING | (kthread() ? P15_FF_KTHREAD : 0);
	r->f_flags = file->f_flags;
	r->f_mode = file->f_mode;
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
	count(P15_FC_WALK_UNNAMED);
	facts_done(oe, carry);
}

/* The session return's OPEN with the walked path (ADR-0029), built whole in the CPU's walk slot and
 * copied at its exact size. Without the slot (never expected): OPEN with PATH_MISSING. */
static __always_inline void write_walked(struct file *file, struct file_ent *fe, int verdict)
{
	struct inode *inode = file->f_inode;
	struct obj_ent *oe = NULL;
	struct file_ent *fe2 = NULL;
	struct walk_slot *ws;
	struct p15_open *r;
	__u32 zero = 0, len;
	int carried = 0;

	ws = bpf_map_lookup_elem(&walk_scratch, &zero);
	if (!ws) {
		write_missing(file, fe, verdict);
		return;
	}
	len = build_open(ws->rec, file, inode, &oe, &fe2, &carried, 1, &ws->dp);
	if (len > P15_OPEN_MAX_SIZE)
		len = P15_OPEN_MAX_SIZE;
	r = (struct p15_open *)ws->rec;
	r->verdict = verdict;
	if (bpf_ringbuf_output(&bulk_rb, ws->rec, len, wake())) {
		count(P15_FC_MISSING_LOST);
		return;
	}
	count(P15_FC_MISSING_EMITTED);
	if (r->fflags & P15_FF_PATH_WALKED) {
		count(P15_FC_WALKED);
		if (r->fflags & P15_FF_PATH_RACED)
			count(P15_FC_WALK_RACED);
		if (r->h.flags & P15_F_TRUNCATED)
			count(P15_FC_WALK_TRUNCATED);
	} else {
		count(P15_FC_WALK_UNNAMED);
	}
	facts_done(oe, carried);
}

static __always_inline void write_verdict(struct file_ent *fe, int verdict, __u32 emitted, __u32 lost)
{
	struct p15_open_verdict *r = bpf_ringbuf_reserve(&bulk_rb, sizeof(*r), 0);

	if (!r) {
		count(lost);
		return;
	}
	__builtin_memset(r, 0, sizeof(*r));
	fill_hdr(&r->h, P15_T_OPEN_VERDICT, P15_OPEN_VERDICT_VERSION);
	r->h.len = sizeof(*r);
	r->fid = fe->fid;
	r->verdict = verdict;
	r->fflags = kthread() ? P15_FF_KTHREAD : 0;
	bpf_ringbuf_submit(r, wake());
	count(emitted);
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
		struct inode *inode;
		int created = 0;

		PROF_T(t_sess);
		count(P15_FC_SESSION_ENTRY);
		key = PT_REGS_PARM1(ctx);
		*cookie = key;
		file = bpf_core_cast((void *)key, struct file);
		inode = file->f_inode;
		if (!inode) {
			count(P15_FC_SESSION_NO_INODE);
			return 1;   /* no return run */
		}
		/* only the registration, so the fentry and the return name one fid; the facts and the
		 * object are read by the program that writes the record (E-0188: they cost 65 ns here) */
		PROF_T(t_sfile);
		fe = file_ent_get_key(key, inode, 0, &created);
		PROF_ADD(P15_PROF_SESS_FILE, t_sfile);
		if (fe)
			__sync_fetch_and_or(&fe->state, ST_SESSION_ENTRY);
		PROF_ADD(P15_PROF_SESS_ENTRY, t_sess);
		return 0;
	}
	PROF_T(t_ret);
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
	if (!(fe->state & ST_FENTRY_RAN)) {
		file = bpf_core_cast((void *)key, struct file);
		if (file->f_mode & P15_FMODE_BACKING) {
			/* an overlay's real file: BACKING as the fentry would have written (ADR-0029 rule 4) */
			count(P15_FC_RET_BACKING);
			write_backing(file, file->f_inode, P15_FC_RET_BACKING_EMITTED, P15_FC_RET_BACKING_LOST);
			if (ret)
				write_verdict(fe, ret, P15_FC_RET_BACKING_VERDICT_EMITTED, P15_FC_RET_BACKING_VERDICT_LOST);
		} else {
			write_walked(file, fe, ret);
		}
	} else if (ret)
		write_verdict(fe, ret, P15_FC_VERDICT_EMITTED, P15_FC_VERDICT_LOST);
	else
		count(P15_FC_SESSION_COMMON);
	PROF_ADD(P15_PROF_SESS_RETURN, t_ret);
	return 0;
}

SEC("kprobe.multi/security_file_free")
int file_free(struct pt_regs *ctx)
{
	__u64 key = PT_REGS_PARM1(ctx);
	struct file *file = bpf_core_cast((void *)key, struct file);
	struct file_ent *fe;
	struct p15_close *r;

	PROF_T(t_free);
	count(P15_FC_FREE_RUN);
	PROF_T(t_flook);
	fe = bpf_map_lookup_elem(&files, &key);
	PROF_ADD(P15_PROF_FREE_LOOKUP, t_flook);
	if (!fe) {
		count(P15_FC_FREE_UNREGISTERED);
		return 0;
	}
	PROF_T(t_fring);
	r = bpf_ringbuf_reserve(&bulk_rb, sizeof(*r), 0);
	if (r) {
		__builtin_memset(r, 0, sizeof(*r));
		fill_hdr(&r->h, P15_T_CLOSE, P15_CLOSE_VERSION);
		r->h.len = sizeof(*r);
		r->fid = fe->fid;
		r->obj = fe->obj;
		r->f_mode = file->f_mode;
		if (!(r->f_mode & P15_FMODE_OPENED))
			r->fflags |= P15_FF_NEVER_OPENED;
		if (kthread())
			r->fflags |= P15_FF_KTHREAD;
		bpf_ringbuf_submit(r, wake());
		count(P15_FC_CLOSE_EMITTED);
	} else {
		count(P15_FC_CLOSE_LOST);
	}
	PROF_ADD(P15_PROF_FREE_RING, t_fring);
	PROF_T(t_fdel);
	if (!bpf_map_delete_elem(&files, &key))
		count_add(P15_FC_FILES_LIVE, (__u64)-1);
	PROF_ADD(P15_PROF_FREE_DELETE, t_fdel);
	PROF_ADD(P15_PROF_FREE_ALL, t_free);
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

/* ---- the snapshot's FD pass (ADR-0015 rule 7) ----
 *
 * iter/task_file over every fd table: the kernel shows each (task, fd) once and skips threads that
 * share their leader's table (kernel/bpf/task_iter.c lines 80 and 126, v7.0). For each descriptor
 * one FD record: the descriptor's process (not the reader's), the open file's id (registered now
 * if capture has not seen it: the first registration wins, rule 7), its object with the facts
 * always present, the offset and the kernel's path. The iterator holds a reference on the file
 * while the program runs, so the free that would end the id cannot race the row.
 *
 * p15d runs one pass at a time from one thread (daemon/snapshot.c), so the books and the buffer
 * are plain globals and one per-CPU slot; the program runs with migration off. Books:
 * bpf/include/p15_snap.h struct p15_fd_books; every early return has one. */
struct p15_fd_books fd_books;
__u32 fd_snap_id;

#define FD_BUF (P15_FD_MAX_SIZE + 8)

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[FD_BUF]);
} fd_scratch SEC(".maps");

static __always_inline void fd_inc(__u64 *c)
{
	__sync_fetch_and_add(c, 1);
}

/* The FD row's facts are always in the record; mark them written in this epoch (without the
 * duplicate count of facts_done: an FD row carries them whatever was written before). */
static __always_inline void fd_facts_mark(struct obj_ent *e)
{
	__u32 cur = facts_epoch, old;

	if (!e)
		return;
	old = e->facts_epoch;
	if (old != cur)
		__sync_val_compare_and_swap(&e->facts_epoch, old, cur);
}

SEC("iter/task_file")
int file_fd_iter(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	struct p15_part_objfacts *f;
	struct obj_ent *oe = NULL;
	struct file_ent *fe;
	struct inode *inode;
	struct p15_fd *r;
	__u32 zero = 0, off, plen, len;
	int carry, created = 0;
	__u8 *buf;
	long n;

	if (!task || !file)
		return 0;   /* the iterator's end-of-output call (ctx->task NULL): not a descriptor */
	fd_inc(&fd_books.files);
	inode = file->f_inode;
	buf = bpf_map_lookup_elem(&fd_scratch, &zero);
	if (!inode || !buf) {
		fd_inc(&fd_books.no_inode);
		return 0;
	}
	r = (void *)buf;
	__builtin_memset(r, 0, sizeof(*r));
	r->h.type = P15_T_FD;
	r->h.version = P15_FD_VERSION;
	r->h.ts_ns = bpf_ktime_get_boot_ns();
	r->h.tgid = task->tgid;
	r->h.tid = task->pid;
	r->h.start_ns = task->group_leader->start_boottime;
	r->fd = ctx->fd;
	r->snap_id = fd_snap_id;
	r->f_flags = file->f_flags;
	r->f_mode = file->f_mode;
	r->pos = file->f_pos;

	off = sizeof(*r);
	f = (void *)(buf + off);
	read_facts(inode, f);
	f->seen = P15_SEEN_SNAPSHOT;
	r->facts_len = r->facts_full = sizeof(*f);
	off += sizeof(*f);
	r->obj = obj_of(inode, f, &oe, &carry);
	fe = file_ent_get_c(file, inode, r->obj, &created);
	r->fid = fe ? fe->fid : new_id();

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
	} else {
		plen = 0;
		r->fflags |= P15_FF_PATH_ERROR;
		r->path_err = (__s32)n;
	}
	r->path_len = plen;
	len = off + plen;
	{
		__u32 end = (len + 7) & ~7u;

		for (__u32 i = 0; i < 8; i++) {
			__u32 p = len + i;

			if (p < end && p < FD_BUF)
				buf[p] = 0;   /* the slot holds the last row's bytes */
		}
		len = end;
	}
	if (len > P15_FD_MAX_SIZE)
		len = P15_FD_MAX_SIZE;
	r->h.len = len;
	if (bpf_seq_write(seq, buf, len)) {
		fd_inc(&fd_books.write_failed);
		return 0;
	}
	fd_inc(&fd_books.emitted);
	if (!fe)
		fd_inc(&fd_books.map_full);
	else if (created)
		fd_inc(&fd_books.registered);
	else
		fd_inc(&fd_books.known);
	if (r->fflags & P15_FF_PATH_ERROR)
		fd_inc(&fd_books.path_error);
	if (r->h.flags & P15_F_TRUNCATED)
		fd_inc(&fd_books.truncated);
	fd_facts_mark(oe);
	return 0;
}
