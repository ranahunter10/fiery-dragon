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
#include "p15_flow.h"   /* data flow (ADR-0005, STATE decisions 18 and 47): FLOW and FILE at a transfer */

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

/* ===== data flow (ADR-0005, STATE decisions 18 and 47): FLOW per transfer, unfolded (step 2b) =====
 *
 * Four kprobe.session on vfs_read/vfs_write/vfs_readv/vfs_writev and the two classic tracepoints
 * sock:sock_send_length / sock:sock_recv_length. Every transfer is resolved to its open file's
 * struct file *, which keys the shared files map above; a file the open path never saw (pipe,
 * socket, memfd, anonymous inode, or a regular file opened before capture) is registered here and
 * gets one FILE record (ADR-0015 rule 5) carrying its object's facts, before its first FLOW.
 *
 * FLOW's start time (decision 47.1, option A): the session's cookie keeps the file pointer, and a
 * task-storage slot keeps {file, entry time}; the return reads the entry time when the stored file
 * is this call's, else START_UNKNOWN (a nested transfer overwrote the slot). The socket
 * tracepoints fire once, so their FLOW is an instant (first_ts == last_ts).
 *
 * Counters and books: bpf/include/p15_flow.h. Records go to the same bulk ring; the drain counts
 * them on the flow books (daemon/drain.c). */

const volatile __u32 flow_self_tgid;   /* p15d's own tgid: its transfers are excluded (ADR-0005). 0 = none */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, P15_CTR_ENTRIES(0));
	__type(key, __u32);
	__type(value, __u64);
} flow_counters SEC(".maps");
const volatile __u32 flow_counters_ncpu;

/* Option A's per-task slot: the file of the vfs call in progress and its entry time. One slot per
 * task; a nested transfer overwrites it, and the outer return then finds a mismatch and flags
 * START_UNKNOWN (measured below the VM's resolution, E-0237). */
struct rw_start {
	__u64 file;
	__u64 ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct rw_start);
} rw_starts SEC(".maps");

/* TEST ONLY (--test-flow-file-fail-first): the first FILE record of every file is lost as a full
 * ring would lose it, so the retry below is exercised (it_p15d case 14). Off, the verifier removes
 * the branch; the map then has one entry and is never used. On, a file whose first attempt finds
 * the map full is not failed: the test can only ever lose fewer records, never more. */
const volatile __u32 flow_test_file_fail_first;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);         /* the loader sizes it when the test switch is on */
	__type(key, __u64);
	__type(value, __u8);
} flow_test_tried SEC(".maps");

static __always_inline void flow_count(__u32 slot)
{
	__u32 row = bpf_get_smp_processor_id(), k;
	__u64 *c;

	if (row > flow_counters_ncpu)
		row = flow_counters_ncpu;
	k = P15_CTR_SLOT(row, slot);
	c = bpf_map_lookup_elem(&flow_counters, &k);
	if (c)
		__sync_fetch_and_add(c, 1);   /* preemptible: the sock tracepoints share slots with the vfs returns */
}

static __always_inline int is_self(void)
{
	return flow_self_tgid && (__u32)(bpf_get_current_pid_tgid() >> 32) == flow_self_tgid;
}

static const __u32 flow_emit_slot[5] = {   /* FLOW.kind -> its EMITTED counter */
	0, P15_FLC_READ_EMITTED, P15_FLC_WRITE_EMITTED, P15_FLC_RECV_EMITTED, P15_FLC_SEND_EMITTED,
};

/* One FILE record (ADR-0015 rule 5) for a file first seen at a transfer: its facts (always, since
 * this is the object's first record unless it raced) and the dentry's own short name, which the
 * reader turns into pipe:[ino] / socket:[ino] / the protocol from the facts. Written before this
 * program's FLOW; another thread's FLOW on the same file can reach the ring first (review V5), so
 * readers join by fid. sock_cookie is the socket's cookie as the kernel holds it, 0 for anything
 * else (ADR-0032). Returns 0 if the record was lost to a full ring (counted FILE_LOST). */
static __always_inline int write_file_rec(struct file *file, __u64 fid, __u64 obj,
					  const struct p15_part_objfacts *f, int carry, __u32 seen, __u64 sock_cookie)
{
	struct p15_file *r;
	const unsigned char *dname;
	__u32 off = sizeof(*r), full;
	long m;

	if (flow_test_file_fail_first) {
		__u64 k = (__u64)file;
		__u8 one = 1;

		if (!bpf_map_lookup_elem(&flow_test_tried, &k)) {
			if (!bpf_map_update_elem(&flow_test_tried, &k, &one, BPF_NOEXIST)) {
				flow_count(P15_FLC_FILE_LOST);   /* as the !r branch below: the planted loss */
				return 0;
			}
		} else {
			bpf_map_delete_elem(&flow_test_tried, &k);
		}
	}
	r = bpf_ringbuf_reserve(&bulk_rb, P15_FILE_MAX_SIZE, 0);
	if (!r) {
		flow_count(P15_FLC_FILE_LOST);
		return 0;
	}
	__builtin_memset(r, 0, P15_FILE_MAX_SIZE);
	fill_hdr(&r->h, P15_T_FILE, P15_FILE_VERSION);
	r->fid = fid;
	r->obj = obj;
	r->sock_cookie = sock_cookie;
	r->f_flags = file->f_flags;
	r->f_mode = file->f_mode;
	r->seen = seen;
	if (carry) {
		__builtin_memcpy((__u8 *)r + off, f, sizeof(*f));
		r->fflags |= P15_FF_OBJ_NEW;
		r->facts_len = r->facts_full = sizeof(*f);
		off += sizeof(*f);
	}
	/* The dentry's own name: at most NAME_MAX bytes, read with room for the helper's NUL (the
	 * reservation's padding holds it). Its length is the helper's count less the NUL, never
	 * masked: a mask would drop the last byte of an odd-length name and leave it behind the
	 * field, which p15_rec_check refuses. A longer name is cut and flagged TRUNCATED, with its
	 * full length from d_name.len; a failed read leaves the name empty, flagged READ_FAILED. */
	dname = BPF_CORE_READ(file, f_path.dentry, d_name.name);
	full = BPF_CORE_READ(file, f_path.dentry, d_name.len);
	m = bpf_probe_read_kernel_str((__u8 *)r + off, P15_FILE_V1_NAME_MAX + 1, dname);
	if (m > 0 && m <= P15_FILE_V1_NAME_MAX + 1) {
		r->name_len = (__u16)(m - 1);
		r->name_full = full > 0xffff ? 0xffff : (__u16)full;
		if (r->name_full < r->name_len)
			r->name_full = r->name_len;   /* d_name.len raced a rename: the bytes read are what holds */
		if (r->name_full != r->name_len)
			r->h.flags |= P15_F_TRUNCATED;
		off += r->name_len;
	} else {
		r->h.flags |= P15_F_READ_FAILED;
	}
	r->h.len = (off + 7) & ~7u;
	bpf_ringbuf_submit(r, wake());
	flow_count(P15_FLC_FILE_EMITTED);
	return 1;
}

/* Resolve the transfer's file to (fid, obj), registering a pseudo file and its FILE record on first
 * sight, and write one FLOW (schema/records.toml). kind is P15_FLOWK_*; extra holds the record's
 * fflags that the caller computed (VECTORED, PEEK, START_UNKNOWN); sock_cookie goes into the FILE
 * record if one is written (ADR-0032). Counts the kind's EMITTED, or FLOW_LOST. */
static __always_inline void emit_flow(struct file *file, struct inode *inode, __u16 kind, __u64 bytes,
				      __u64 first_ts, __u64 last_ts, __u32 extra, __u64 sock_cookie)
{
	struct p15_part_objfacts f;
	struct obj_ent *oe = NULL;
	struct file_ent *fe;
	struct p15_flow *r;
	__u64 obj, key = (__u64)file;
	int carry = 0, created = 0;
	__u32 seen = kind == P15_FLOWK_READ || kind == P15_FLOWK_WRITE ? P15_SEEN_IO : P15_SEEN_NET;

	read_facts(inode, &f);
	f.seen = seen;
	obj = obj_of(inode, &f, &oe, &carry);
	fe = file_ent_get_key(key, inode, obj, &created);
	if (fe && created) {
		if (write_file_rec(file, fe->fid, obj, &f, carry, seen, sock_cookie)) {
			facts_done(oe, carry);   /* the FILE record carried the object's facts */
		} else {
			/* the FILE was lost (counted FILE_LOST): undo the registration so the next
			 * transfer on this file registers it again and writes its FILE, and leave the
			 * object's facts unsent. This FLOW still names the fid; the reader counts a FLOW
			 * whose fid has no FILE (graph: openfile_flow). */
			__u64 fid = fe->fid;

			if (!bpf_map_delete_elem(&files, &key))
				count_add(P15_FC_FILES_LIVE, (__u64)-1);
			r = bpf_ringbuf_reserve(&bulk_rb, sizeof(*r), 0);
			if (!r) {
				flow_count(P15_FLC_FLOW_LOST);
				return;
			}
			__builtin_memset(r, 0, sizeof(*r));
			fill_hdr(&r->h, P15_T_FLOW, P15_FLOW_VERSION);
			r->fid = fid;
			r->obj = obj;
			r->fflags = extra;
			r->reason = P15_FLOWR_SINGLE;
			r->h.len = sizeof(*r);
			goto fill;
		}
	}

	if (!fe) {
		/* the files map is full: one FLOW, UNREGISTERED, carrying the facts (ADR-0015 rule 9) */
		r = bpf_ringbuf_reserve(&bulk_rb, P15_FLOW_MAX_SIZE, 0);
		if (!r) {
			flow_count(P15_FLC_FLOW_LOST);
			return;
		}
		__builtin_memset(r, 0, P15_FLOW_MAX_SIZE);
		fill_hdr(&r->h, P15_T_FLOW, P15_FLOW_VERSION);
		r->fid = new_id();
		r->obj = obj;
		r->fflags = extra | P15_FF_UNREGISTERED;
		r->reason = P15_FLOWR_MAP_FULL;
		r->h.len = sizeof(*r);
		if (carry) {   /* the object's facts have not travelled yet: inline them (ADR-0005 rule 8) */
			__builtin_memcpy((__u8 *)r + sizeof(*r), &f, sizeof(f));
			r->fflags |= P15_FF_OBJ_NEW;
			r->facts_len = r->facts_full = sizeof(f);
			r->h.len = sizeof(*r) + sizeof(f);
		}
		flow_count(P15_FLC_FILE_MAP_FULL);
		flow_count(P15_FLC_UNREGISTERED);
		goto fill;
	}
	r = bpf_ringbuf_reserve(&bulk_rb, sizeof(*r), 0);
	if (!r) {
		flow_count(P15_FLC_FLOW_LOST);
		return;
	}
	__builtin_memset(r, 0, sizeof(*r));
	fill_hdr(&r->h, P15_T_FLOW, P15_FLOW_VERSION);
	r->fid = fe->fid;
	r->obj = obj;
	r->fflags = extra;
	r->reason = P15_FLOWR_SINGLE;
	r->h.len = sizeof(*r);
fill:
	r->first_ts = first_ts;
	r->last_ts = last_ts;
	r->bytes = bytes;
	r->count = 1;
	r->kind = kind;
	if (extra & P15_FF_START_UNKNOWN)
		flow_count(P15_FLC_START_UNKNOWN);
	bpf_ringbuf_submit(r, wake());
	flow_count(flow_emit_slot[kind]);
}

/* vfs entry: exclude self and kernel threads (no return runs for them); else keep the file in the
 * cookie and the entry time in the task slot (option A). */
static __always_inline int rw_entry(struct pt_regs *ctx)
{
	__u64 *cookie = bpf_session_cookie(ctx);
	__u64 key = PT_REGS_PARM1(ctx);
	struct rw_start *st;

	flow_count(P15_FLC_SESS_ENTRY);
	if (is_self()) {
		flow_count(P15_FLC_V_EXCL_SELF);
		return 1;
	}
	if (kthread()) {
		flow_count(P15_FLC_V_EXCL_KTHREAD);
		return 1;
	}
	{
		/* a read() or write() on a socket reaches sock_recvmsg/sock_sendmsg, whose tracepoint
		 * writes the RECV or SEND (ADR-0005 rule 11): the vfs hook leaves it, so it is not
		 * recorded twice (review V2) */
		struct file *file = bpf_core_cast((void *)key, struct file);
		struct inode *inode = file->f_inode;

		if (inode && (inode->i_mode & S_IFMT) == S_IFSOCK) {
			flow_count(P15_FLC_V_OWNED_BY_SOCK);
			return 1;
		}
	}
	*cookie = key;
	st = bpf_task_storage_get(&rw_starts, bpf_get_current_task_btf(), 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (st) {
		st->file = key;
		st->ts = bpf_ktime_get_boot_ns();
	}
	return 0;
}

/* vfs return: the transfer's size is the return value; a FLOW only for ret > 0. */
static __always_inline int rw_return(struct pt_regs *ctx, __u16 kind, __u32 vectored)
{
	__u64 *cookie = bpf_session_cookie(ctx);
	__u64 file_key = *cookie, now, first;
	long ret = (long)PT_REGS_RC(ctx);
	struct file *file;
	struct inode *inode;
	struct rw_start *st;
	__u32 extra = vectored;

	flow_count(P15_FLC_SESS_RETURN);
	if (ret == 0) {
		flow_count(P15_FLC_V_EMPTY);
		return 0;
	}
	if (ret < 0) {
		flow_count(P15_FLC_V_FAILED);
		return 0;
	}
	file = bpf_core_cast((void *)file_key, struct file);
	inode = file->f_inode;
	if (!inode) {
		flow_count(P15_FLC_V_NO_INODE);
		return 0;
	}
	flow_count(P15_FLC_V_ATTEMPT);
	now = bpf_ktime_get_boot_ns();
	st = bpf_task_storage_get(&rw_starts, bpf_get_current_task_btf(), 0, 0);
	if (st && st->file == file_key) {
		first = st->ts;
		st->file = 0;   /* used: a later return without its entry cannot match it */
	} else {
		first = now;
		extra |= P15_FF_START_UNKNOWN;
	}
	emit_flow(file, inode, kind, (__u64)ret, first, now, extra, 0);   /* not a socket: rule 11 */
	return 0;
}

SEC("kprobe.session/vfs_read")
int flow_read(struct pt_regs *ctx)
{
	return bpf_session_is_return(ctx) ? rw_return(ctx, P15_FLOWK_READ, 0) : rw_entry(ctx);
}

SEC("kprobe.session/vfs_write")
int flow_write(struct pt_regs *ctx)
{
	return bpf_session_is_return(ctx) ? rw_return(ctx, P15_FLOWK_WRITE, 0) : rw_entry(ctx);
}

SEC("kprobe.session/vfs_readv")
int flow_readv(struct pt_regs *ctx)
{
	return bpf_session_is_return(ctx) ? rw_return(ctx, P15_FLOWK_READ, P15_FF_VECTORED) : rw_entry(ctx);
}

SEC("kprobe.session/vfs_writev")
int flow_writev(struct pt_regs *ctx)
{
	return bpf_session_is_return(ctx) ? rw_return(ctx, P15_FLOWK_WRITE, P15_FF_VECTORED) : rw_entry(ctx);
}

/* sock:sock_send_length / sock:sock_recv_length (design checks D5-D7). Classic tracepoints: the
 * kernel runs them with preemption off, so they are not skipped for other tasks. The context's
 * fields are not in the dev container's vmlinux.h; CO-RE relocates them against the target's BTF
 * (the 7.0 kernel has the type). send always passes flags 0; recv passes the receive flags, so
 * MSG_PEEK is visible (D5). */
struct trace_event_raw_sock_msg_length___p15 {
	struct trace_entry ent;
	void *sk;
	__u16 family;
	__u16 protocol;
	int ret;
	int flags;
} __attribute__((preserve_access_index));

static __always_inline int sock_flow(__u64 sk_addr, long ret, int msg_flags, __u16 kind)
{
	/* the tracepoint gives the sock's address as a scalar; cast it to a trusted pointer so the
	 * chain to the file and inode is a protected direct load, as file_free casts its key (E-0190).
	 * read_facts needs a trusted inode: a bpf_probe_read scalar would be rejected (R6 invalid). */
	struct sock *sk = sk_addr ? bpf_core_cast((void *)sk_addr, struct sock) : NULL;
	struct socket *sock;
	struct file *file;
	struct inode *inode;
	__u64 now;
	__u32 extra = 0;

	flow_count(P15_FLC_SOCK_SEEN);
	if (is_self()) {
		flow_count(P15_FLC_S_EXCL_SELF);
		return 0;
	}
	if (kthread()) {
		flow_count(P15_FLC_S_EXCL_KTHREAD);
		return 0;
	}
	sock = sk ? sk->sk_socket : NULL;
	file = sock ? sock->file : NULL;
	if (!file) {
		flow_count(P15_FLC_S_NO_FILE);   /* a kernel socket used from a user task (D6): out of scope */
		return 0;
	}
	if (ret == 0) {
		flow_count(P15_FLC_S_EMPTY);
		return 0;
	}
	if (ret < 0) {
		flow_count(P15_FLC_S_FAILED);
		return 0;
	}
	inode = file->f_inode;
	if (!inode) {
		flow_count(P15_FLC_S_NO_INODE);
		return 0;
	}
	flow_count(P15_FLC_S_ATTEMPT);
	if (kind == P15_FLOWK_RECV && (msg_flags & MSG_PEEK))
		extra |= P15_FF_PEEK;
	now = bpf_ktime_get_boot_ns();
	/* The socket's cookie as the kernel holds it (ADR-0032): NET's bpf_get_socket_cookie made it at
	 * connect, accept, listen or bind and stored it in skc_cookie; a read of the field is no helper
	 * call, so this classic tracepoint may make it. 0 if no program has made it yet. An aligned
	 * 8-byte load: the kernel's own atomic64_read is the same load on x86-64. */
	emit_flow(file, inode, kind, (__u64)ret, now, now, extra,
		  (__u64)sk->__sk_common.skc_cookie.counter);   /* an instant (ADR-0005 rule 5) */
	return 0;
}

SEC("tracepoint/sock/sock_send_length")
int flow_send(struct trace_event_raw_sock_msg_length___p15 *ctx)
{
	return sock_flow((__u64)ctx->sk, ctx->ret, ctx->flags, P15_FLOWK_SEND);
}

SEC("tracepoint/sock/sock_recv_length")
int flow_recv(struct trace_event_raw_sock_msg_length___p15 *ctx)
{
	return sock_flow((__u64)ctx->sk, ctx->ret, ctx->flags, P15_FLOWK_RECV);
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
