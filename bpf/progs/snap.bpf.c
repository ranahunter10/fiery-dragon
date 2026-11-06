// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * snap.bpf.c: the process snapshot (ADR-0007 rule 3, ADR-0023). A sleepable task iterator that
 * writes one PROC record per live thread group to the iterator's output; p15d reads it, checks
 * every record and puts them in the daemon ring of the WAL (ADR-0020 rule 6).
 *
 * Why an iterator and not /proc: the identities are the kernel's own (ADR-0009 start_boottime in
 * ns, which /proc rounds to clock ticks), and parent, executable and argv come from one visit.
 *
 * Sleepable (iter.s): bpf_copy_from_user_task, for argv, may sleep (kernel/bpf/helpers.c, v7.0).
 * The kernel allows sleepable programs only on iterators that can reschedule, which the task
 * iterator does (kernel/bpf/bpf_iter.c line 547); it runs them with migration off (line 687).
 *
 * The executable's path is read from the task's own mapping, not from mm->exe_file: the task
 * iterator pins the task, not its mm, so a file reached through task->mm could be freed under
 * us by an exit. bpf_iter_task_vma_new takes the mmap lock, and a mapped file is held by its
 * mapping, so bpf_d_path on vma->vm_file is safe (the pattern of the kernel's own selftest,
 * tools/testing/selftests/bpf/progs/bpf_iter_task_vmas.c). The kfuncs that would read exe_file
 * safely, bpf_get_task_exe_file and bpf_path_d_path, are LSM-only (fs/bpf_fs_kfuncs.c line 371)
 * and this kernel has no BPF-LSM.
 *
 * Rules kept here: every record byte is written; every early return is counted in `books`
 * (bpf/include/p15_snap.h); variable fields are bounded copies, cut or failed reads flagged.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "p15_records.h"
#include "p15_snap.h"
#include "p15_kernel.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define PF_EXITING 0x00000004   /* include/linux/sched.h */
#define PF_KTHREAD 0x00200000
#define ENAMETOOLONG 36

/* Set by p15d before each snapshot, read back after it. One snapshot runs at a time (p15d's
 * snapshot module is called from one thread at a time), so plain globals are enough. */
struct p15_snap_books books;
__u32 snap_id;
__u32 snap_kind;

/* The record is built here, then written whole: bpf_seq_write either takes all of it or none.
 * Per-CPU, and the iterator runs with migration off; one snapshot at a time (above). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[P15_PROC_MAX_SIZE]);
} proc_scratch SEC(".maps");

#define PROC_TAIL (P15_PROC_MAX_SIZE - (int)sizeof(struct p15_proc))
#define TAIL_MASK (2 * P15_PROC_ARGV_MAX - 1)   /* 2047: >= PROC_TAIL - 1, for the verifier */

static __always_inline void inc(__u64 *c)
{
	__sync_fetch_and_add(c, 1);
}

/* argv into tail[0..), the bytes of mm->arg_start..arg_end. Returns the bytes kept. */
static __always_inline __u32 read_argv(struct p15_proc *r, __u8 *tail, struct task_struct *t, struct mm_struct *mm,
				       __u16 *flags)
{
	__u64 a0 = BPF_CORE_READ(mm, arg_start), a1 = BPF_CORE_READ(mm, arg_end);
	__u64 full = a1 > a0 ? a1 - a0 : 0;
	__u32 n = full > P15_PROC_ARGV_MAX ? P15_PROC_ARGV_MAX : (__u32)full;

	r->argv_full = full > 0xFFFFFFFEull ? P15_LEN_UNKNOWN : (__u32)full;
	if (full > P15_PROC_ARGV_MAX) {
		*flags |= P15_F_TRUNCATED;
		inc(&books.truncated);
	}
	n &= 2 * P15_PROC_ARGV_MAX - 1;
	if (n > P15_PROC_ARGV_MAX)
		n = P15_PROC_ARGV_MAX;
	if (n && bpf_copy_from_user_task(tail, n, (const void *)a0, t, 0)) {
		*flags |= P15_F_READ_FAILED;
		inc(&books.argv_failed);
		n = 0;
	}
	return n;
}

/* The executable's path into tail[0..), from the mapping at mm->start_code when that mapping is
 * mm->exe_file (compared by inode). It holds the task's mmap lock only inside this function.
 * Returns the bytes kept (no NUL), at most P15_PROC_EXE_PATH_MAX - 1.
 *
 * Inside bpf_rcu_read_lock: in a sleepable program the verifier marks a pointer read from a
 * trusted one (vma->vm_file) untrusted outside an RCU section, and bpf_d_path refuses those.
 * Nothing in here sleeps: the vma iterator only try-locks, and d_path doesn't sleep. */
static __always_inline __u32 read_exe_path(struct p15_proc *r, __u8 *tail, struct task_struct *t,
					   struct mm_struct *mm, __u64 exe_inode, __u16 *flags)
{
	struct bpf_iter_task_vma it;
	struct vm_area_struct *vma;
	struct file *f;
	__u32 n = 0;
	long ret;

	r->exe_path_full = P15_LEN_UNKNOWN;
	bpf_rcu_read_lock();
	if (bpf_iter_task_vma_new(&it, t, BPF_CORE_READ(mm, start_code))) {
		*flags |= P15_F_READ_FAILED;
		inc(&books.path_unlocked);
		goto out;
	}
	vma = bpf_iter_task_vma_next(&it);
	f = vma ? vma->vm_file : NULL;
	if (!f || !exe_inode || (__u64)BPF_CORE_READ(f, f_inode) != exe_inode) {
		*flags |= P15_F_READ_FAILED;
		inc(&books.path_not_found);
		goto out;
	}
	ret = bpf_d_path(&f->f_path, (char *)tail, P15_PROC_EXE_PATH_MAX);
	if (ret == -ENAMETOOLONG) {
		*flags |= P15_F_TRUNCATED;          /* d_path keeps nothing when the path doesn't fit */
		inc(&books.truncated);
	} else if (ret <= 0) {
		*flags |= P15_F_READ_FAILED;
		inc(&books.path_failed);
	} else {
		n = (__u32)ret - 1;                 /* ret counts the NUL */
		if (n > P15_PROC_EXE_PATH_MAX - 1)
			n = P15_PROC_EXE_PATH_MAX - 1;
		r->exe_path_full = n;
	}
out:
	bpf_iter_task_vma_destroy(&it);
	bpf_rcu_read_unlock();
	return n;
}

SEC("iter.s/task")
int snap_task(struct bpf_iter__task *ctx)
{
	struct task_struct *t = ctx->task;
	struct mm_struct *mm;
	struct p15_proc *r;
	__u8 *tail;
	__u32 zero = 0, plen = 0, alen = 0, end, len;
	__u64 exe_inode;
	__u16 flags = 0;
	unsigned int pf;

	if (!t)
		return 0;                           /* the end-of-iteration call: not a task */
	inc(&books.tasks);
	if (t->pid != t->tgid) {
		inc(&books.threads);
		return 0;
	}
	r = bpf_map_lookup_elem(&proc_scratch, &zero);
	if (!r) {                                   /* cannot happen for a one-entry array; counted all the same */
		inc(&books.write_failed);
		return 0;
	}
	tail = (__u8 *)(r + 1);
	pf = t->flags;
	mm = t->mm;

	const struct cred *cr = BPF_CORE_READ(t, cred);

	r->parent_start_ns = BPF_CORE_READ(t, real_parent, group_leader, start_boottime);
	r->parent_tgid = BPF_CORE_READ(t, real_parent, tgid);
	r->pflags = (pf & PF_KTHREAD ? P15_PROC_KTHREAD : 0) | (pf & PF_EXITING ? P15_PROC_EXITING : 0);
	r->snap_id = snap_id;
	r->kind = (__u16)snap_kind;
	r->reserved = 0;
	__builtin_memset(r->comm, 0, sizeof(r->comm));
	bpf_probe_read_kernel_str(r->comm, sizeof(r->comm), t->comm);
	r->exe_ino = 0;
	r->exe_dev = 0;
	r->exe_gen = 0;
	r->exe_nlink = 0;
	r->exe_fs_magic = 0;
	r->exe_mode = 0;
	r->exe_uid = 0;
	r->exe_gid = 0;
	r->exe_ctime_ns = 0;
	r->exe_mtime_ns = 0;
	r->exe_path_full = 0;
	r->argv_full = 0;
	/* self_exec_id and the credentials of the leader (ADR-0025 rule 6) */
	r->self_exec_id = BPF_CORE_READ(t, self_exec_id);
	r->uid = BPF_CORE_READ(cr, uid.val);
	r->euid = BPF_CORE_READ(cr, euid.val);
	r->gid = BPF_CORE_READ(cr, gid.val);
	r->egid = BPF_CORE_READ(cr, egid.val);
	r->fsuid = BPF_CORE_READ(cr, fsuid.val);
	r->fsgid = BPF_CORE_READ(cr, fsgid.val);

	if (pf & PF_KTHREAD) {
		inc(&books.kthreads);
	} else if (!mm) {
		inc(&books.exiting);                /* a leader that has exited while its threads live on */
	} else {
		struct inode *ei = BPF_CORE_READ(mm, exe_file, f_inode);

		exe_inode = (__u64)(long)BPF_CORE_READ(mm, exe_file, f_inode);
		r->exe_ino = BPF_CORE_READ(ei, i_ino);
		r->exe_dev = BPF_CORE_READ(ei, i_sb, s_dev);
		r->exe_gen = BPF_CORE_READ(ei, i_generation);
		r->exe_nlink = BPF_CORE_READ(ei, __i_nlink);
		r->exe_fs_magic = (__u32)BPF_CORE_READ(ei, i_sb, s_magic);
		r->exe_mode = BPF_CORE_READ(ei, i_mode);
		r->exe_uid = BPF_CORE_READ(ei, i_uid.val);
		r->exe_gid = BPF_CORE_READ(ei, i_gid.val);
		r->exe_ctime_ns = (__u64)BPF_CORE_READ(ei, i_ctime_sec) * 1000000000ull + (BPF_CORE_READ(ei, i_ctime_nsec) & P15_CTIME_NSEC_MASK);
		r->exe_mtime_ns = (__u64)BPF_CORE_READ(ei, i_mtime_sec) * 1000000000ull + BPF_CORE_READ(ei, i_mtime_nsec);
		/* schema order: exe_path, then argv. read_exe_path takes and drops the mmap lock before
		 * read_argv, whose bpf_copy_from_user_task takes it again: never nested. */
		plen = read_exe_path(r, tail, t, mm, exe_inode, &flags);
		alen = read_argv(r, tail + (plen & (P15_PROC_EXE_PATH_MAX - 1)), t, mm, &flags);
	}
	r->exe_path_len = (__u16)plen;
	r->argv_len = (__u16)alen;

	/* zero the bytes between the data and the 8-byte end of the record */
	end = plen + alen;
	for (int i = 0; i < 8; i++) {
		__u32 o = end + i;

		if (o < PROC_TAIL && ((sizeof(*r) + o) & 7))
			tail[o & TAIL_MASK] = 0;
		else
			break;
	}
	len = ((__u32)sizeof(*r) + end + 7) & ~7u;
	if (len > P15_PROC_MAX_SIZE)
		len = P15_PROC_MAX_SIZE;            /* for the verifier: 104 + 255 + 1024 + 7 rounds to 1384 */

	r->h.type = P15_T_PROC;
	r->h.version = P15_PROC_VERSION;
	r->h.len = (__u16)len;
	r->h.flags = flags;
	r->h.ts_ns = bpf_ktime_get_boot_ns();
	r->h.tgid = t->tgid;
	r->h.tid = t->pid;
	r->h.start_ns = t->start_boottime;      /* t is the leader */

	if (bpf_seq_write(ctx->meta->seq, r, len)) {
		inc(&books.write_failed);
		return 0;
	}
	inc(&books.emitted);
	return 0;
}
