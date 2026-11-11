/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * The process snapshot's books (ADR-0007 rule 3, ADR-0023), shared by snap.bpf.c, which counts,
 * and p15d, which zeroes them before each snapshot and copies them into SNAP_DONE after it.
 * Every early return in the program has one of these counters. They close:
 *
 *     tasks == threads + emitted + write_failed
 *
 * Exact only if each task is shown to the program once. bpf_seq_read shows an object a second
 * time only after its output overflowed the iterator's 32 KiB buffer (kernel/bpf/bpf_iter.c,
 * v7.0, lines 105 and 172-199); p15d reads in P15_SNAP_READ_CHUNK pieces, so the buffer never
 * holds more than one chunk plus one record and cannot overflow.
 */
#ifndef P15_SNAP_H
#define P15_SNAP_H

#define P15_SNAP_READ_CHUNK (16u << 10)   /* + P15_PROC_MAX_SIZE (1384) or P15_FD_MAX_SIZE (4232) < 32 KiB */

enum p15_snap_kind { P15_SNAP_OPENING = 1, P15_SNAP_CLOSING = 2 };

/* PROC pflags */
#define P15_PROC_KTHREAD (1u << 0)
#define P15_PROC_EXITING (1u << 1)

struct p15_snap_books {
	__u64 tasks;           /* the program ran for a task */
	__u64 threads;         /* not a thread-group leader: not recorded, by design */
	__u64 emitted;         /* a PROC record was written to the output */
	__u64 write_failed;    /* bpf_seq_write refused it */
	__u64 kthreads;        /* emitted records that are kernel threads */
	__u64 exiting;         /* emitted records of a leader with no mm left */
	__u64 argv_failed;
	__u64 path_unlocked;   /* bpf_iter_task_vma_new failed (mmap lock busy, no memory) */
	__u64 path_not_found;  /* the mapping at mm->start_code is not mm->exe_file */
	__u64 path_failed;     /* bpf_d_path failed, other than -ENAMETOOLONG */
	__u64 truncated;       /* fields cut: argv, or a path longer than its maximum (both: counted twice) */
};

/* The FD pass's books (ADR-0015 rule 7), counted by file.bpf.c's iter/task_file program, zeroed by
 * p15d before each pass and copied into SNAP_DONE v2's fd_* fields. They close:
 *
 *     files   == no_inode + emitted + write_failed
 *     emitted == known + registered + map_full
 *
 * with the same read-chunk argument as above (P15_SNAP_READ_CHUNK + P15_FD_MAX_SIZE < 32 KiB). */
struct p15_fd_books {
	__u64 files;           /* the program ran for a descriptor */
	__u64 no_inode;        /* its file has no inode: not recorded */
	__u64 emitted;         /* an FD record was written to the output */
	__u64 write_failed;    /* bpf_seq_write refused it */
	__u64 known;           /* emitted, the open file was already registered (an OPEN or an earlier pass) */
	__u64 registered;      /* emitted, the open file was registered by this pass */
	__u64 map_full;        /* emitted with a fresh, unregistered id: the open-file map was full */
	__u64 path_error;      /* emitted with PATH_ERROR */
	__u64 truncated;       /* emitted with TRUNCATED */
};

#endif /* P15_SNAP_H */
