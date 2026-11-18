/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * Data flow (ADR-0005, STATE decisions 18 and 47): the counters the flow programs in file.bpf.c
 * keep, in their own mmapable map (bpf/include/p15_counters.h layout, P15_FLC__N named slots), so
 * the file-identity books (p15_file.h) and the spine/NET (type, kind) table are untouched. Step 2b
 * writes one FLOW per transfer, unfolded; folding (step 2c) reuses the same counters.
 *
 * The flow programs are four kprobe.session on vfs_read/vfs_write/vfs_readv/vfs_writev and the two
 * classic tracepoints sock:sock_send_length / sock:sock_recv_length (design checks §3, D5-D7). A
 * transfer is resolved to the open file's struct file *; a file the open path never saw (a pipe,
 * socket, memfd, anonymous inode, or a regular file opened before capture) is registered in the
 * shared files/objs maps and gets one FILE record (ADR-0015 rule 5) before its first FLOW.
 *
 * The books, at quiescence (p15d checks them in daemon/writer.c):
 *   B1  SESS_ENTRY  = SESS_RETURN + V_EXCL_SELF + V_EXCL_KTHREAD + V_OWNED_BY_SOCK   (every vfs entry run)
 *   B2  SESS_RETURN = V_EMPTY + V_FAILED + V_NO_INODE + V_ATTEMPT                    (every vfs return run)
 *   B3  SOCK_SEEN   = S_EXCL_SELF + S_EXCL_KTHREAD + S_NO_FILE + S_EMPTY + S_FAILED + S_NO_INODE + S_ATTEMPT
 *   B4  V_ATTEMPT + S_ATTEMPT = READ_EMITTED + WRITE_EMITTED + SEND_EMITTED + RECV_EMITTED + FLOW_LOST
 *   B5 (drain side) READ_EMITTED + WRITE_EMITTED + SEND_EMITTED + RECV_EMITTED + FILE_EMITTED
 *                   = flow_drained + taken by the self-test + flow_invalid
 * START_UNKNOWN and UNREGISTERED are sub-counts of the emitted FLOWs (each also flagged in the
 * record); FILE_LOST and FILE_MAP_FULL are reported, not book terms. A FILE is written by the
 * program that registered its open file; another thread's FLOW on the same file can reach the ring
 * before it (a race), so a reader joins FLOW to FILE by fid, never by order. A FLOW_LOST or FILE_LOST (a
 * bulk-ring reserve that failed), or a kernel skip of a flow program, makes the run DEGRADED
 * (ADR-0005 rule, as for NET); START_UNKNOWN, UNREGISTERED and the folding reasons do not.
 */
#ifndef P15_FLOW_H
#define P15_FLOW_H

enum p15_flc {
	P15_FLC_SESS_ENTRY = 0,     /* a vfs kprobe.session ran at entry */
	P15_FLC_SESS_RETURN,        /* ... and its return ran */
	P15_FLC_V_EXCL_SELF,        /* a vfs entry in p15d itself (ADR-0005 rule: capture excludes itself): no return */
	P15_FLC_V_EXCL_KTHREAD,     /* a vfs entry in a kernel thread: no return */
	P15_FLC_V_OWNED_BY_SOCK,    /* a vfs entry on a socket: its sock tracepoint records it (ADR-0005 rule 11): no return */
	P15_FLC_V_EMPTY,            /* a vfs return with ret == 0 (nothing transferred): no record */
	P15_FLC_V_FAILED,           /* a vfs return with ret < 0 (the call failed): no record */
	P15_FLC_V_NO_INODE,         /* a vfs return whose file has no inode: no record */
	P15_FLC_V_ATTEMPT,          /* a vfs return that reached the emit path (ret > 0) */
	P15_FLC_SOCK_SEEN,          /* a sock tracepoint fired */
	P15_FLC_S_EXCL_SELF,        /* ... in p15d itself: no record */
	P15_FLC_S_EXCL_KTHREAD,     /* ... in a kernel thread: no record */
	P15_FLC_S_NO_FILE,          /* ... on a socket with no struct file (a kernel socket, D6): no record */
	P15_FLC_S_EMPTY,            /* ... with ret == 0: no record */
	P15_FLC_S_FAILED,           /* ... with ret < 0: no record */
	P15_FLC_S_NO_INODE,         /* ... whose socket file has no inode: no record */
	P15_FLC_S_ATTEMPT,          /* ... that reached the emit path (ret > 0) */
	P15_FLC_READ_EMITTED,       /* FLOW records of kind READ submitted */
	P15_FLC_WRITE_EMITTED,      /* ... WRITE */
	P15_FLC_SEND_EMITTED,       /* ... SEND */
	P15_FLC_RECV_EMITTED,       /* ... RECV */
	P15_FLC_FLOW_LOST,          /* a FLOW lost to a full bulk ring (run DEGRADED) */
	P15_FLC_START_UNKNOWN,      /* a vfs FLOW whose entry time was not kept (option A missed; START_UNKNOWN): sub-count of emitted */
	P15_FLC_UNREGISTERED,       /* a FLOW on a file with no entry (files map full): facts inline, reason MAP_FULL; sub-count of emitted */
	P15_FLC_FILE_EMITTED,       /* FILE records written for a file first seen at a transfer (ADR-0015 rule 5) */
	P15_FLC_FILE_LOST,          /* ... lost to a full bulk ring (run DEGRADED): the entry is removed, so the next transfer retries */
	P15_FLC_FILE_MAP_FULL,      /* a pseudo file that could not be registered (files map full): its FLOW is UNREGISTERED */
	P15_FLC__N,
};

/* FLOW.kind (schema/records.toml P15_FLOW_KIND_*); kept here so the programs need no generated header. */
#define P15_FLOWK_READ  1
#define P15_FLOWK_WRITE 2
#define P15_FLOWK_RECV  3
#define P15_FLOWK_SEND  4

/* FLOW.reason (schema P15_FLOW_REASON_*): step 2b writes only SINGLE and MAP_FULL. */
#define P15_FLOWR_SINGLE   1
#define P15_FLOWR_MAP_FULL 11

/* OBJFACTS.seen for a FILE first seen at a transfer (schema): first I/O, mmap (2d), network (2e). */
#define P15_SEEN_IO   3
#define P15_SEEN_MMAP 4
#define P15_SEEN_NET  5

#ifndef MSG_PEEK        /* include/linux/socket.h: a receive that left the data queued */
#define MSG_PEEK 2
#endif

#ifndef S_IFMT          /* include/uapi/linux/stat.h; vmlinux.h carries no macros */
#define S_IFMT   00170000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif

#endif /* P15_FLOW_H */
