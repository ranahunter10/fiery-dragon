/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * File identity (ADR-0015, STATE decision 19): what file.bpf.c and p15d share. The counters live
 * in their own mmapable map with ADR-0026's rows (bpf/include/p15_counters.h: P15_CTR_MAX u64 per
 * row), one named slot each, so the spine and NET table of (type, kind) is untouched (decision
 * 19.4). Every early return of a program has a slot. At quiescence they close:
 *
 *   FENTRY_RUN     = OPEN_EMITTED + OPEN_LOST + BACKING_EMITTED + BACKING_LOST + FENTRY_NO_INODE
 *   SESSION_ENTRY  = SESSION_RETURN + SESSION_NO_INODE
 *   SESSION_RETURN = SESSION_COMMON + MISSING_EMITTED + MISSING_LOST + VERDICT_EMITTED + VERDICT_LOST
 *                    + SESSION_NO_COOKIE + SESSION_NO_ENTRY
 *   FREE_RUN       = CLOSE_EMITTED + CLOSE_LOST + FREE_UNREGISTERED
 *
 * and on the drain side, the records submitted
 *   OPEN_EMITTED + MISSING_EMITTED + VERDICT_EMITTED + BACKING_EMITTED + CLOSE_EMITTED
 *   = drained + taken by the self-tests + invalid.
 * FILES_LIVE and OBJS_LIVE are gauges: +1 per insert, -1 (as u64) per delete; their sum over the
 * rows is the live count (u64 arithmetic wraps back to it).
 */
#ifndef P15_FILE_H
#define P15_FILE_H

enum p15_fc {
	P15_FC_FENTRY_RUN = 0,       /* the path fentry ran */
	P15_FC_FENTRY_NO_INODE,      /* ... for a file without an inode (never expected: counted, nothing written) */
	P15_FC_OPEN_EMITTED,         /* OPEN records the fentry submitted */
	P15_FC_OPEN_LOST,            /* ... lost to a full bulk ring (run DEGRADED) */
	P15_FC_OPEN_FULL_SIZE,       /* ... written full size: no scratch slot was free (rule 6) */
	P15_FC_OPEN_TRUNCATED,       /* ... whose path did not fit (dentry name, TRUNCATED) */
	P15_FC_OPEN_PATH_ERROR,      /* ... whose bpf_d_path failed otherwise (PATH_ERROR) */
	P15_FC_BACKING_EMITTED,      /* BACKING records submitted */
	P15_FC_BACKING_LOST,
	P15_FC_BACKING_USER_UNREAD,  /* BACKING without the overlay inode (user_obj 0, READ_FAILED) */
	P15_FC_SESSION_ENTRY,        /* the kprobe.session ran at entry */
	P15_FC_SESSION_NO_INODE,     /* ... for a file without an inode: no return run */
	P15_FC_SESSION_RETURN,       /* the session's return run */
	P15_FC_SESSION_COMMON,       /* ... with the OPEN written and verdict 0: nothing to write */
	P15_FC_MISSING_EMITTED,      /* OPEN with PATH_MISSING (the fentry did not run) */
	P15_FC_MISSING_LOST,
	P15_FC_VERDICT_EMITTED,      /* OPEN_VERDICT */
	P15_FC_VERDICT_LOST,
	P15_FC_SESSION_NO_COOKIE,    /* return run with an empty cookie (never expected) */
	P15_FC_SESSION_NO_ENTRY,     /* return run without an open-file entry (its map was full) */
	P15_FC_FREE_RUN,             /* security_file_free ran (every struct file of the system) */
	P15_FC_CLOSE_EMITTED,
	P15_FC_CLOSE_LOST,
	P15_FC_FREE_UNREGISTERED,    /* a free of a file capture never registered (decision 19.5) */
	P15_FC_INODE_FREE_RUN,       /* security_inode_free ran */
	P15_FC_INODE_FREE_HIT,       /* ... and deleted an object entry */
	P15_FC_FILE_MAP_FULL,        /* no open-file entry: the event is written with a fresh, unregistered id */
	P15_FC_OBJ_MAP_FULL,         /* no object entry: the facts go inline, with a fresh id */
	P15_FC_FILE_STALE,           /* an entry whose stored inode differs from the live file's: replaced (rule 9) */
	P15_FC_OBJ_STALE,            /* an entry whose dev/ino/gen differ from the live inode's: replaced */
	P15_FC_FILE_RACE,            /* another program inserted the entry between lookup and insert */
	P15_FC_OBJ_RACE,
	P15_FC_FACTS_DUP,            /* a second record carried an object's facts (decision 19.7: twice, never zero) */
	P15_FC_SUBVOL_UNKNOWN,       /* facts of a btrfs object read without btrfs BTF (oflags SUBVOL_UNKNOWN) */
	P15_FC_KTHREAD_OPEN,         /* OPEN records written in a kernel thread (KTHREAD) */
	P15_FC_FILES_LIVE,           /* gauge: open-file entries */
	P15_FC_OBJS_LIVE,            /* gauge: object entries */
	P15_FC__N,
};

/* OBJFACTS seen and oflags (schema/records.toml) */
#define P15_SEEN_OPEN 1
#define P15_SEEN_SNAPSHOT 2
#define P15_OFL_SUBVOL_UNKNOWN 1

/* include/linux/fs.h and include/uapi/linux/magic.h, v7.0 (macros are not in BTF) */
#define P15_FMODE_OPENED (1u << 19)
#define P15_FMODE_BACKING (1u << 24)
#define P15_BTRFS_MAGIC 0x9123683Eu

#define P15_PATH_MAX 4096
#define P15_PATH_SLOTS 4             /* path scratch slots per CPU (ADR-0015 rule 6: claimed per call) */

/* Map size defaults and bounds (decision 19.6, E-0142): configurable with --file-map-entries and
 * --obj-map-entries, echoed in the WAL header's config.* keys. */
#define P15_FILE_MAP_DEFAULT 65536u
#define P15_OBJ_MAP_DEFAULT 131072u

#endif /* P15_FILE_H */
