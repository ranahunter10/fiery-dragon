/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * File identity (ADR-0015, STATE decision 19): what file.bpf.c and p15d share. The counters live
 * in their own mmapable map with ADR-0026's rows (bpf/include/p15_counters.h: P15_CTR_MAX u64 per
 * row), one named slot each, so the spine and NET table of (type, kind) is untouched (decision
 * 19.4). Every early return of a program has a slot. At quiescence they close:
 *
 *   FENTRY_RUN     = OPEN_EMITTED + OPEN_LOST + BACKING_EMITTED + BACKING_LOST + FENTRY_NO_INODE
 *   SESSION_ENTRY  = SESSION_RETURN + SESSION_NO_INODE + SESSION_GATED
 *                    + (SESSION_OPEN_AT_END - SESSION_RETURNED_AFTER_COUNT)
 *                    + (SESSION_NOSLOT_ENTRY - SESSION_NOSLOT_RETURN)
 *   SESSION_RETURN = SESSION_COMMON + MISSING_EMITTED + MISSING_LOST + VERDICT_EMITTED + VERDICT_LOST
 *                    + RET_BACKING + SESSION_NO_COOKIE + SESSION_NO_ENTRY
 *   MISSING_EMITTED = WALKED + WALK_UNNAMED     (the return's OPENs: walked, or without a path; ADR-0029)
 *   RET_BACKING    = RET_BACKING_EMITTED + RET_BACKING_LOST
 *   FREE_RUN       = CLOSE_EMITTED + CLOSE_LOST + FREE_UNREGISTERED
 * WALK_RACED and WALK_TRUNCATED are parts of WALKED, not book terms.
 *
 * and on the drain side, the records submitted
 *   OPEN_EMITTED + MISSING_EMITTED + VERDICT_EMITTED + BACKING_EMITTED + CLOSE_EMITTED
 *   + RET_BACKING_EMITTED + RET_BACKING_VERDICT_EMITTED
 *   = drained + taken by the self-tests + invalid.
 * FILES_LIVE and OBJS_LIVE are gauges: +1 per insert, -1 (as u64) per delete; their sum over the
 * rows is the live count (u64 arithmetic wraps back to it).
 *
 * Opens in flight at the end (docs/research/2026-11-14-open-session-end-count.md). On 7.0 a call
 * that is inside security_file_open when the session is detached never runs its return
 * (fprobe_return skips an unregistered probe; E-0303), so its entry has no return to match. The
 * call is marked in the open-file entry it registered, which both ends of the session already
 * hold: the entry sets ST_SESSION_ENTRY, the return sets ST_SESSION_RETURNED. p15d ends a run as
 * for the flow programs (p15_flow.h), in one pass with them:
 *   1. it shuts file_gate: an entry after that is counted SESSION_GATED and registers nothing;
 *   2. an RCU grace period: every entry that read the gate open has set its mark;
 *   3. a bounded wait;
 *   4. the map iterator file_open_iter claims every entry marked entered and not returned
 *      (ST_SESSION_CLAIMED, by compare-and-exchange) and counts it SESSION_OPEN_AT_END;
 *   5. detach. A return between 4 and 5 finds its entry claimed and counts
 *      SESSION_RETURNED_AFTER_COUNT (its records are still written).
 * An entry that got no open-file entry (the map was full) cannot be marked: it sets the low bit of
 * the session's cookie and counts SESSION_NOSLOT_ENTRY, its return SESSION_NOSLOT_RETURN; the
 * difference is such calls still open, which nothing observes directly. SESSION_CLAIM_RACE (the
 * iterator gave up on an entry) and SESSION_REENTERED (an entry found the marks of an earlier
 * open on its open-file entry: a free that was not seen) are reported, expected 0, not terms.
 * What the mark cannot do: tell an open still in flight from a return lost earlier in the run on a
 * file that is still open. Both are SESSION_OPEN_AT_END. A lost return on a file since freed is in
 * no count, and breaks the book, as before.
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
	P15_FC_MISSING_EMITTED,      /* OPEN written by the session return (the fentry did not run): walked or without a path */
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
	P15_FC_WALKED,               /* the return's OPENs with the walked path (PATH_WALKED, ADR-0029) */
	P15_FC_WALK_RACED,           /* ... the tree moved during both tries (PATH_RACED) */
	P15_FC_WALK_TRUNCATED,       /* ... a bound of the walk cut the path (TRUNCATED) */
	P15_FC_WALK_UNNAMED,         /* the return's OPENs without a path (PATH_MISSING): unknown d_dname, no fs, no scratch */
	P15_FC_RET_BACKING,          /* the return, the fentry skipped, for an FMODE_BACKING file */
	P15_FC_RET_BACKING_EMITTED,  /* ... BACKING submitted */
	P15_FC_RET_BACKING_LOST,
	P15_FC_RET_BACKING_VERDICT_EMITTED,   /* OPEN_VERDICT after such a BACKING */
	P15_FC_RET_BACKING_VERDICT_LOST,
	P15_FC_SESSION_GATED,        /* a session entry after the gate shut (the run is ending): nothing registered, no return */
	P15_FC_SESSION_NOSLOT_ENTRY, /* a session entry that got no open-file entry (map full): marked in the cookie */
	P15_FC_SESSION_NOSLOT_RETURN, /* ... and its return */
	P15_FC_SESSION_OPEN_AT_END,  /* entries the end's iterator found entered, not returned, and claimed */
	P15_FC_SESSION_RETURNED_AFTER_COUNT, /* ... of which these returned before the detach (their records are written) */
	P15_FC_SESSION_CLAIM_RACE,   /* the iterator gave up on an entry after its tries (expected 0; reported) */
	P15_FC_SESSION_REENTERED,    /* an entry found an earlier open's marks on its open-file entry (expected 0; reported) */
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

/* The session's cookie holds the struct file pointer, which is at least 8-aligned: its low bit
 * marks a call that got no open-file entry, so is in no count. */
#define P15_FILE_COOKIE_NOSLOT 1ull
#define P15_FILE_CAS_TRIES 4

/* TEST ONLY (--test-open-end-mode, with --test-open-end-tgid): what the session does for that
 * process's opens, to stage states no test can time (no task can be held inside
 * security_file_open from user space):
 *   1  the entry marks its open and asks for no return, as a detach in flight leaves it;
 *   2  the entry marks its open as already claimed and counts it SESSION_OPEN_AT_END, as the
 *      end's iterator would have; its return then runs the returned-after-the-count branch. */
#define P15_TEST_OPEN_LOSE_RETURN 1u
#define P15_TEST_OPEN_PRECLAIM 2u

#endif /* P15_FILE_H */
