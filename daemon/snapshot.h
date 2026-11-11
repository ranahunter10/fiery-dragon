/* SPDX-License-Identifier: MIT */
/*
 * The process snapshot (ADR-0007 rule 3, ADR-0023). The task iterator in bpf/progs/snap.bpf.c
 * writes one PROC record per live thread group; with file identity, the task_file iterator in
 * bpf/progs/file.bpf.c then writes one FD record per open descriptor (ADR-0015 rule 7). This
 * module reads both outputs, checks every record, appends them to the daemon ring of the WAL,
 * then appends SNAP_DONE v2 with the books of both passes.
 *
 * Two parts, so the checking can be tested without BPF:
 *   framing   (snapshot_frame.c): bytes in, checked PROC records out to a put function, and
 *             the books that close (p15_snap_books_close);
 *   taking    (snapshot.c): the BPF object, the iterator read loop and the WAL.
 *
 * When snapshots are taken (one at a time, never concurrently):
 *   opening: at every segment open, through p15w_opts.on_open. The first segment opens on the
 *            main thread before the writer thread starts; later ones on the writer thread.
 *   closing: at an orderly stop, on the writer thread when main asks (run.h closing_req), while
 *            the hooks are still attached (ADR-0023 rule 1, the fuzzy-checkpoint order).
 */
#ifndef P15_SNAPSHOT_H
#define P15_SNAPSHOT_H

#include <stddef.h>
#include <stdint.h>
#include <linux/types.h>

#include "compiler.h"
#include "p15_records.h"
#include "p15_snap.h"
#include "run.h"
#include "wal.h"

/* ---- framing ---- */

/* Where a checked record goes. Returns 0, or -errno: the record is counted unwritten. */
typedef int (*p15_snap_put_fn)(void *ctx, const void *rec, uint32_t len);

#define P15_SNAP_REC_MAX (P15_FD_MAX_SIZE > P15_PROC_MAX_SIZE ? P15_FD_MAX_SIZE : P15_PROC_MAX_SIZE)

struct p15_snap_frame {
	uint16_t type;               /* P15_T_PROC or P15_T_FD: every record must be of it */
	uint32_t snap_id;            /* every record must carry these, else it is invalid */
	uint16_t kind;               /* PROC only (FD has no kind) */
	uint32_t have;               /* bytes waiting in buf: at most one partial record */
	int lost;                    /* framing lost (a len that can't be a record): the rest is not read */
	__u64 *entries, *invalid, *unwritten;   /* the pass's books in SNAP_DONE */
	__s32 *error;
	p15_snap_put_fn put;
	void *put_ctx;
	uint8_t buf[P15_SNAP_READ_CHUNK + P15_SNAP_REC_MAX];
};

/* The PROC pass: its books are SNAP_DONE's entries, invalid, unwritten and error. */
void p15_snap_frame_init(struct p15_snap_frame *f, uint32_t snap_id, uint16_t kind, struct p15_snap_done_v2 *done,
			 p15_snap_put_fn put, void *ctx);
/* The FD pass: its books are SNAP_DONE's fd_entries, fd_invalid, fd_unwritten and fd_error. */
void p15_snap_frame_init_fd(struct p15_snap_frame *f, uint32_t snap_id, struct p15_snap_done_v2 *done,
			    p15_snap_put_fn put, void *ctx);
/* The caller wrote n new bytes at f->buf + f->have (n <= sizeof(buf) - have). Every complete
 * record is checked and put; the partial one stays. Counts entries, invalid and unwritten. */
void p15_snap_frame_feed(struct p15_snap_frame *f, size_t n);
/* End of output: bytes left over are one invalid record. */
void p15_snap_frame_end(struct p15_snap_frame *f);

/* Copy the BPF books into SNAP_DONE. */
void p15_snap_books_fill(struct p15_snap_done_v2 *d, const struct p15_snap_books *b);
/* Copy the FD pass's BPF books into SNAP_DONE's fd_* fields and set fd_pass. */
void p15_snap_fd_books_fill(struct p15_snap_done_v2 *d, const struct p15_fd_books *b);
/* 0 if the books close (p15_snap.h, SNAP_DONE doc), the FD pass's too when it ran, and nothing
 * was lost or refused, else a reason in why. A snapshot that fails this makes the run INVALID. */
int p15_snap_books_close(const struct p15_snap_done_v2 *d, char *why, size_t n);

/* ---- taking ---- */

struct snap_bpf;
struct file_bpf;
struct bpf_link;

struct p15_snapshot {
	struct snap_bpf *skel;
	struct bpf_link *link;
	struct file_bpf *file;       /* the FD pass (ADR-0015 rule 7); NULL without file identity */
	struct bpf_link *fd_link;
	struct p15_run *run;
	uint32_t next_id;
	struct p15w_batch batch;     /* the daemon ring */
	struct p15_snap_done_v2 last; /* the last SNAP_DONE, for the log and tests */
	struct p15_snap_frame frame;
};

/* Open, load and attach the iterator. Returns 0, or a P15_EXIT_* code with a reason in err. */
P15_MUST_CHECK int p15_snapshot_init(struct p15_snapshot *s, struct p15_run *run, char *err, size_t errlen);
void p15_snapshot_free(struct p15_snapshot *s);
/* Give every later snapshot the FD pass: the loaded file object and its task_file iterator link
 * (both stay the loader's). Before the WAL opens, so the first segment's snapshot has it. */
void p15_snapshot_set_fd(struct p15_snapshot *s, struct file_bpf *file, struct bpf_link *fd_link);

#define P15_SNAP_INCOMPLETE 1

/*
 * Take one snapshot into w: its PROC records, then SNAP_DONE. Returns 0 when it is complete and
 * its books close; P15_SNAP_INCOMPLETE when it is not (the run is then INVALID, with the reason);
 * a negative errno when a WAL append failed (the WAL is then failed too).
 */
P15_MUST_CHECK int p15_snapshot_take(struct p15_snapshot *s, unsigned kind, struct p15w *w);

/* p15w_open_fn: the opening snapshot of every segment. ctx is a struct p15_snapshot *. Fails
 * only when the WAL itself fails; an incomplete snapshot makes the run INVALID but goes on. */
int p15_snapshot_on_open(struct p15w *w, void *ctx);

#endif
