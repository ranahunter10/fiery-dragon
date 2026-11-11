/* SPDX-License-Identifier: MIT */
/*
 * The WAL writer thread (ADR-0017 layer 2): the only code that touches the disk. It appends
 * the drain's batches in order, ticks the WAL (rotation, fdatasync), writes STATS every stats
 * interval and CLOCK_SYNC every tenth, rewrites the Prometheus text file, and at the end
 * checks the accounting invariant (ADR-0006 rule 6) and writes the final STATS and END. When main
 * asks (run.h closing_req), it takes the closing process snapshot (ADR-0023 rule 1) before END.
 */
#ifndef P15_WRITER_H
#define P15_WRITER_H

#include "compiler.h"
#include "run.h"
#include "wal.h"

/* Takes the closing snapshot into the WAL (ADR-0023 rule 1): 0 complete, > 0 incomplete (the run
 * is then INVALID), < 0 a WAL failure. p15d passes the snapshot module; tests pass a fake. */
typedef int (*p15_writer_snap_fn)(void *ctx, struct p15w *w);

struct p15_writer {
	struct p15_run *run;
	struct p15w *wal;           /* owned by the writer once the thread starts */
	p15_writer_snap_fn closing; /* NULL: no closing snapshot; the opening ones come through the WAL's on_open */
	void *closing_ctx;
	uint64_t prev_stats_ns;
	unsigned stats_written;
	int close_rc;               /* p15w_close's result, for main */
};

/* The thread function: arg is a struct p15_writer *. Returns NULL. */
void *p15_writer_main(void *arg);
/* The writer's wait when no batch comes (gate 3): until the next STATS (stats_due, boot ns) or the
 * WAL's next rotation or fdatasync (wal_due_ns from now, p15w_due_ns), whichever is first, in ms,
 * at least 1 and at most P15_WRITER_WAIT_MAX_MS (a batch wakes it at once through the queue). */
#define P15_WRITER_WAIT_MAX_MS 500
int p15_writer_wait_ms(uint64_t stats_due, uint64_t now, uint64_t wal_due_ns);

/* The ADR-0006 rule 6 check at quiescence, from the run's counters. Records the result in the run
 * and makes a broken run INVALID. Returns P15_INV_CLOSED or P15_INV_BROKEN. */
int p15_invariant_check(struct p15_run *r, char *why, size_t n);

#endif
