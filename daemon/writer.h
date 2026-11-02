/* SPDX-License-Identifier: MIT */
/*
 * The WAL writer thread (ADR-0017 layer 2): the only code that touches the disk. It appends
 * the drain's batches in order, ticks the WAL (rotation, fdatasync), writes STATS every stats
 * interval and CLOCK_SYNC every tenth, rewrites the Prometheus text file, and at the end
 * checks the accounting invariant (ADR-0006 rule 6) and writes the final STATS and END.
 */
#ifndef P15_WRITER_H
#define P15_WRITER_H

#include "compiler.h"
#include "run.h"
#include "wal.h"

struct p15_writer {
	struct p15_run *run;
	struct p15w *wal;           /* owned by the writer once the thread starts */
	uint64_t prev_stats_ns;
	unsigned stats_written;
	int close_rc;               /* p15w_close's result, for main */
};

/* The thread function: arg is a struct p15_writer *. Returns NULL. */
void *p15_writer_main(void *arg);

/* The ADR-0006 rule 6 check at quiescence, from the run's counters. Records the result in the run
 * and makes a broken run INVALID. Returns P15_INV_CLOSED or P15_INV_BROKEN. */
int p15_invariant_check(struct p15_run *r, char *why, size_t n);

#endif
