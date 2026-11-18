/* SPDX-License-Identifier: MIT */
/*
 * Load-time self-test of the data-flow programs (ADR-0005, ADR-0003), run once they are attached.
 * p15d's own transfers are excluded from capture (decision 47.1), so a forked child does the
 * transfers: a write and a read of a new file, a writev and a readv of it, a write and a read
 * through a pipe, and a send and a receive over an AF_UNIX socketpair. Each must arrive as exactly
 * one FLOW of the child with its kind and bytes; the file's FLOWs must name the open-file id of its
 * OPEN, the pipe's and the socketpair's ends a FILE each (seen IO and NET). With lost_first (the
 * test switch --test-flow-file-fail-first) the FILE records are planted losses, so only the FLOWs
 * are checked. The child's records, and anyone else's taken meanwhile, are consumed: they count on
 * the books as taken by the self-test, and the opening snapshot's FD records then name every file
 * still open (ADR-0015 rule 7), as for the other self-tests.
 */
#ifndef P15_SELFTEST_FLOW_H
#define P15_SELFTEST_FLOW_H

#include <stdio.h>

#include "compiler.h"

/* Returns the number of failed checks, or -errno if the test could not be run. The records it took
 * from the shared bulk ring, anyone's: FLOW and FILE in *flow_consumed, file identity (OPEN,
 * OPEN_VERDICT, BACKING, CLOSE) in *file_consumed, the rest (NET) in *net_consumed. */
P15_MUST_CHECK int p15_selftest_flow(int bulk_rb_fd, int lost_first, FILE *log, unsigned long long *flow_consumed,
				     unsigned long long *file_consumed, unsigned long long *net_consumed);

#endif
