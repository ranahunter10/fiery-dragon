/* SPDX-License-Identifier: MIT */
/*
 * Load-time self-test of the file-identity programs (ADR-0015 confirmation 1, ADR-0003). p15d
 * creates, closes and reopens a file and opens a FIFO that fails in ->open, in a fresh directory
 * under /tmp; the OPEN and CLOSE records attributed to its own tgid must match what it did and
 * what fstat(2) and fstatfs(2) report. With no_path_fentry (the test-only switch that leaves the
 * fentry unattached) every open must instead arrive as OPEN with PATH_WALKED and its path, from
 * the kprobe.session return (ADR-0029).
 */
#ifndef P15_SELFTEST_FILE_H
#define P15_SELFTEST_FILE_H

#include <stdio.h>

#include "compiler.h"

/* Returns the number of failed checks, or -errno if the test could not be run. The records it took
 * from the shared bulk ring, anyone's: file-identity ones in *file_consumed, the rest (NET) in
 * *net_consumed (the run's books count both). */
P15_MUST_CHECK int p15_selftest_file(int bulk_rb_fd, int no_path_fentry, FILE *log, unsigned long long *file_consumed,
				     unsigned long long *net_consumed);

#endif
