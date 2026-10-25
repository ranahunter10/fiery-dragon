/* SPDX-License-Identifier: MIT */
/*
 * Load-time self-test of the spine (ADR-0003): a test child performs known
 * lifecycle operations and the records attributed to it, and only to it,
 * must match exactly. Background activity on the machine cannot make a
 * broken hook pass, because nothing is counted system-wide.
 */
#ifndef P15_SELFTEST_H
#define P15_SELFTEST_H

#include <stdio.h>
#include <stddef.h>
#include <linux/types.h>

#include "compiler.h"

#define P15_ST_NAME "fd-selftest"      /* the test child's comm and argv[1] */
#define P15_ST_EXE "/bin/true"
#define P15_ST_GRANDCHILD_EXIT 7

/* Owned copies of records, in arrival order. */
struct p15_rec_list {
	size_t n, cap;
	void **recs;
	size_t invalid;      /* records that failed p15_rec_check; never stored */
	size_t dropped_oom;  /* records not stored for lack of memory; makes the test fail */
	size_t size_not_len; /* stored records whose ring size is not their len (ADR-0017 layer 1) */
};

/* Copy a record that passes p15_rec_check. 0 (an invalid record is counted, not stored) or -ENOMEM (counted). */
P15_MUST_CHECK int p15_rec_list_add(struct p15_rec_list *l, const void *data, size_t size);
void p15_rec_list_free(struct p15_rec_list *l);

struct p15_selftest_expect {
	__u32 daemon_tgid;
	char daemon_comm[16];   /* the test child's comm before its rename */
	__u32 child;            /* tgid of the test child */
	__u32 grandchild;       /* tgid of the child's child */
};

/* Judge collected records. One line per check to `log`; returns the number of failed checks. */
P15_MUST_CHECK int p15_selftest_eval(const struct p15_rec_list *l, const struct p15_selftest_expect *e, FILE *log);

/*
 * Fork the test child and collect records from the spine ring until the child and its child
 * are reaped and the ring has been quiet for a grace period. Then evaluate.
 * Returns the number of failed checks, or -errno if the test could not be run.
 */
P15_MUST_CHECK int p15_selftest_run(int spine_rb_fd, FILE *log);

#endif
