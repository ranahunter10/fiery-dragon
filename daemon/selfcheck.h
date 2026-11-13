/* SPDX-License-Identifier: MIT */
/*
 * p15d checks its own links (docs/research/2026-11-14-canary-and-self-check.md; the research note's
 * I4). After the programs are attached, main records every link p15d holds: its descriptor, the
 * kernel's link id and the id of the program it attached. At every stats tick the writer asks the
 * kernel about each descriptor again. A descriptor that is no longer a link, or names another link
 * or another program, is counted once, logged, written in a CANARY_MISS record of kind LINK, and
 * the run is DEGRADED.
 *
 * What this can see: p15d's descriptor closed or replaced, by a fault in p15d or by something
 * acting inside its process. What it cannot: a program that is still attached and no longer runs
 * (ftrace or kprobes switched off system-wide). That is the canary's part (canary.h).
 */
#ifndef P15_SELFCHECK_H
#define P15_SELFCHECK_H

#include "run.h"

struct bpf_link;

/* Record one link of p15d under `name` (truncated to 31 bytes). A NULL link is skipped. Returns 0,
 * -ENOSPC when the table is full (P15_LINKS_MAX), or -errno when the kernel will not describe it. */
P15_MUST_CHECK int p15_links_add(struct p15_run *r, const struct bpf_link *link, const char *name);
/* What p15_links_check found for one link. */
struct p15_link_gone {
	int index;
	int err;        /* errno of the info call; 0 when the descriptor names another link or program */
};
/* Check every recorded link not already found gone. Fills out[] (up to max) with the links found
 * gone by this call and returns their number; each is reported once. Does nothing while
 * r->links_closing is set. */
int p15_links_check(struct p15_run *r, struct p15_link_gone *out, int max);

#endif
