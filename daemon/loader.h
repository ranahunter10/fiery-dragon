/* SPDX-License-Identifier: MIT */
/*
 * Open, size, load and attach the BPF programs, then run the load-time self-test (ADR-0003).
 * exec, exit and rename attach to classic tracepoints, which need tracefs (ADR-0020 rule 1).
 * The run starts only if every step succeeds; each failure has its own exit code (ADR-0019 G2).
 */
#ifndef P15_LOADER_H
#define P15_LOADER_H

#include <stddef.h>
#include <stdint.h>
#include <linux/types.h>

#include "compiler.h"

struct spine_bpf;
struct net_bpf;

struct p15_loader {
	struct spine_bpf *spine;
	struct net_bpf *net;        /* NULL with --no-net */
	int selftest_failed;       /* failed checks, or -errno if it could not run */
	int net_selftest_failed;
	__u64 daemon_start_ns;     /* from the self-test (ADR-0009 identity of p15d) */
	__u64 spine_consumed;      /* records the self-tests took from the rings: part of the run's books */
	unsigned long long net_consumed;
	char manifest[1024];       /* the attached hooks, for the WAL header */
	int miss_fd[5];            /* program fds by spine record type 1..4, for recursion_misses (ADR-0020) */
	int net_miss_fd[8];
	int n_net_miss;
	int ncpu;                   /* possible CPUs: the counter maps' row count (ADR-0026) */
};

/* Returns 0, or a P15_EXIT_* code with a reason in err. */
P15_MUST_CHECK int p15_loader_start(struct p15_loader *l, uint32_t spine_ring_bytes, uint32_t bulk_ring_bytes, int net,
				  char *err, size_t errlen);
/* Detach every program (so the rings stop filling); the maps stay readable. */
void p15_loader_detach(struct p15_loader *l);
void p15_loader_free(struct p15_loader *l);
int p15_loader_spine_rb_fd(const struct p15_loader *l);
int p15_loader_counters_fd(const struct p15_loader *l);
int p15_loader_bulk_rb_fd(const struct p15_loader *l);     /* -1 with --no-net */
int p15_loader_bulk_counters_fd(const struct p15_loader *l);

#endif
