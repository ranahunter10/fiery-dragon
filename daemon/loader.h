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
struct file_bpf;
struct bpf_link;

/* What to load besides the spine (config.h). */
struct p15_loader_opts {
	uint32_t spine_ring_bytes, bulk_ring_bytes;
	int net;                     /* the network-intent programs (ADR-0004) */
	int files;                   /* the file-identity programs (ADR-0015) */
	int flow;                    /* attach the data-flow programs (ADR-0005); needs files */
	int test_no_path_fentry;     /* TEST ONLY: leave the path fentry unattached (ADR-0015 confirmation 1) */
	int test_flow_file_fail_first; /* TEST ONLY: lose the first FILE record of every file (it_p15d case 14) */
	uint32_t file_map_entries, obj_map_entries;
};

struct p15_loader {
	struct spine_bpf *spine;
	struct net_bpf *net;        /* NULL with --no-net */
	struct file_bpf *file;      /* NULL with --no-files; owns the bulk ring when loaded (decision 19.4) */
	struct bpf_link *fd_iter_link; /* the snapshot's FD pass (ADR-0015 rule 7); NULL with --no-files */
	struct bpf_link *flow_links[6]; /* the flow programs (ADR-0005): attached after the self-tests so their I/O is not in the books */
	int n_flow_links;
	struct bpf_link *flow_open_link; /* the end's count of open calls (p15_flow.h): a task iterator, run once */
	int selftest_failed;       /* failed checks, or -errno if it could not run */
	int net_selftest_failed;
	int file_selftest_failed;
	unsigned long long file_consumed;   /* file-identity records the self-tests took from the bulk ring */
	unsigned long long flow_consumed;   /* FLOW and FILE records the flow self-test took from the bulk ring */
	int flow_selftest_failed;
	__u64 daemon_start_ns;     /* from the self-test (ADR-0009 identity of p15d) */
	__u64 spine_consumed;      /* records the self-tests took from the rings: part of the run's books */
	unsigned long long net_consumed;
	char manifest[1024];       /* the attached hooks, for the WAL header */
	int miss_fd[5];            /* program fds by spine record type 1..4, for recursion_misses (ADR-0020) */
	int net_miss_fd[8];
	int n_net_miss;
	int file_fentry_fd;         /* the path fentry: its skips are written by the session return (ADR-0029), not lost */
	int file_kprobe_fd[3];      /* the session and the two frees: their skips are losses */
	int n_file_kprobe;
	int flow_prog_fd[6];        /* the flow programs (ADR-0005): vfs_read/write/readv/writev and the two sock tracepoints */
	int n_flow_prog;
	int ncpu;                   /* possible CPUs: the counter maps' row count (ADR-0026) */
};

/* Returns 0, or a P15_EXIT_* code with a reason in err. */
P15_MUST_CHECK int p15_loader_start(struct p15_loader *l, const struct p15_loader_opts *o, char *err, size_t errlen);
/* The end of the flow programs' run, in two steps (bpf/include/p15_flow.h). Both do nothing and
 * return 0 when the flow programs are not attached.
 * p15_loader_flow_gate: shut the gate, a store into the mapped .bss. The caller then waits a grace
 * period (p15_barrier) before the count.
 * p15_loader_flow_count: run the task iterator that claims every open call into OPEN_AT_END.
 * Returns 0, or -errno if the iterator could not be created or read. */
void p15_loader_flow_gate(struct p15_loader *l);
P15_MUST_CHECK int p15_loader_flow_count(struct p15_loader *l);
/* Detach every program (so the rings stop filling); the maps stay readable. The spine is detached
 * last, as it is attached first: every record another program writes names a process, and that
 * process's EXIT belongs in the same run. */
void p15_loader_detach(struct p15_loader *l);
void p15_loader_free(struct p15_loader *l);
int p15_loader_spine_rb_fd(const struct p15_loader *l);
int p15_loader_counters_fd(const struct p15_loader *l);
int p15_loader_bulk_rb_fd(const struct p15_loader *l);     /* -1 with --no-net and --no-files */
int p15_loader_bulk_counters_fd(const struct p15_loader *l);  /* NET's counters; -1 with --no-net */
int p15_loader_file_counters_fd(const struct p15_loader *l);  /* -1 with --no-files */
int p15_loader_flow_counters_fd(const struct p15_loader *l);  /* data flow (ADR-0005); -1 with --no-files */

#endif
