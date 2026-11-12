/* SPDX-License-Identifier: MIT */
/*
 * The run: everything p15d's two threads share, the run state machine and the single fatal
 * path (ADR-0019 G2). There is no other global mutable state (ADR-0019 G5).
 *
 * Threads: the drain (main thread) writes the drain-side counters; the writer thread writes
 * the WAL-side ones; either may call p15_invalidate or p15_fail. Every shared field is atomic.
 */
#ifndef P15_RUN_H
#define P15_RUN_H

#include <stdatomic.h>
#include <stdint.h>

#include "compiler.h"
#include "config.h"
#include "p15_counters.h"
#include "queue.h"

enum p15_run_state { P15_RUN_RUNNING = 0, P15_RUN_DEGRADED = 1, P15_RUN_INVALID = 2 };
enum p15_invariant { P15_INV_NOT_CHECKED = 0, P15_INV_CLOSED = 1, P15_INV_BROKEN = 2 };
enum p15_closing { P15_CLOSING_NONE = 0, P15_CLOSING_ASKED = 1, P15_CLOSING_DONE = 2 };

#define P15_POLL_BUCKETS 6         /* <=100us, <=1ms, <=10ms, <=100ms, <=1s, >1s (STATS) */
#define P15_SPINE_TYPES 5          /* index by record type 1..4 */

struct p15_run {
	struct p15_config cfg;
	uint32_t tgid;
	uint64_t start_ns;          /* the daemon's ADR-0009 identity start time (from the self-test) */
	uint32_t spine_ring_bytes, bulk_ring_bytes;
	int net;                    /* the network-intent programs are loaded (ADR-0004) */
	int files;                  /* the file-identity programs are loaded (ADR-0015) */
	struct p15q q;

	_Atomic int state;          /* enum p15_run_state; only moves towards INVALID */
	_Atomic int stop;           /* a stop was requested (signal, duration, p15_fail) */
	_Atomic int stop_signal;
	_Atomic int fatal_code;     /* the first p15_fail code, or 0 */
	_Atomic int reason_set;
	char reason[256];           /* the first reason the state changed or the run failed */
	_Atomic int drain_done;     /* the drain detached, emptied the rings and published its last batch */

	/* drain side */
	_Atomic uint64_t bpf[P15_CTR_MAX];       /* the last read of the BPF counters, summed over their rows (ADR-0026) */
	uint64_t bpf_base[P15_CTR_MAX];          /* their values when the drain started, after the self-test:
						  * every count STATS reports is relative to it */
	uint64_t spine_selftest_consumed;        /* records the self-tests took from the rings before the drain */
	uint64_t net_selftest_consumed;          /* started: the invariant counts them (absolute counters) */
	_Atomic uint64_t drained[P15_SPINE_TYPES];
	_Atomic uint64_t spine_invalid, gap_records, spine_seq_next;
	_Atomic uint64_t poll_hist[P15_POLL_BUCKETS];
	_Atomic uint64_t poll_gap_max_ns;        /* interval field: the writer takes and resets it */
	_Atomic uint64_t spine_fill_max;         /* interval field */

	_Atomic uint64_t bulk[P15_CTR_MAX];      /* the bulk (NET) counters, as bpf[] for the spine */
	uint64_t bulk_base[P15_CTR_MAX];
	_Atomic uint64_t net_drained, net_invalid;
	_Atomic uint64_t bulk_fill_max;          /* interval field */

	/* file identity (ADR-0015, bpf/include/p15_file.h): counters by named slot, as bulk[] for NET */
	_Atomic uint64_t filec[P15_CTR_MAX];
	uint64_t filec_base[P15_CTR_MAX];
	uint64_t file_selftest_consumed;         /* file records the self-tests took from the bulk ring */
	_Atomic uint64_t file_drained, file_invalid;
	_Atomic uint64_t files_live_max, objs_live_max;   /* the most entries seen at a poll */
	int file_fentry_fd;                      /* the path fentry: its skips are written by the session return (ADR-0029), not lost */
	int file_kprobe_fd[3];                   /* the session and the frees: skips are losses */
	int n_file_kprobe;
	_Atomic uint64_t fentry_missed, file_kprobe_missed;
	uint64_t fentry_missed_base, file_kprobe_missed_base;

	/* events the kernel skipped before our programs ran (ADR-0020 rule 3): bpf_prog_info.recursion_misses
	 * of each attached program, read by the drain; *_base is the read after the self-tests */
	int miss_fd[P15_SPINE_TYPES];            /* by record type 1..4; 0 = none */
	int net_miss_fd[8];
	int n_net_miss;
	_Atomic uint64_t missed[P15_SPINE_TYPES];
	uint64_t missed_base[P15_SPINE_TYPES];
	_Atomic uint64_t net_missed;
	uint64_t net_missed_base;

	/* writer side */
	_Atomic uint64_t spine_written, spine_drain_lost;
	_Atomic uint64_t net_written, net_drain_lost;   /* every bulk-ring record (NET and file identity) */
	_Atomic int invariant;                   /* enum p15_invariant, set at the end */

	/* the closing snapshot (ADR-0023 rule 1): main asks while the hooks are attached, the writer
	 * (which owns the WAL) takes it, main waits for it, then detaches */
	_Atomic int closing_req;                 /* enum p15_closing */
	/* the stop's watchdog (E-0162): the writer adds one per loop and per snapshot batch; main watches it
	 * while it waits for the writer, and gives up when it stands still (p15_writer_stalled) */
	_Atomic uint64_t writer_beats;
	_Atomic int writer_exited;
	_Atomic int closing_result;              /* END closing_snapshot: 1 taken, 0 not, -errno failed */
};

/* Move the run to DEGRADED or INVALID (never back), keeping the first reason. */
void p15_run_set_state(struct p15_run *r, int state, const char *reason);
/* The single fatal path: INVALID, remember code and reason, request a stop, wake the writer. */
void p15_fail(struct p15_run *r, int exit_code, const char *reason);
/* The exit code the run ends with: the fatal code, else by state (0 / 3 / 4). */
int p15_run_exit_code(struct p15_run *r);
/* CLOCK_BOOTTIME and CLOCK_MONOTONIC in ns. */
uint64_t p15_boot_ns(void);
uint64_t p15_mono_ns(void);

/* The stop's watchdog. It counts observations at least 100 ms apart in which writer_beats did not
 * move, not seconds: a guest frozen by its host for minutes (E-0158) adds one observation when it
 * resumes, not the frozen span, so a freeze alone never fires it. */
struct p15_watch {
	uint64_t beats, at_ns;
	uint32_t still;
};

/* 1 when the writer stood still for cfg.stop_stall_s worth of observations. now_ns: CLOCK_MONOTONIC. */
int p15_writer_stalled(struct p15_run *r, struct p15_watch *w, uint64_t now_ns);

#endif
