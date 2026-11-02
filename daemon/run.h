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

#define P15_POLL_BUCKETS 6         /* <=100us, <=1ms, <=10ms, <=100ms, <=1s, >1s (STATS) */
#define P15_SPINE_TYPES 5          /* index by record type 1..4 */

struct p15_run {
	struct p15_config cfg;
	uint32_t tgid;
	uint64_t start_ns;          /* the daemon's ADR-0009 identity start time (from the self-test) */
	uint32_t spine_ring_bytes;
	struct p15q q;

	_Atomic int state;          /* enum p15_run_state; only moves towards INVALID */
	_Atomic int stop;           /* a stop was requested (signal, duration, p15_fail) */
	_Atomic int stop_signal;
	_Atomic int fatal_code;     /* the first p15_fail code, or 0 */
	_Atomic int reason_set;
	char reason[256];           /* the first reason the state changed or the run failed */
	_Atomic int drain_done;     /* the drain detached, emptied the rings and published its last batch */

	/* drain side */
	_Atomic uint64_t bpf[P15_CTR_MAX];       /* the last read of the BPF per-CPU counters, summed */
	uint64_t bpf_base[P15_CTR_MAX];          /* their values when the drain started, after the self-test:
						  * every count the run reports is relative to it */
	_Atomic uint64_t drained[P15_SPINE_TYPES];
	_Atomic uint64_t spine_invalid, gap_records, spine_seq_next;
	_Atomic uint64_t poll_hist[P15_POLL_BUCKETS];
	_Atomic uint64_t poll_gap_max_ns;        /* interval field: the writer takes and resets it */
	_Atomic uint64_t spine_fill_max;         /* interval field */

	/* writer side */
	_Atomic uint64_t spine_written, spine_drain_lost;
	_Atomic int invariant;                   /* enum p15_invariant, set at the end */
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

#endif
