/* SPDX-License-Identifier: MIT */
/*
 * The canary: a continuous self-test (ADR-0019 G4.4; docs/research/2026-11-14-canary-and-self-check.md).
 *
 * The books show that every event that entered a hook was accounted for. They cannot show that
 * events still enter the hooks: when a program stops running, its counters stop with it and every
 * book still closes (the design review's F-05). So every --canary-s seconds p15d starts one short
 * process and checks what that process must cause:
 *   - its FORK, EXEC and EXIT records, always (the spine's three tracepoints);
 *   - with file identity on: its OPEN record (the path program), and that the open session and
 *     security_file_free's program ran at all since it started (their run counters moved);
 *   - with the flow programs attached: its FLOW record (the vfs_write session).
 * A canary that fails is counted, logged, written in a CANARY_MISS record, and the run is DEGRADED.
 *
 * The process: fork; in the child, open /dev/null and write one byte to it (an OPEN and a FLOW of
 * the child, not of p15d, whose own transfers are excluded), then exec /bin/true as "fd-canary".
 *
 * The verdict, taken by the drain because the records travel through the rings:
 *   OK    everything wanted was seen within P15_CANARY_DEADLINE_NS of the start;
 *   LATE  everything was seen, but later than that: the pipeline stood still (a stuck drain);
 *   MISS  the deadline has passed, the drain has since polled at least P15_CANARY_POLLS times, the
 *         last of them finding the rings empty, and something wanted has not been seen.
 * A poll that comes more than P15_CANARY_STALL_NS after the previous one means the guest was not
 * scheduled (E-0250): the deadline starts again from that poll, and the canary is counted stalled.
 * A drain wait that returns more than P15_CANARY_OVERSLEEP_NS after its timeout moves the deadline
 * by the overshoot (p15_canary_oversleep), also counted stalled: on the VM such waits came back up
 * to 1 s late while p15d did nothing slow (E-0316).
 * A canary still in flight when the run stops gets no verdict and is counted unfinished.
 *
 * Everything here runs on the drain thread. The writer reads the result through p15_run's
 * canary fields (run.h), under their sequence counter.
 */
#ifndef P15_CANARY_H
#define P15_CANARY_H

#include <stdint.h>
#include <sys/types.h>

#include "exitcodes.h"   /* before the records: it names an enum that p15_records.h aliases */
#include "p15_records.h"
#include "run.h"

#define P15_CANARY_FORK (1u << 0)
#define P15_CANARY_EXEC (1u << 1)
#define P15_CANARY_EXIT (1u << 2)
#define P15_CANARY_OPEN (1u << 3)
#define P15_CANARY_FLOW (1u << 4)
#define P15_CANARY_SESSION (1u << 5)   /* the open session ran since the canary started (SESSION_ENTRY moved) */
#define P15_CANARY_FREE (1u << 6)      /* security_file_free's program ran since then (FREE_RUN moved) */
#define P15_CANARY_ALL 0x7fu
#define P15_CANARY_FILES (P15_CANARY_OPEN | P15_CANARY_SESSION | P15_CANARY_FREE)

#define P15_CANARY_DEADLINE_NS 1000000000ull   /* ADR-0019 G4.4: the records arrive within 1 s */
#define P15_CANARY_POLLS 3
#define P15_CANARY_STALL_NS 5000000000ull
/* A drain wait that returned more than this after its timeout was the scheduler's (or the host's)
 * delay, not the pipeline's: the canary's deadline moves by the whole overshoot (E-0316). */
#define P15_CANARY_OVERSLEEP_NS 20000000ull

struct p15_canary_state {
	struct p15_run *run;
	uint64_t interval_ns;       /* 0: off */
	unsigned want;              /* P15_CANARY_* the run's attached programs can deliver */
	unsigned blind;             /* TEST ONLY (--test-canary-blind): bits never marked seen, as a stopped program */
	int stopped;                /* the run is ending: no new canary */
	/* the canary in flight */
	pid_t pid;                  /* 0: none */
	unsigned seen, cur_want;
	uint64_t spawn_boot_ns, spawn_ns, deadline_ns, last_poll_ns;
	uint64_t all_seen_ns;       /* when the last wanted thing was seen (monotonic); 0: not yet */
	uint64_t base_session, base_free;   /* the two run counters when it started */
	unsigned polls;
	int reaped;
	int excused;                /* its deadline was moved for the drain's oversleep (counted stalled once) */
	uint64_t next_ns;           /* when the next one starts (monotonic) */
	uint64_t n;                 /* canaries started, for the nonce */
	/* injected for the unit test; NULL means the real ones */
	pid_t (*spawn)(struct p15_canary_state *c, int with_io);   /* > 0 the child's pid, <= 0 failed */
	int (*reap)(pid_t pid, int *exec_failed);            /* 1 reaped, 0 not yet */
};

/* want: P15_CANARY_FILES with file identity on, P15_CANARY_FLOW with the flow programs attached;
 * the spine's three are always wanted. interval_s 0 turns the canary off. */
void p15_canary_init(struct p15_canary_state *c, struct p15_run *run, unsigned interval_s, unsigned want, unsigned blind,
		     uint64_t now_mono_ns);
/* A record the drain took from a ring: marks what it proves about the canary in flight. */
void p15_canary_see(struct p15_canary_state *c, const struct p15_hdr *h);
/* After each poll: start a canary when one is due, reap it, take its verdict. took: records the
 * poll took from the rings. */
void p15_canary_tick(struct p15_canary_state *c, uint64_t now_mono_ns, int took);
/* The drain's wait returned `over_ns` after its timeout: the thread was not run when its timer fired.
 * On the VM such waits came back up to 1 s late while p15d itself did nothing slow (bpftrace, E-0316):
 * that time is not the pipeline's, so a canary in flight gets it added to its deadline. A drain that
 * is slow in its own work (case 23's pause, a blocked writer) is outside the wait and is not excused. */
void p15_canary_oversleep(struct p15_canary_state *c, uint64_t over_ns);
/* The run is ending: no new canary; one in flight gets no verdict (counted unfinished). */
void p15_canary_stop(struct p15_canary_state *c);

#endif
