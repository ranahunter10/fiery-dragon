// SPDX-License-Identifier: MIT
/* The run state machine and the single fatal path (ADR-0019 G2). See run.h. */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "exitcodes.h"
#include "run.h"

static void set_reason(struct p15_run *r, const char *reason)
{
	int expected = 0;

	if (atomic_compare_exchange_strong(&r->reason_set, &expected, 1))
		snprintf(r->reason, sizeof(r->reason), "%s", reason);
}

void p15_run_set_state(struct p15_run *r, int state, const char *reason)
{
	int cur = atomic_load(&r->state);

	while (state > cur && !atomic_compare_exchange_weak(&r->state, &cur, state))
		;
	if (state > P15_RUN_RUNNING)
		set_reason(r, reason);
}

void p15_fail(struct p15_run *r, int exit_code, const char *reason)
{
	int expected = 0;

	atomic_compare_exchange_strong(&r->fatal_code, &expected, exit_code);
	p15_run_set_state(r, P15_RUN_INVALID, reason);
	atomic_store(&r->stop, 1);
	if (r->q.efd >= 0)
		p15q_kick(&r->q);
}

int p15_run_exit_code(struct p15_run *r)
{
	int f = atomic_load(&r->fatal_code);

	if (f)
		return f;
	switch (atomic_load(&r->state)) {
	case P15_RUN_RUNNING:
		return P15_EXIT_OK;
	case P15_RUN_DEGRADED:
		return P15_EXIT_DEGRADED;
	default:
		return P15_EXIT_INVALID;
	}
}

static uint64_t ns(clockid_t id)
{
	struct timespec t;

	clock_gettime(id, &t);
	return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

uint64_t p15_boot_ns(void) { return ns(CLOCK_BOOTTIME); }
uint64_t p15_mono_ns(void) { return ns(CLOCK_MONOTONIC); }
