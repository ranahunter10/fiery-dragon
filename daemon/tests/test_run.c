// SPDX-License-Identifier: MIT
/* Unit tests for the run state machine, the exit code and the accounting invariant
 * (daemon/run.c, daemon/writer.c p15_invariant_check; ADR-0006 rule 6, ADR-0019 G2). */
#include <stdio.h>
#include <string.h>

#include "exitcodes.h"
#include "p15_records.h"
#include "run.h"
#include "writer.h"

static int failures;

#define EXPECT(cond, msg) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

static struct p15_run r;

static void reset(void)
{
	memset(&r, 0, sizeof(r));
	r.q.efd = -1;
}

/* A consistent run: per type, seen = emitted + lost; emitted = drained + invalid; drained = written + lost. */
static void books(uint64_t seen, uint64_t emitted, uint64_t reserve_failed, uint64_t drained, uint64_t written)
{
	for (int t = 1; t < P15_SPINE_TYPES; t++) {
		r.bpf[P15_CTR_INDEX(t, P15_CK_SEEN)] = seen + 100;          /* + the base */
		r.bpf[P15_CTR_INDEX(t, P15_CK_EMITTED)] = emitted + 90;
		r.bpf[P15_CTR_INDEX(t, P15_CK_RESERVE_FAILED)] = reserve_failed + 10;
		r.bpf_base[P15_CTR_INDEX(t, P15_CK_SEEN)] = 100;
		r.bpf_base[P15_CTR_INDEX(t, P15_CK_EMITTED)] = 90;
		r.bpf_base[P15_CTR_INDEX(t, P15_CK_RESERVE_FAILED)] = 10;
		r.drained[t] = drained;
	}
	r.spine_written = written * (P15_SPINE_TYPES - 1);
}

int main(void)
{
	char why[200];

	reset();
	EXPECT(p15_run_exit_code(&r) == P15_EXIT_OK, "fresh run: exit 0");
	p15_run_set_state(&r, P15_RUN_DEGRADED, "first");
	p15_run_set_state(&r, P15_RUN_RUNNING, "back");
	EXPECT(r.state == P15_RUN_DEGRADED && p15_run_exit_code(&r) == P15_EXIT_DEGRADED, "never moves back; exit 3");
	p15_run_set_state(&r, P15_RUN_INVALID, "second");
	EXPECT(r.state == P15_RUN_INVALID && p15_run_exit_code(&r) == P15_EXIT_INVALID && !strcmp(r.reason, "first"),
	       "INVALID: exit 4; the first reason is kept");
	reset();
	p15_fail(&r, P15_EXIT_IO, "disk");
	p15_fail(&r, P15_EXIT_OSERR, "later");
	EXPECT(r.stop && r.state == P15_RUN_INVALID && p15_run_exit_code(&r) == P15_EXIT_IO && !strcmp(r.reason, "disk"),
	       "p15_fail: stop, INVALID, the first code and reason");

	reset();
	books(50, 45, 5, 45, 45);
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_CLOSED && r.invariant == P15_INV_CLOSED &&
	       r.state == P15_RUN_RUNNING, "consistent books close, relative to the base; state unchanged");
	reset();
	books(50, 45, 4, 45, 45);
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_BROKEN && strstr(why, "seen") &&
	       r.state == P15_RUN_INVALID && r.invariant == P15_INV_BROKEN, "seen != emitted + lost: broken, INVALID");
	reset();
	books(50, 45, 5, 44, 44);
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_BROKEN && strstr(why, "drained"),
	       "emitted != drained + invalid: broken");
	reset();
	books(50, 45, 5, 44, 44);
	r.spine_invalid = 4;
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_CLOSED, "invalid records count on the drain side");
	reset();
	books(50, 45, 5, 45, 44);
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_BROKEN && strstr(why, "written"),
	       "drained != written + drain_lost: broken");
	reset();
	books(50, 45, 5, 45, 44);
	r.spine_drain_lost = 4;
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_CLOSED, "drain_lost closes the last side");
	printf("%s: %d failures\n", __FILE__, failures);
	return failures != 0;
}
