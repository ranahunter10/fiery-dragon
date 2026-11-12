// SPDX-License-Identifier: MIT
/* Unit tests for the run state machine, the exit code and the accounting invariant
 * (daemon/run.c, daemon/writer.c p15_invariant_check; ADR-0006 rule 6, ADR-0019 G2). */
#include <stdio.h>
#include <string.h>

#include "drain.h"
#include "exitcodes.h"
#include "p15_file.h"
#include "p15_flow.h"
#include "p15_records.h"
#include "queue.h"
#include "run.h"
#include "wal.h"
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
	r.spine_selftest_consumed = 90 * (P15_SPINE_TYPES - 1);   /* the emitted base: taken by the self-test */
}

/* Gate 3: the drain's adaptive poll timeout */
static void test_poll_next(void)
{
	int t = P15_POLL_MIN_MS, seen[8], k = 0;

	EXPECT(p15_poll_next(P15_POLL_MIN_MS, 0, 0, 10) == 10, "max 10 ms: the timer of ADR-0020, unchanged");
	EXPECT(p15_poll_next(80, 3, 0, 200) == P15_POLL_MIN_MS, "a poll that took records: back to the minimum");
	EXPECT(p15_poll_next(80, 0, 1, 200) == P15_POLL_MIN_MS, "records left for want of a batch: the minimum");
	for (k = 0; k < 8; k++) {
		t = p15_poll_next(t, 0, 0, 200);
		seen[k] = t;
	}
	EXPECT(seen[0] == 20 && seen[1] == 40 && seen[2] == 80 && seen[3] == 160 && seen[4] == 200 && seen[7] == 200,
	       "empty polls double the timeout up to the maximum: 20 40 80 160 200 200");
	EXPECT(p15_poll_next(1000, 0, 0, 1000) == 1000 && p15_poll_next(0, 0, 0, 100) == P15_POLL_MIN_MS,
	       "bounded on both sides");
}

/* Gate 3: the writer waits until its next deadline, not on a 100 ms timer */
static void test_writer_wait(void)
{
	EXPECT(p15_writer_wait_ms(2000000000ull, 1000000000ull, UINT64_MAX) == P15_WRITER_WAIT_MAX_MS,
	       "STATS in 1 s, nothing to sync: the longest wait");
	EXPECT(p15_writer_wait_ms(1300000000ull, 1000000000ull, UINT64_MAX) == 300, "STATS in 300 ms: 300 ms");
	EXPECT(p15_writer_wait_ms(2000000000ull, 1000000000ull, 40500000ull) == 41, "a sync due in 40.5 ms: 41 ms, rounded up");
	EXPECT(p15_writer_wait_ms(900000000ull, 1000000000ull, UINT64_MAX) == 1, "STATS overdue: 1 ms, not 0");
	EXPECT(p15_writer_wait_ms(2000000000ull, 1000000000ull, 0) == 1, "the WAL due now: 1 ms");
}

/* ADR-0020 rule 3: a change in any spine type's ring loss, build loss or kernel skip calls for a GAP */
static void test_loss_changed(void)
{
	uint64_t pc[P15_CTR_MAX] = { 0 }, nc[P15_CTR_MAX] = { 0 }, pm[P15_SPINE_TYPES] = { 0 }, nm[P15_SPINE_TYPES] = { 0 };

	EXPECT(!p15_spine_loss_changed(pc, nc, pm, nm), "no change: no GAP");
	nc[P15_CTR_INDEX(P15_T_EXEC, P15_CK_SEEN)] = 5;
	nc[P15_CTR_INDEX(P15_T_EXEC, P15_CK_EMITTED)] = 5;
	EXPECT(!p15_spine_loss_changed(pc, nc, pm, nm), "records seen and emitted are not a loss");
	for (int t = 1; t < P15_SPINE_TYPES; t++) {
		nm[t] = 1;
		EXPECT(p15_spine_loss_changed(pc, nc, pm, nm), "a kernel skip of any spine type calls for a GAP");
		nm[t] = 0;
		nc[P15_CTR_INDEX(t, P15_CK_RESERVE_FAILED)] = 1;
		EXPECT(p15_spine_loss_changed(pc, nc, pm, nm), "a reserve failure of any spine type calls for a GAP");
		nc[P15_CTR_INDEX(t, P15_CK_RESERVE_FAILED)] = 0;
		nc[P15_CTR_INDEX(t, P15_CK_BUILD_FAILED)] = 1;
		EXPECT(p15_spine_loss_changed(pc, nc, pm, nm), "a build failure of any spine type calls for a GAP");
		nc[P15_CTR_INDEX(t, P15_CK_BUILD_FAILED)] = 0;
	}
	nm[0] = 7;   /* index 0 is not a spine type */
	EXPECT(!p15_spine_loss_changed(pc, nc, pm, nm), "slot 0 is ignored");
}

/* The drain asks for room before it reads a ring (E-0173): a record cannot be handed back to libbpf. */
static void test_drain_room(void)
{
	struct p15_drain d;
	struct p15q q;
	struct p15q_slot *s;
	const uint32_t cap = 3 * P15_RECORD_MAX_SIZE + 100;

	memset(&d, 0, sizeof(d));
	reset();
	EXPECT(p15q_init(&q, 4, cap) == 0, "queue");
	r.q = q;
	d.run = &r;
	EXPECT(p15_drain_room(&d, P15W_RING_BULK) == 3 && d.open && d.open->ring == P15W_RING_BULK, "a fresh batch: cap / the largest record");
	d.open->len = 100;
	d.open->count = 1;
	EXPECT(p15_drain_room(&d, P15W_RING_BULK) == 3, "exactly three still fit");
	d.open->len = 101;
	EXPECT(p15_drain_room(&d, P15W_RING_BULK) == 2, "one byte more: two");
	d.open->len = cap - P15_RECORD_MAX_SIZE;
	EXPECT(p15_drain_room(&d, P15W_RING_BULK) == 1 && p15q_depth(&r.q) == 0, "room for one: the batch is kept");
	d.open->len = cap - P15_RECORD_MAX_SIZE + 1;
	EXPECT(p15_drain_room(&d, P15W_RING_BULK) == 3 && p15q_depth(&r.q) == 1,
	       "less than one largest record free: published, a fresh batch");
	s = d.open;
	EXPECT(p15_drain_room(&d, P15W_RING_SPINE) == 3 && d.open == s && d.open->ring == P15W_RING_SPINE && p15q_depth(&r.q) == 1,
	       "an empty batch of another ring is taken over, not published");
	d.open->len = 8;
	d.open->count = 1;
	EXPECT(p15_drain_room(&d, P15W_RING_BULK) == 3 && p15q_depth(&r.q) == 2 && d.open->ring == P15W_RING_BULK,
	       "a batch of another ring with records is published first");
	d.open->len = 8;
	d.open->count = 1;
	EXPECT(p15_drain_room(&d, P15W_RING_SPINE) == 3 && p15q_depth(&r.q) == 3, "third published");
	d.open->len = 8;
	d.open->count = 1;
	EXPECT(p15_drain_room(&d, P15W_RING_BULK) == 0 && d.open == NULL && p15q_depth(&r.q) == 4 && atomic_load(&r.q.full) == 1,
	       "every batch taken: no room, counted, nothing acquired");
	EXPECT(p15_drain_room(&d, P15W_RING_SPINE) == 0 && atomic_load(&r.q.full) == 2, "still none");
	(void)p15q_peek(&r.q);
	p15q_release(&r.q);
	EXPECT(p15_drain_room(&d, P15W_RING_SPINE) == 3 && d.open, "the writer released one: room again");
	p15q_free(&r.q);
}

int main(void)
{
	test_loss_changed();
	test_poll_next();
	test_writer_wait();
	test_drain_room();
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
	       r.state == P15_RUN_RUNNING, "consistent books close, the self-test's records counted; state unchanged");
	r.spine_selftest_consumed -= 1;
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_BROKEN, "one record the self-test took, uncounted: broken");
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
	/* NET books (ADR-0004 rule 4): seen = emitted + reserve_failed + excluded; emitted = drained + self-test + invalid */
	reset();
	books(50, 45, 5, 45, 45);
	r.net = 1;
	r.bulk[P15_CTR_INDEX(P15_T_NET, P15_CK_SEEN)] = 30;
	r.bulk[P15_CTR_INDEX(P15_T_NET, P15_CK_EMITTED)] = 20;
	r.bulk[P15_CTR_INDEX(P15_T_NET, P15_CK_RESERVE_FAILED)] = 4;
	r.bulk[P15_CTR_INDEX(P15_T_NET, P15_CK_EXCLUDED)] = 6;
	r.net_selftest_consumed = 5;
	r.net_drained = 15;
	r.net_written = 15;
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_CLOSED, "NET books close");
	r.bulk[P15_CTR_INDEX(P15_T_NET, P15_CK_EXCLUDED)] = 5;
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_BROKEN && strstr(why, "NET: seen"), "NET seen side broken");
	r.bulk[P15_CTR_INDEX(P15_T_NET, P15_CK_EXCLUDED)] = 6;
	r.state = P15_RUN_RUNNING;
	r.net_written = 14;
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_BROKEN && strstr(why, "NET: emitted"), "NET written side broken");
	/* file-identity books (bpf/include/p15_file.h), with NET off: the shared ring is all file records */
	reset();
	books(50, 45, 5, 45, 45);
	r.files = 1;
	r.filec[P15_FC_FENTRY_RUN] = 20;
	r.filec[P15_FC_OPEN_EMITTED] = 16;
	r.filec[P15_FC_OPEN_LOST] = 1;
	r.filec[P15_FC_BACKING_EMITTED] = 2;
	r.filec[P15_FC_BACKING_LOST] = 1;
	r.filec[P15_FC_SESSION_ENTRY] = 22;
	r.filec[P15_FC_SESSION_NO_INODE] = 1;
	r.filec[P15_FC_SESSION_RETURN] = 21;
	r.filec[P15_FC_SESSION_COMMON] = 14;
	r.filec[P15_FC_MISSING_EMITTED] = 2;
	r.filec[P15_FC_WALKED] = 1;        /* ADR-0029: the return's OPENs = walked + without a path */
	r.filec[P15_FC_WALK_RACED] = 1;    /* parts of WALKED, not book terms */
	r.filec[P15_FC_WALK_UNNAMED] = 1;
	r.filec[P15_FC_RET_BACKING] = 1;   /* an overlay's real file, fentry skipped: BACKING from the return */
	r.filec[P15_FC_RET_BACKING_EMITTED] = 1;
	r.filec[P15_FC_RET_BACKING_VERDICT_EMITTED] = 1;
	r.filec[P15_FC_VERDICT_EMITTED] = 1;
	r.filec[P15_FC_VERDICT_LOST] = 1;
	r.filec[P15_FC_SESSION_NO_ENTRY] = 2;
	r.filec[P15_FC_FREE_RUN] = 30;
	r.filec[P15_FC_CLOSE_EMITTED] = 9;
	r.filec[P15_FC_CLOSE_LOST] = 1;
	r.filec[P15_FC_FREE_UNREGISTERED] = 20;
	r.file_selftest_consumed = 8;      /* emitted: 16 + 2 + 1 + 2 + 9 + 1 + 1 = 32 = 22 drained + 8 self-test + 2 invalid */
	r.file_drained = 22;
	r.file_invalid = 2;
	r.net_written = 21;                /* the bulk ring's writer side: 22 drained = 21 written + 1 lost in the drain */
	r.net_drain_lost = 1;
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_CLOSED, "file books close");
#define BREAKS(field, delta, word, msg) do { r.field += (delta); r.state = P15_RUN_RUNNING; \
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_BROKEN && strstr(why, word), msg); \
	r.field -= (delta); } while (0)
	BREAKS(filec[P15_FC_OPEN_LOST], 1, "fentry runs", "a fentry run unaccounted: broken");
	BREAKS(filec[P15_FC_FENTRY_NO_INODE], 1, "fentry runs", "the no-inode return is on the fentry books");
	BREAKS(filec[P15_FC_SESSION_NO_INODE], 1, "session entries", "session entry side broken");
	BREAKS(filec[P15_FC_SESSION_NO_COOKIE], 1, "session entries", "session return side broken");
	BREAKS(filec[P15_FC_MISSING_LOST], 1, "session entries", "a lost PATH_MISSING open is on the session books");
	BREAKS(filec[P15_FC_RET_BACKING], 1, "session entries", "the return's BACKING branch is on the session books");
	BREAKS(filec[P15_FC_WALKED], 1, "walked", "the return's OPENs = walked + without a path");
	BREAKS(filec[P15_FC_WALK_UNNAMED], 1, "walked", "... both terms");
	BREAKS(filec[P15_FC_RET_BACKING_LOST], 1, "BACKING", "the return's BACKING written + lost");
	BREAKS(filec[P15_FC_RET_BACKING_VERDICT_EMITTED], 1, "FILE: emitted", "the return's records are on the drain side");
	BREAKS(filec[P15_FC_FREE_UNREGISTERED], 1, "frees", "free side broken");
	BREAKS(file_selftest_consumed, 1, "FILE: emitted", "a record the self-test took, uncounted: broken");
	BREAKS(file_invalid, 1, "FILE: emitted", "invalid records are on the drain side");
	BREAKS(net_drain_lost, 1, "bulk ring", "the shared ring's writer side broken");
	r.state = P15_RUN_RUNNING;
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_CLOSED, "restored: closed again");

	/* data-flow books (bpf/include/p15_flow.h, B1 to B5), added to the same closed file-identity run.
	 * FLOW and FILE records share the bulk ring, so they add to the writer side (net_written). */
	r.flowc[P15_FLC_SESS_ENTRY] = 30;      /* B1: entries = returns + excluded self + excluded kthread */
	r.flowc[P15_FLC_V_EXCL_SELF] = 3;
	r.flowc[P15_FLC_V_EXCL_KTHREAD] = 2;
	r.flowc[P15_FLC_SESS_RETURN] = 25;     /* B2: returns = empty + failed + emit attempts */
	r.flowc[P15_FLC_V_EMPTY] = 4;
	r.flowc[P15_FLC_V_FAILED] = 1;
	r.flowc[P15_FLC_V_ATTEMPT] = 20;
	r.flowc[P15_FLC_SOCK_SEEN] = 18;       /* B3: sock = excluded + no-file + empty + failed + attempts */
	r.flowc[P15_FLC_S_EXCL_SELF] = 2;
	r.flowc[P15_FLC_S_EXCL_KTHREAD] = 1;
	r.flowc[P15_FLC_S_NO_FILE] = 3;
	r.flowc[P15_FLC_S_EMPTY] = 1;
	r.flowc[P15_FLC_S_FAILED] = 1;
	r.flowc[P15_FLC_S_ATTEMPT] = 10;
	r.flowc[P15_FLC_READ_EMITTED] = 12;    /* B4: attempts (20+10) = written (28) + lost (2) */
	r.flowc[P15_FLC_WRITE_EMITTED] = 6;
	r.flowc[P15_FLC_SEND_EMITTED] = 5;
	r.flowc[P15_FLC_RECV_EMITTED] = 5;
	r.flowc[P15_FLC_FLOW_LOST] = 2;
	r.flowc[P15_FLC_FILE_EMITTED] = 4;     /* B5: FLOW 28 + FILE 4 = drained 29 + self-test 2 + invalid 1 */
	r.flow_drained = 29;
	r.flow_selftest_consumed = 2;
	r.flow_invalid = 1;
	r.net_written += 29;                   /* the bulk ring carries the 29 drained flow records too */
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_CLOSED, "file and flow books close together");
	BREAKS(flowc[P15_FLC_V_EXCL_SELF], 1, "vfs entries", "B1: a vfs entry unaccounted");
	BREAKS(flowc[P15_FLC_V_EMPTY], 1, "vfs returns", "B2: a vfs return unaccounted");
	BREAKS(flowc[P15_FLC_S_NO_FILE], 1, "sock events", "B3: a sock event unaccounted");
	BREAKS(flowc[P15_FLC_FLOW_LOST], 1, "emit attempts", "B4: attempts != written + lost");
	BREAKS(flowc[P15_FLC_FILE_EMITTED], 1, "FLOW: written", "B5: a FILE record off the drain side");
	BREAKS(flow_selftest_consumed, 1, "FLOW: written", "B5: a record the self-test took, uncounted");
	BREAKS(flow_invalid, 1, "FLOW: written", "B5: invalid flow records are on the drain side");
	BREAKS(net_drain_lost, 1, "bulk ring", "the flow records count on the shared ring's writer side");
	r.state = P15_RUN_RUNNING;
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_CLOSED, "flow books restored: closed again");

	r.files = 0;
	r.filec[P15_FC_FREE_RUN] = 99;
	EXPECT(p15_invariant_check(&r, why, sizeof(why)) == P15_INV_CLOSED, "without file identity its books are not read");
	/* the stop's watchdog (E-0162): it counts observations 100 ms apart, not time */
	{
		struct p15_watch wd = { 0 };
		uint64_t t = 1000000000ull;
		int fired = 0, n;

		reset();
		r.cfg.stop_stall_s = 2;           /* 20 observations */
		EXPECT(!p15_writer_stalled(&r, &wd, t), "the first call only records");
		for (n = 1; n <= 40 && !fired; n++)
			fired = p15_writer_stalled(&r, &wd, t + (uint64_t)n * 100000000ull);
		EXPECT(fired && n - 1 == 20, "a still writer: fires at the 20th observation 100 ms apart");
		memset(&wd, 0, sizeof(wd));
		p15_writer_stalled(&r, &wd, t);
		for (n = 1; n <= 19; n++)
			p15_writer_stalled(&r, &wd, t + (uint64_t)n * 100000000ull);
		r.writer_beats++;                 /* one beat resets it */
		EXPECT(!p15_writer_stalled(&r, &wd, t + 20 * 100000000ull), "a beat before the limit resets the count");
		for (n = 21, fired = 0; n <= 39; n++)
			fired |= p15_writer_stalled(&r, &wd, t + (uint64_t)n * 100000000ull);
		EXPECT(!fired, "  ... so 19 more still observations do not fire");
		memset(&wd, 0, sizeof(wd));
		p15_writer_stalled(&r, &wd, t);
		EXPECT(!p15_writer_stalled(&r, &wd, t + 280ull * 1000000000ull), "a 280 s freeze is one observation, not 2,800");
		for (n = 0, fired = 0; n < 1000 && !fired; n++)
			fired = p15_writer_stalled(&r, &wd, t + 280ull * 1000000000ull + (uint64_t)n * 1000000ull);
		EXPECT(!fired, "  ... and calls 1 ms apart are not observations");
	}
	printf("%s: %d failures\n", __FILE__, failures);
	return failures != 0;
}
