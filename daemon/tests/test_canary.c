// SPDX-License-Identifier: MIT
/*
 * Unit tests for the canary's verdict (daemon/canary.c, ADR-0019 G4.4). The process and its reaping
 * are injected and the clock is the test's, so every path of the verdict is driven exactly:
 * what is a miss, what is late, what only delays the verdict, and what is neither. One case at the
 * end starts the real process and reaps it.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "canary.h"
#include "p15_file.h"

static int failures;

#define EXPECT(cond, msg) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

#define S 1000000000ull
#define MS 1000000ull
#define PID 4242

static struct p15_run run;
static int spawned, spawn_io, spawn_fail, reap_ready, reap_exec_failed;

static pid_t fake_spawn(struct p15_canary_state *c, int with_io)
{
	(void)c;
	spawned++;
	spawn_io = with_io;
	return spawn_fail ? -1 : PID;
}

static int fake_reap(pid_t pid, int *exec_failed)
{
	if (pid != PID || !reap_ready)
		return 0;
	*exec_failed = reap_exec_failed;
	return 1;
}

static void start(struct p15_canary_state *c, unsigned interval_s, unsigned want, unsigned blind)
{
	memset(&run, 0, sizeof(run));
	run.q.efd = -1;
	spawned = spawn_io = spawn_fail = reap_ready = reap_exec_failed = 0;
	p15_canary_init(c, &run, interval_s, want, blind, 100 * S);
	c->spawn = fake_spawn;
	c->reap = fake_reap;
}

static void see(struct p15_canary_state *c, unsigned type, uint32_t tgid)
{
	struct p15_fork f;

	memset(&f, 0, sizeof(f));
	f.h.type = (uint16_t)type;
	f.h.len = sizeof(f);
	f.h.tgid = type == P15_T_FORK ? 1 : tgid;   /* a FORK's header is the parent's */
	f.child_tgid = f.child_tid = tgid;
	p15_canary_see(c, &f.h);
}

static void see_all(struct p15_canary_state *c, uint32_t tgid)
{
	see(c, P15_T_FORK, tgid);
	see(c, P15_T_EXEC, tgid);
	see(c, P15_T_EXIT, tgid);
	see(c, P15_T_OPEN, tgid);
	see(c, P15_T_FLOW, tgid);
}

#define RUNS() atomic_load(&run.canary_runs)
#define MISSED() atomic_load(&run.canary_missed)
#define LATE() atomic_load(&run.canary_late)
#define BAD(f) atomic_load(&run.canary_bad_##f)
#define ALL5 (P15_CANARY_FORK | P15_CANARY_EXEC | P15_CANARY_EXIT | P15_CANARY_OPEN | P15_CANARY_FLOW)
#define STATE() atomic_load(&run.state)

static void test_off_and_schedule(void)
{
	struct p15_canary_state c;

	start(&c, 0, 0, 0);
	p15_canary_tick(&c, 1000 * S, 0);
	EXPECT(spawned == 0 && c.pid == 0, "interval 0: never started");

	start(&c, 10, 0, 0);
	p15_canary_tick(&c, 109 * S, 0);
	EXPECT(spawned == 0, "not before the first interval has passed");
	p15_canary_tick(&c, 110 * S, 0);
	EXPECT(spawned == 1 && c.pid == PID && spawn_io == 0, "started at the interval; no open or write without those programs");
	EXPECT(c.cur_want == (P15_CANARY_FORK | P15_CANARY_EXEC | P15_CANARY_EXIT), "the spine's three are always wanted");
	p15_canary_tick(&c, 130 * S, 0);
	EXPECT(spawned == 1, "one at a time: none started while one is in flight");

	start(&c, 10, P15_CANARY_FILES | P15_CANARY_FLOW | 0x80, 0);
	p15_canary_tick(&c, 110 * S, 0);
	EXPECT(spawn_io == 1 && c.cur_want == P15_CANARY_ALL, "with the file and flow programs: all seven, and no bit beyond them");
	start(&c, 10, P15_CANARY_FLOW, 0);
	p15_canary_tick(&c, 110 * S, 0);
	EXPECT(spawn_io == 1, "the flow programs alone still need the write");
}

static void test_all_seen(void)
{
	struct p15_canary_state c;

	start(&c, 10, P15_CANARY_FILES | P15_CANARY_FLOW, 0);
	run.filec[P15_FC_SESSION_ENTRY] = 500;
	run.filec[P15_FC_FREE_RUN] = 900;
	p15_canary_tick(&c, 110 * S, 0);
	see_all(&c, PID + 1);
	EXPECT(c.seen == 0, "another process's records prove nothing");
	see(&c, P15_T_FORK, PID);
	see(&c, P15_T_OPEN, PID);
	see(&c, P15_T_FLOW, PID);
	see(&c, P15_T_EXEC, PID);
	see(&c, P15_T_EXIT, PID);
	p15_canary_tick(&c, 110 * S + 10 * MS, 1);
	EXPECT(c.pid == PID && RUNS() == 0 && c.seen == ALL5, "the five records seen, the two programs' counters still: no verdict");
	run.filec[P15_FC_SESSION_ENTRY] = 501;
	p15_canary_tick(&c, 110 * S + 20 * MS, 1);
	EXPECT(c.pid == PID && (c.seen & P15_CANARY_SESSION) && !(c.seen & P15_CANARY_FREE), "the open session ran: its counter moved");
	run.filec[P15_FC_FREE_RUN] = 901;
	p15_canary_tick(&c, 110 * S + 30 * MS, 1);
	EXPECT(c.pid == PID && RUNS() == 0 && c.seen == P15_CANARY_ALL, "everything seen but not reaped: no verdict");
	reap_ready = 1;
	p15_canary_tick(&c, 110 * S + 2000 * MS, 1);
	EXPECT(c.pid == 0 && RUNS() == 1 && MISSED() == 0 && LATE() == 0 && STATE() == P15_RUN_RUNNING,
	       "reaped later: in time, because the last thing was seen in time");
	EXPECT(atomic_load(&run.canary_seq) == 0, "nothing published for a canary that passed");
	p15_canary_tick(&c, 119 * S, 0);
	EXPECT(spawned == 1, "the next one waits for its interval");
	p15_canary_tick(&c, 120 * S, 0);
	EXPECT(spawned == 2, "and starts at it");
}

/* Everything arrives, but later than the deadline: the pipeline stood still (a drain that was
 * stuck for less than the stall bound). ADR-0019 G4's confirmation: a stuck drain raises a miss. */
static void test_late(void)
{
	struct p15_canary_state c;
	uint64_t t = 110 * S;

	start(&c, 10, 0, 0);
	p15_canary_tick(&c, t, 0);
	see(&c, P15_T_FORK, PID);
	see(&c, P15_T_EXEC, PID);
	see(&c, P15_T_EXIT, PID);
	reap_ready = 1;
	p15_canary_tick(&c, t + 1500 * MS, 1);
	EXPECT(c.pid == 0 && RUNS() == 1 && LATE() == 1 && MISSED() == 0, "seen 1.5 s after the start: late, not a miss");
	EXPECT(STATE() == P15_RUN_DEGRADED && strstr(run.reason, "records late"), "the run is DEGRADED and says late");
	EXPECT(BAD(kind) == P15_CANARY_MISS_KIND_LATE && BAD(late_ms) == 500 && BAD(pid) == PID && BAD(want) == 7 &&
	       BAD(seen) == 7 && BAD(n) == 1 && (atomic_load(&run.canary_seq) & 1) == 0, "published: kind, lateness, masks; sequence even");

	start(&c, 10, 0, 0);
	p15_canary_tick(&c, t, 0);
	see(&c, P15_T_FORK, PID);
	see(&c, P15_T_EXEC, PID);
	see(&c, P15_T_EXIT, PID);
	reap_ready = 1;
	p15_canary_tick(&c, t + 1000 * MS, 1);
	EXPECT(c.pid == 0 && LATE() == 0 && RUNS() == 1, "seen exactly at the deadline: in time");
}

/* A FORK whose child is a thread of the canary's tgid is not the canary's FORK; a short record is
 * not read past its length. */
static void test_fork_match(void)
{
	struct p15_canary_state c;
	struct p15_fork f;

	start(&c, 10, 0, 0);
	p15_canary_tick(&c, 110 * S, 0);
	memset(&f, 0, sizeof(f));
	f.h.type = P15_T_FORK;
	f.h.len = sizeof(f);
	f.child_tgid = PID;
	f.child_tid = PID + 1;
	p15_canary_see(&c, &f.h);
	EXPECT(c.seen == 0, "a thread's FORK is not the process's");
	f.child_tid = PID;
	f.h.len = sizeof(f.h);
	p15_canary_see(&c, &f.h);
	EXPECT(c.seen == 0, "a FORK shorter than its layout is not read");
	f.h.len = sizeof(f);
	p15_canary_see(&c, &f.h);
	EXPECT(c.seen == P15_CANARY_FORK, "the canary's FORK");
}

static void test_miss(void)
{
	struct p15_canary_state c;
	uint64_t t = 110 * S;

	start(&c, 10, 0, 0);
	p15_canary_tick(&c, t, 0);
	see(&c, P15_T_FORK, PID);
	see(&c, P15_T_EXIT, PID);            /* its EXEC never comes */
	reap_ready = 1;
	p15_canary_tick(&c, t + 100 * MS, 0);
	p15_canary_tick(&c, t + 200 * MS, 0);
	p15_canary_tick(&c, t + 999 * MS, 0);
	EXPECT(c.pid == PID && MISSED() == 0, "before the deadline: no verdict, however many polls");
	p15_canary_tick(&c, t + 1000 * MS, 1);
	EXPECT(c.pid == PID && MISSED() == 0, "deadline passed but the poll took records: more may be queued, no verdict");
	p15_canary_tick(&c, t + 1100 * MS, 0);
	EXPECT(c.pid == 0 && RUNS() == 1 && MISSED() == 1, "deadline passed, rings empty: a miss");
	EXPECT(STATE() == P15_RUN_DEGRADED && strstr(run.reason, "records missing, mask 0x2 of 0x7"), "the run is DEGRADED, the reason names what is missing");
	EXPECT(BAD(kind) == P15_CANARY_MISS_KIND_RECORD && BAD(seen) == 5 && BAD(want) == 7 && BAD(late_ms) == 100,
	       "published: kind, seen and want, how long after the deadline");
}

/* The deadline alone is not enough: the drain must have polled P15_CANARY_POLLS times since the
 * canary started (a drain that slept through the second has not looked yet). */
static void test_polls_needed(void)
{
	struct p15_canary_state c;
	uint64_t t = 110 * S;

	start(&c, 10, 0, 0);
	p15_canary_tick(&c, t, 0);
	reap_ready = 1;
	p15_canary_tick(&c, t + 2 * S, 0);
	EXPECT(c.pid == PID, "first poll after the deadline: not yet");
	p15_canary_tick(&c, t + 2 * S + MS, 0);
	EXPECT(c.pid == PID, "second: not yet");
	p15_canary_tick(&c, t + 2 * S + 2 * MS, 0);
	EXPECT(c.pid == 0 && MISSED() == 1, "third empty poll: the verdict");
}

/* A gap between polls longer than P15_CANARY_STALL_NS is the guest standing still (E-0250), not
 * the programs: the second starts again from the poll that ended the gap. */
static void test_stall(void)
{
	struct p15_canary_state c;
	uint64_t t = 110 * S;

	start(&c, 10, 0, 0);
	p15_canary_tick(&c, t, 0);
	reap_ready = 1;
	p15_canary_tick(&c, t + 100 * MS, 0);
	p15_canary_tick(&c, t + 200 * MS, 0);
	p15_canary_tick(&c, t + 60 * S, 0);
	EXPECT(c.pid == PID && MISSED() == 0, "the poll after a 60 s gap takes no verdict");
	p15_canary_tick(&c, t + 60 * S + 999 * MS, 0);
	EXPECT(c.pid == PID && MISSED() == 0, "nor any poll in the second after it");
	see(&c, P15_T_FORK, PID);
	see(&c, P15_T_EXEC, PID);
	see(&c, P15_T_EXIT, PID);
	p15_canary_tick(&c, t + 61 * S, 0);
	EXPECT(c.pid == 0 && RUNS() == 1 && MISSED() == 0 && LATE() == 0 && atomic_load(&run.canary_stalled) == 1,
	       "records that arrive in that second: neither a miss nor late; the stall is counted");

	start(&c, 10, 0, 0);
	p15_canary_tick(&c, t, 0);
	reap_ready = 1;
	p15_canary_tick(&c, t + 100 * MS, 0);
	p15_canary_tick(&c, t + 5 * S, 0);
	EXPECT(c.pid == PID, "gap of 4.9 s, one poll short");
	p15_canary_tick(&c, t + 5 * S + MS, 0);
	EXPECT(c.pid == 0 && MISSED() == 1, "a gap under the stall bound does not restart the deadline");
}

/* The drain's wait came back late (the VM did not run the thread when its timer fired, E-0316):
 * that time moves the deadline, so the canary is not late; the excuse is counted stalled once. A
 * drain slow in its own work reports no oversleep and stays late (test_late). */
static void test_oversleep(void)
{
	struct p15_canary_state c;
	uint64_t t = 110 * S, stalled0;

	start(&c, 10, 0, 0);
	stalled0 = atomic_load(&run.canary_stalled);
	p15_canary_tick(&c, t, 0);
	p15_canary_oversleep(&c, 300 * MS);
	p15_canary_oversleep(&c, 300 * MS);
	see(&c, P15_T_FORK, PID);
	see(&c, P15_T_EXEC, PID);
	see(&c, P15_T_EXIT, PID);
	reap_ready = 1;
	p15_canary_tick(&c, t + 1500 * MS, 1);
	EXPECT(c.pid == 0 && LATE() == 0 && RUNS() == 1, "seen 1.5 s after the start, 600 ms of it the drain's oversleep: in time");
	EXPECT(atomic_load(&run.canary_stalled) == stalled0 + 1, "the excuse is counted stalled, once per canary");

	start(&c, 10, 0, 0);
	p15_canary_tick(&c, t, 0);
	p15_canary_oversleep(&c, 20 * MS);   /* at the bound: timer jitter, not excused */
	see(&c, P15_T_FORK, PID);
	see(&c, P15_T_EXEC, PID);
	see(&c, P15_T_EXIT, PID);
	reap_ready = 1;
	p15_canary_tick(&c, t + 1010 * MS, 1);
	EXPECT(c.pid == 0 && LATE() == 1, "an oversleep of 20 ms is not excused: 10 ms late");

	start(&c, 10, 0, 0);
	p15_canary_oversleep(&c, 900 * MS);  /* no canary in flight: nothing to move */
	p15_canary_tick(&c, t, 0);
	see(&c, P15_T_FORK, PID);
	see(&c, P15_T_EXEC, PID);
	see(&c, P15_T_EXIT, PID);
	reap_ready = 1;
	p15_canary_tick(&c, t + 1200 * MS, 1);
	EXPECT(c.pid == 0 && LATE() == 1, "an oversleep before the canary started does not move its deadline");

	/* every wait oversleeps (the VM, E-0318) and the EXEC never comes: the miss is still judged at
	 * the unmoved deadline, not pushed away poll after poll */
	start(&c, 10, 0, 0);
	p15_canary_tick(&c, t, 0);
	see(&c, P15_T_FORK, PID);
	see(&c, P15_T_EXIT, PID);
	reap_ready = 1;
	for (unsigned i = 1; i <= 12; i++) {
		p15_canary_oversleep(&c, 250 * MS);
		p15_canary_tick(&c, t + i * 100 * MS, 0);
	}
	EXPECT(c.pid == 0 && MISSED() == 1 && LATE() == 0 && BAD(kind) == P15_CANARY_MISS_KIND_RECORD && BAD(seen) == 5,
	       "chronic oversleep: the missing EXEC is still a miss, judged at the first empty poll after 1 s");
}

static void test_exec_failed(void)
{
	struct p15_canary_state c;
	uint64_t t = 110 * S;

	start(&c, 10, 0, 0);
	p15_canary_tick(&c, t, 0);
	see(&c, P15_T_FORK, PID);
	see(&c, P15_T_EXIT, PID);
	reap_ready = reap_exec_failed = 1;
	p15_canary_tick(&c, t + 10 * MS, 0);
	EXPECT(c.pid == 0 && RUNS() == 1 && MISSED() == 0 && atomic_load(&run.canary_exec_failed) == 1,
	       "the exec failed: its EXEC is not wanted, counted exec_failed, no miss");
	EXPECT(atomic_load(&run.canary_seq) == 0, "and nothing is published for it");
}

static void test_never_reaped(void)
{
	struct p15_canary_state c;
	uint64_t t = 110 * S;

	start(&c, 10, 0, 0);
	p15_canary_tick(&c, t, 0);
	see(&c, P15_T_FORK, PID);
	see(&c, P15_T_EXEC, PID);            /* it never exits: no EXIT, never reaped */
	for (unsigned i = 1; i <= 10; i++)
		p15_canary_tick(&c, t + i * S, 0);
	EXPECT(c.pid == PID && RUNS() == 0, "not reaped, within 11 s: no verdict");
	p15_canary_tick(&c, t + 11 * S, 0);
	EXPECT(c.pid == 0 && RUNS() == 1 && MISSED() == 1 && BAD(seen) == 3, "still unreaped 10 s after the deadline: a miss, so the canary cannot hang");
}

static void test_blind(void)
{
	struct p15_canary_state c;
	uint64_t t = 110 * S;

	start(&c, 10, 0, P15_CANARY_EXEC);
	p15_canary_tick(&c, t, 0);
	see_all(&c, PID);
	EXPECT(c.seen == (P15_CANARY_FORK | P15_CANARY_EXIT | P15_CANARY_OPEN | P15_CANARY_FLOW), "--test-canary-blind: that bit is never seen");
	c.blind |= P15_CANARY_SESSION;
	c.cur_want |= P15_CANARY_SESSION;
	run.filec[P15_FC_SESSION_ENTRY] = 7;
	p15_canary_tick(&c, t + MS, 0);
	EXPECT(!(c.seen & P15_CANARY_SESSION), "... nor a blinded counter");
	c.cur_want &= ~P15_CANARY_SESSION;
	reap_ready = 1;
	for (unsigned i = 1; i <= 12; i++)
		p15_canary_tick(&c, t + i * 100 * MS, 0);
	EXPECT(MISSED() == 1 && STATE() == P15_RUN_DEGRADED, "and the canary is a miss");
}

static void test_spawn_failed_and_stop(void)
{
	struct p15_canary_state c;

	start(&c, 10, 0, 0);
	spawn_fail = 1;
	p15_canary_tick(&c, 110 * S, 0);
	EXPECT(c.pid == 0 && atomic_load(&run.canary_spawn_failed) == 1 && RUNS() == 0 && STATE() == P15_RUN_RUNNING,
	       "a canary that could not be started is counted, and is not a miss");
	spawn_fail = 0;
	p15_canary_tick(&c, 119 * S, 0);
	EXPECT(spawned == 1, "the next attempt waits for its interval");
	p15_canary_tick(&c, 120 * S, 0);
	EXPECT(spawned == 2 && c.pid == PID, "and is made");
	p15_canary_stop(&c);
	EXPECT(c.pid == 0 && atomic_load(&run.canary_unfinished) == 1 && RUNS() == 0 && MISSED() == 0,
	       "stopped with one in flight: unfinished, no verdict");
	p15_canary_tick(&c, 500 * S, 0);
	EXPECT(spawned == 2, "none started after the stop");
	p15_canary_stop(&c);
	EXPECT(atomic_load(&run.canary_unfinished) == 1, "a second stop counts nothing");
}

/* The real process: started, exec'd /bin/true (or failed to, where there is none), reaped. No
 * record reaches this test, so its verdict would be a miss: stop before it. */
static void test_real_process(void)
{
	struct p15_canary_state c;
	struct timespec ts = { 0, 10 * 1000 * 1000 };
	uint64_t t0 = p15_mono_ns();
	int i;

	memset(&run, 0, sizeof(run));
	run.q.efd = -1;
	p15_canary_init(&c, &run, 1, P15_CANARY_FILES | P15_CANARY_FLOW, 0, t0 - S);
	p15_canary_tick(&c, t0, 0);
	EXPECT(c.pid > 0, "the real canary started");
	for (i = 0; i < 90 && !c.reaped; i++) {
		nanosleep(&ts, NULL);
		p15_canary_tick(&c, t0 + (uint64_t)(i + 1) * MS, 1);   /* took: no verdict */
	}
	EXPECT(c.reaped == 1, "and was reaped within 0.9 s");
	p15_canary_stop(&c);
}

int main(void)
{
	test_off_and_schedule();
	test_all_seen();
	test_late();
	test_fork_match();
	test_miss();
	test_polls_needed();
	test_stall();
	test_oversleep();
	test_exec_failed();
	test_never_reaped();
	test_blind();
	test_spawn_failed_and_stop();
	test_real_process();
	if (failures) {
		printf("test_canary: %d FAILED\n", failures);
		return 1;
	}
	printf("test_canary: all passed\n");
	return 0;
}
