// SPDX-License-Identifier: MIT
/* The WAL writer thread (ADR-0017 layer 2, ADR-0019 G4.1). See writer.h. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "drain.h"
#include "exitcodes.h"
#include "p15_file.h"
#include "p15_flow.h"
#include "p15_records.h"
#include "writer.h"

/* A NET counter since the run's start (run.h). */
static uint64_t netc(struct p15_run *r, int kind)
{
	int k = P15_CTR_INDEX(P15_T_NET, kind);

	return atomic_load(&r->bulk[k]) - r->bulk_base[k];
}

/* A BPF counter since the run's start (the self-test's own events excluded, run.h). */
static uint64_t bpfc(struct p15_run *r, int type, int kind)
{
	int k = P15_CTR_INDEX(type, kind);

	return atomic_load(&r->bpf[k]) - r->bpf_base[k];
}

/* A file-identity counter since the run's start (the self-tests' events excluded). */
static uint64_t filec(struct p15_run *r, int slot)
{
	return atomic_load(&r->filec[slot]) - r->filec_base[slot];
}

/* A data-flow counter since the run's start. */
static uint64_t flowc(struct p15_run *r, int slot)
{
	return atomic_load(&r->flowc[slot]) - r->flowc_base[slot];
}

/* bpf/include/p15_flow.h's books (B1 to B5), on absolute counters. Returns 0 if closed. */
static int flow_books(struct p15_run *r, char *why, size_t n)
{
#define L(slot) atomic_load(&r->flowc[P15_FLC_##slot])
	uint64_t emitted = L(READ_EMITTED) + L(WRITE_EMITTED) + L(SEND_EMITTED) + L(RECV_EMITTED);
	uint64_t taken = atomic_load(&r->flow_drained) + r->flow_selftest_consumed + atomic_load(&r->flow_invalid);

	if (L(SESS_ENTRY) != L(SESS_RETURN) + L(V_EXCL_SELF) + L(V_EXCL_KTHREAD)) {
		snprintf(why, n, "FLOW: vfs entries %llu != returns + excluded self + excluded kthread",
			 (unsigned long long)L(SESS_ENTRY));
		return -1;
	}
	if (L(SESS_RETURN) != L(V_EMPTY) + L(V_FAILED) + L(V_ATTEMPT)) {
		snprintf(why, n, "FLOW: vfs returns %llu != empty + failed + emit attempts", (unsigned long long)L(SESS_RETURN));
		return -1;
	}
	if (L(SOCK_SEEN) != L(S_EXCL_SELF) + L(S_EXCL_KTHREAD) + L(S_NO_FILE) + L(S_EMPTY) + L(S_FAILED) + L(S_ATTEMPT)) {
		snprintf(why, n, "FLOW: sock events %llu != excluded + no-file + empty + failed + emit attempts",
			 (unsigned long long)L(SOCK_SEEN));
		return -1;
	}
	if (L(V_ATTEMPT) + L(S_ATTEMPT) != emitted + L(FLOW_LOST)) {
		snprintf(why, n, "FLOW: emit attempts %llu != FLOW records written %llu + lost %llu",
			 (unsigned long long)(L(V_ATTEMPT) + L(S_ATTEMPT)), (unsigned long long)emitted,
			 (unsigned long long)L(FLOW_LOST));
		return -1;
	}
	if (emitted + L(FILE_EMITTED) != taken) {
		snprintf(why, n, "FLOW: written %llu (FLOW) + %llu (FILE) != drained %llu + %llu by the self-test + invalid %llu",
			 (unsigned long long)emitted, (unsigned long long)L(FILE_EMITTED),
			 (unsigned long long)atomic_load(&r->flow_drained), (unsigned long long)r->flow_selftest_consumed,
			 (unsigned long long)atomic_load(&r->flow_invalid));
		return -1;
	}
#undef L
	return 0;
}

/* bpf/include/p15_file.h's books, on absolute counters (ADR-0006 rule 6). Returns 0 if closed. */
static int file_books(struct p15_run *r, char *why, size_t n)
{
#define A(slot) atomic_load(&r->filec[P15_FC_##slot])
	uint64_t emitted = A(OPEN_EMITTED) + A(MISSING_EMITTED) + A(VERDICT_EMITTED) + A(BACKING_EMITTED) + A(CLOSE_EMITTED) +
			   A(RET_BACKING_EMITTED) + A(RET_BACKING_VERDICT_EMITTED);
	uint64_t taken = atomic_load(&r->file_drained) + r->file_selftest_consumed + atomic_load(&r->file_invalid);

	if (A(FENTRY_RUN) != A(OPEN_EMITTED) + A(OPEN_LOST) + A(BACKING_EMITTED) + A(BACKING_LOST) + A(FENTRY_NO_INODE)) {
		snprintf(why, n, "FILE: fentry runs %llu != OPEN and BACKING written or lost, or without an inode",
			 (unsigned long long)A(FENTRY_RUN));
		return -1;
	}
	if (A(SESSION_ENTRY) != A(SESSION_RETURN) + A(SESSION_NO_INODE) ||
	    A(SESSION_RETURN) != A(SESSION_COMMON) + A(MISSING_EMITTED) + A(MISSING_LOST) + A(VERDICT_EMITTED) +
					 A(VERDICT_LOST) + A(RET_BACKING) + A(SESSION_NO_COOKIE) + A(SESSION_NO_ENTRY)) {
		snprintf(why, n, "FILE: session entries %llu, returns %llu: not every run is accounted for",
			 (unsigned long long)A(SESSION_ENTRY), (unsigned long long)A(SESSION_RETURN));
		return -1;
	}
	if (A(MISSING_EMITTED) != A(WALKED) + A(WALK_UNNAMED) || A(RET_BACKING) != A(RET_BACKING_EMITTED) + A(RET_BACKING_LOST)) {
		snprintf(why, n, "FILE: the session return's OPENs %llu != walked %llu + without a path %llu, or its BACKING "
			 "branch %llu != written + lost", (unsigned long long)A(MISSING_EMITTED), (unsigned long long)A(WALKED),
			 (unsigned long long)A(WALK_UNNAMED), (unsigned long long)A(RET_BACKING));
		return -1;
	}
	if (A(FREE_RUN) != A(CLOSE_EMITTED) + A(CLOSE_LOST) + A(FREE_UNREGISTERED)) {
		snprintf(why, n, "FILE: frees %llu != CLOSE written or lost + unregistered", (unsigned long long)A(FREE_RUN));
		return -1;
	}
	if (emitted != taken) {
		snprintf(why, n, "FILE: emitted %llu != drained %llu + %llu by the self-tests + invalid %llu",
			 (unsigned long long)emitted, (unsigned long long)atomic_load(&r->file_drained),
			 (unsigned long long)r->file_selftest_consumed, (unsigned long long)atomic_load(&r->file_invalid));
		return -1;
	}
#undef A
	return 0;
}

static int invariant(struct p15_run *r, char *why, size_t n);

int p15_invariant_check(struct p15_run *r, char *why, size_t n)
{
	int inv = invariant(r, why, n);

	atomic_store(&r->invariant, inv);
	if (inv == P15_INV_BROKEN)
		p15_run_set_state(r, P15_RUN_INVALID, why);
	return inv;
}

/*
 * ADR-0006 rule 6, exactly: absolute counters since load, with the records the self-tests took
 * from the rings counted on the drain side. (A base taken after the self-test would race with
 * records emitted before it and drained after it.)
 */
static uint64_t abs_c(_Atomic uint64_t *a, int type, int kind)
{
	return atomic_load(&a[P15_CTR_INDEX(type, kind)]);
}

static int invariant(struct p15_run *r, char *why, size_t n)
{
	uint64_t emitted = 0, drained = r->spine_selftest_consumed;

	for (int t = 1; t < P15_SPINE_TYPES; t++) {
		uint64_t seen = abs_c(r->bpf, t, P15_CK_SEEN), em = abs_c(r->bpf, t, P15_CK_EMITTED);
		uint64_t lost = abs_c(r->bpf, t, P15_CK_RESERVE_FAILED) + abs_c(r->bpf, t, P15_CK_BUILD_FAILED);

		if (seen != em + lost) {
			snprintf(why, n, "type %d: seen %llu != emitted %llu + lost %llu", t, (unsigned long long)seen,
				 (unsigned long long)em, (unsigned long long)lost);
			return P15_INV_BROKEN;
		}
		emitted += em;
		drained += atomic_load(&r->drained[t]);
	}
	if (emitted != drained + atomic_load(&r->spine_invalid)) {
		snprintf(why, n, "emitted %llu != drained %llu (incl. %llu by the self-test) + invalid %llu",
			 (unsigned long long)emitted, (unsigned long long)drained,
			 (unsigned long long)r->spine_selftest_consumed, (unsigned long long)atomic_load(&r->spine_invalid));
		return P15_INV_BROKEN;
	}
	drained -= r->spine_selftest_consumed;
	if (drained != atomic_load(&r->spine_written) + atomic_load(&r->spine_drain_lost)) {
		snprintf(why, n, "drained %llu != written %llu + drain_lost %llu", (unsigned long long)drained,
			 (unsigned long long)atomic_load(&r->spine_written),
			 (unsigned long long)atomic_load(&r->spine_drain_lost));
		return P15_INV_BROKEN;
	}
	if (r->net) {
		uint64_t seen = abs_c(r->bulk, P15_T_NET, P15_CK_SEEN), em = abs_c(r->bulk, P15_T_NET, P15_CK_EMITTED);
		uint64_t out = abs_c(r->bulk, P15_T_NET, P15_CK_RESERVE_FAILED) + abs_c(r->bulk, P15_T_NET, P15_CK_EXCLUDED);
		uint64_t nd = atomic_load(&r->net_drained);

		if (seen != em + out) {
			snprintf(why, n, "NET: seen %llu != emitted %llu + reserve_failed/excluded %llu",
				 (unsigned long long)seen, (unsigned long long)em, (unsigned long long)out);
			return P15_INV_BROKEN;
		}
		if (em != nd + r->net_selftest_consumed + atomic_load(&r->net_invalid) ||
		    nd + atomic_load(&r->file_drained) + atomic_load(&r->flow_drained) !=
			    atomic_load(&r->net_written) + atomic_load(&r->net_drain_lost)) {
			snprintf(why, n, "NET: emitted %llu, drained %llu + %llu by the self-test, invalid %llu, written %llu, drain_lost %llu",
				 (unsigned long long)em, (unsigned long long)nd, (unsigned long long)r->net_selftest_consumed,
				 (unsigned long long)atomic_load(&r->net_invalid),
				 (unsigned long long)atomic_load(&r->net_written),
				 (unsigned long long)atomic_load(&r->net_drain_lost));
			return P15_INV_BROKEN;
		}
	}
	if (r->files) {
		if (file_books(r, why, n) || flow_books(r, why, n))
			return P15_INV_BROKEN;
		/* every bulk-ring record (NET, file identity and data flow) counts in net_written */
		if (!r->net) {
			uint64_t bulk = atomic_load(&r->file_drained) + atomic_load(&r->flow_drained);

			if (bulk != atomic_load(&r->net_written) + atomic_load(&r->net_drain_lost)) {
				snprintf(why, n, "bulk ring: drained %llu != written %llu + drain_lost %llu",
					 (unsigned long long)bulk, (unsigned long long)atomic_load(&r->net_written),
					 (unsigned long long)atomic_load(&r->net_drain_lost));
				return P15_INV_BROKEN;
			}
		}
	}
	snprintf(why, n, "closed");
	return P15_INV_CLOSED;
}

static void append(struct p15_writer *w, unsigned ring, uint32_t count, const void *buf, uint32_t len)
{
	int rc = p15w_append(w->wal, ring, count, buf, len);

	if (ring == P15W_RING_SPINE)
		atomic_fetch_add(rc ? &w->run->spine_drain_lost : &w->run->spine_written, count);
	else if (ring == P15W_RING_BULK)
		atomic_fetch_add(rc ? &w->run->net_drain_lost : &w->run->net_written, count);
	if (rc)
		p15_fail(w->run, P15_EXIT_IO, "WAL append failed");
}

static void clock_sync(struct p15_writer *w)
{
	struct p15_clock_sync c;
	struct timespec t;

	memset(&c, 0, sizeof(c));
	p15_daemon_hdr(w->run, &c, P15_T_CLOCK_SYNC, P15_CLOCK_SYNC_VERSION, sizeof(c));
	c.boottime_ns = c.h.ts_ns;
	c.monotonic_ns = p15_mono_ns();
	clock_gettime(CLOCK_REALTIME, &t);
	c.realtime_ns = (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
	c.read_spread_ns = p15_boot_ns() - c.boottime_ns;
	append(w, P15W_RING_DAEMON, 1, &c, sizeof(c));
}

static void fill_stats(struct p15_writer *w, struct p15_stats *s, uint64_t now)
{
	struct p15_run *r = w->run;
	const struct p15w_stats *ws = p15w_stats(w->wal);
	struct rusage ru;

	memset(s, 0, sizeof(*s));
	p15_daemon_hdr(r, s, P15_T_STATS, P15_STATS_VERSION, sizeof(*s));
#define T(name, type)                                                              \
	s->name##_seen = bpfc(r, type, P15_CK_SEEN);                                  \
	s->name##_emitted = bpfc(r, type, P15_CK_EMITTED);                            \
	s->name##_reserve_failed = bpfc(r, type, P15_CK_RESERVE_FAILED);              \
	s->name##_build_failed = bpfc(r, type, P15_CK_BUILD_FAILED);                  \
	s->name##_read_failed = bpfc(r, type, P15_CK_READ_FAILED);                    \
	s->name##_truncated = bpfc(r, type, P15_CK_TRUNCATED);                        \
	s->name##_drained = atomic_load(&r->drained[type]);
	T(fork, P15_T_FORK)
	T(exec, P15_T_EXEC)
	T(exit, P15_T_EXIT)
	T(rename, P15_T_RENAME)
#undef T
	s->spine_invalid = atomic_load(&r->spine_invalid);
	s->spine_written = atomic_load(&r->spine_written);
	s->spine_drain_lost = atomic_load(&r->spine_drain_lost);
	s->gap_records = atomic_load(&r->gap_records);
	s->poll_gap_le_100us = atomic_load(&r->poll_hist[0]);
	s->poll_gap_le_1ms = atomic_load(&r->poll_hist[1]);
	s->poll_gap_le_10ms = atomic_load(&r->poll_hist[2]);
	s->poll_gap_le_100ms = atomic_load(&r->poll_hist[3]);
	s->poll_gap_le_1s = atomic_load(&r->poll_hist[4]);
	s->poll_gap_gt_1s = atomic_load(&r->poll_hist[5]);
	s->poll_gap_max_ns = atomic_exchange(&r->poll_gap_max_ns, 0);
	s->spine_fill_max = atomic_exchange(&r->spine_fill_max, 0);
	s->queue_full = atomic_load(&r->q.full);
	s->wal_bytes = ws->file_bytes;
	s->wal_batches = ws->batches;
	s->wal_fsyncs = ws->fsyncs;
	s->wal_fsync_max_ns = p15w_take_fsync_max(w->wal);
	if (!getrusage(RUSAGE_SELF, &ru)) {
		s->cpu_user_us = (uint64_t)ru.ru_utime.tv_sec * 1000000u + (uint64_t)ru.ru_utime.tv_usec;
		s->cpu_sys_us = (uint64_t)ru.ru_stime.tv_sec * 1000000u + (uint64_t)ru.ru_stime.tv_usec;
		s->maxrss_kb = (uint64_t)ru.ru_maxrss;
	}
	s->interval_ns = now - w->prev_stats_ns;
	s->spine_ring_bytes = r->spine_ring_bytes;
	s->queue_depth_max = atomic_exchange(&r->q.depth_max, 0);
	s->queue_batches = r->q.n;
	s->run_state = (uint32_t)atomic_load(&r->state);
	/* ADR-0020 rule 3: events the kernel skipped, since the run's start */
	s->fork_missed = atomic_load(&r->missed[P15_T_FORK]) - r->missed_base[P15_T_FORK];
	s->exec_missed = atomic_load(&r->missed[P15_T_EXEC]) - r->missed_base[P15_T_EXEC];
	s->exit_missed = atomic_load(&r->missed[P15_T_EXIT]) - r->missed_base[P15_T_EXIT];
	s->rename_missed = atomic_load(&r->missed[P15_T_RENAME]) - r->missed_base[P15_T_RENAME];
}

/* Prometheus text format, written to PATH.tmp and renamed over PATH (ADR-0019 G4.2). */
static void textfile(struct p15_writer *w, const struct p15_stats *s)
{
	char tmp[4200];
	FILE *f;
	static const char *const names[] = { "", "fork", "exec", "exit", "rename" };

	if (!w->run->cfg.textfile)
		return;
	snprintf(tmp, sizeof(tmp), "%s.tmp", w->run->cfg.textfile);
	f = fopen(tmp, "w");
	if (!f) {
		p15_run_set_state(w->run, P15_RUN_DEGRADED, "textfile not writable");
		return;
	}
	fprintf(f, "# HELP p15_spine_events_total Spine hook events by record type and cause (ADR-0006).\n");
	fprintf(f, "# TYPE p15_spine_events_total counter\n");
	for (int t = 1; t < P15_SPINE_TYPES; t++) {
		static const char *const kinds[] = { "seen", "emitted", "reserve_failed", "read_failed", "truncated", "build_failed" };

		for (int k = 0; k < 6; k++)
			fprintf(f, "p15_spine_events_total{type=\"%s\",cause=\"%s\"} %llu\n", names[t], kinds[k],
				(unsigned long long)bpfc(w->run, t, k));
		fprintf(f, "p15_spine_events_total{type=\"%s\",cause=\"drained\"} %llu\n", names[t],
			(unsigned long long)atomic_load(&w->run->drained[t]));
		fprintf(f, "p15_spine_events_total{type=\"%s\",cause=\"kernel_skipped\"} %llu\n", names[t],
			(unsigned long long)(atomic_load(&w->run->missed[t]) - w->run->missed_base[t]));
	}
	fprintf(f, "# TYPE p15_spine_written_total counter\np15_spine_written_total %llu\n", (unsigned long long)s->spine_written);
	fprintf(f, "# TYPE p15_gap_records_total counter\np15_gap_records_total %llu\n", (unsigned long long)s->gap_records);
	fprintf(f, "# TYPE p15_queue_full_total counter\np15_queue_full_total %llu\n", (unsigned long long)s->queue_full);
	fprintf(f, "# TYPE p15_wal_bytes_total counter\np15_wal_bytes_total %llu\n", (unsigned long long)s->wal_bytes);
	fprintf(f, "# TYPE p15_poll_gap_max_seconds gauge\np15_poll_gap_max_seconds %.6f\n", (double)s->poll_gap_max_ns / 1e9);
	fprintf(f, "# TYPE p15_spine_fill_max_bytes gauge\np15_spine_fill_max_bytes %llu\n", (unsigned long long)s->spine_fill_max);
	if (w->run->net) {
		static const char *const nk[] = { "seen", "emitted", "reserve_failed" };

		fprintf(f, "# HELP p15_net_events_total NET hook events by cause (ADR-0004).\n# TYPE p15_net_events_total counter\n");
		for (int k = 0; k < 3; k++)
			fprintf(f, "p15_net_events_total{cause=\"%s\"} %llu\n", nk[k], (unsigned long long)netc(w->run, k));
		fprintf(f, "p15_net_events_total{cause=\"excluded\"} %llu\n", (unsigned long long)netc(w->run, P15_CK_EXCLUDED));
		fprintf(f, "p15_net_events_total{cause=\"written\"} %llu\n", (unsigned long long)atomic_load(&w->run->net_written));
		fprintf(f, "p15_net_events_total{cause=\"kernel_skipped\"} %llu\n",
			(unsigned long long)(atomic_load(&w->run->net_missed) - w->run->net_missed_base));
	}
	fprintf(f, "# HELP p15_run_state 0 RUNNING, 1 DEGRADED, 2 INVALID (ADR-0019 G2.3).\n# TYPE p15_run_state gauge\n");
	fprintf(f, "p15_run_state %u\n", s->run_state);
	if (fclose(f) || rename(tmp, w->run->cfg.textfile))
		p15_run_set_state(w->run, P15_RUN_DEGRADED, "textfile not writable");
}

static void net_stats(struct p15_writer *w)
{
	struct p15_run *r = w->run;
	struct p15_net_stats s;

	memset(&s, 0, sizeof(s));
	p15_daemon_hdr(r, &s, P15_T_NET_STATS, P15_NET_STATS_VERSION, sizeof(s));
	s.net_seen = netc(r, P15_CK_SEEN);
	s.net_emitted = netc(r, P15_CK_EMITTED);
	s.net_reserve_failed = netc(r, P15_CK_RESERVE_FAILED);
	s.net_excluded = netc(r, P15_CK_EXCLUDED);
	s.net_drained = atomic_load(&r->net_drained);
	s.net_invalid = atomic_load(&r->net_invalid);
	s.net_written = atomic_load(&r->net_written);
	s.net_drain_lost = atomic_load(&r->net_drain_lost);
	s.bulk_fill_max = atomic_exchange(&r->bulk_fill_max, 0);
	s.net_missed = atomic_load(&r->net_missed) - r->net_missed_base;   /* ADR-0020 rule 3 */
	s.bulk_ring_bytes = r->bulk_ring_bytes;
	append(w, P15W_RING_DAEMON, 1, &s, sizeof(s));
}

static void file_stats(struct p15_writer *w)
{
	struct p15_run *r = w->run;
	struct p15_file_stats s;

	memset(&s, 0, sizeof(s));
	p15_daemon_hdr(r, &s, P15_T_FILE_STATS, P15_FILE_STATS_VERSION, sizeof(s));
#define F(field, slot) s.field = filec(r, slot);
	F(fentry_run, P15_FC_FENTRY_RUN)
	F(fentry_no_inode, P15_FC_FENTRY_NO_INODE)
	F(open_emitted, P15_FC_OPEN_EMITTED)
	F(open_lost, P15_FC_OPEN_LOST)
	F(open_full_size, P15_FC_OPEN_FULL_SIZE)
	F(open_truncated, P15_FC_OPEN_TRUNCATED)
	F(open_path_error, P15_FC_OPEN_PATH_ERROR)
	F(backing_emitted, P15_FC_BACKING_EMITTED)
	F(backing_lost, P15_FC_BACKING_LOST)
	F(backing_user_unread, P15_FC_BACKING_USER_UNREAD)
	F(session_entry, P15_FC_SESSION_ENTRY)
	F(session_no_inode, P15_FC_SESSION_NO_INODE)
	F(session_return, P15_FC_SESSION_RETURN)
	F(session_common, P15_FC_SESSION_COMMON)
	F(missing_emitted, P15_FC_MISSING_EMITTED)
	F(missing_lost, P15_FC_MISSING_LOST)
	F(verdict_emitted, P15_FC_VERDICT_EMITTED)
	F(verdict_lost, P15_FC_VERDICT_LOST)
	F(session_no_cookie, P15_FC_SESSION_NO_COOKIE)
	F(session_no_entry, P15_FC_SESSION_NO_ENTRY)
	F(free_run, P15_FC_FREE_RUN)
	F(close_emitted, P15_FC_CLOSE_EMITTED)
	F(close_lost, P15_FC_CLOSE_LOST)
	F(free_unregistered, P15_FC_FREE_UNREGISTERED)
	F(inode_free_run, P15_FC_INODE_FREE_RUN)
	F(inode_free_hit, P15_FC_INODE_FREE_HIT)
	F(file_map_full, P15_FC_FILE_MAP_FULL)
	F(obj_map_full, P15_FC_OBJ_MAP_FULL)
	F(file_stale, P15_FC_FILE_STALE)
	F(obj_stale, P15_FC_OBJ_STALE)
	F(file_race, P15_FC_FILE_RACE)
	F(obj_race, P15_FC_OBJ_RACE)
	F(facts_dup, P15_FC_FACTS_DUP)
	F(subvol_unknown, P15_FC_SUBVOL_UNKNOWN)
	F(kthread_open, P15_FC_KTHREAD_OPEN)
	F(walked, P15_FC_WALKED)
	F(walk_raced, P15_FC_WALK_RACED)
	F(walk_truncated, P15_FC_WALK_TRUNCATED)
	F(walk_unnamed, P15_FC_WALK_UNNAMED)
	F(ret_backing, P15_FC_RET_BACKING)
	F(ret_backing_emitted, P15_FC_RET_BACKING_EMITTED)
	F(ret_backing_lost, P15_FC_RET_BACKING_LOST)
	F(ret_backing_verdict_emitted, P15_FC_RET_BACKING_VERDICT_EMITTED)
	F(ret_backing_verdict_lost, P15_FC_RET_BACKING_VERDICT_LOST)
#undef F
	s.files_live = atomic_load(&r->filec[P15_FC_FILES_LIVE]);   /* gauges: absolute, not since the start */
	s.objs_live = atomic_load(&r->filec[P15_FC_OBJS_LIVE]);
	s.files_live_max = atomic_load(&r->files_live_max);
	s.objs_live_max = atomic_load(&r->objs_live_max);
	s.file_drained = atomic_load(&r->file_drained);
	s.file_invalid = atomic_load(&r->file_invalid);
	s.fentry_missed = atomic_load(&r->fentry_missed) - r->fentry_missed_base;
	s.kprobe_missed = atomic_load(&r->file_kprobe_missed) - r->file_kprobe_missed_base;
	s.file_map_entries = r->cfg.file_map_entries;
	s.obj_map_entries = r->cfg.obj_map_entries;
	append(w, P15W_RING_DAEMON, 1, &s, sizeof(s));
}

/* FLOW_STATS (ADR-0005, schema/records.toml): the data-flow counters since the run's start, their
 * drain side, and the kernel's skips. One field per bpf/include/p15_flow.h slot. */
static void flow_stats(struct p15_writer *w)
{
	struct p15_run *r = w->run;
	struct p15_flow_stats s;

	memset(&s, 0, sizeof(s));
	p15_daemon_hdr(r, &s, P15_T_FLOW_STATS, P15_FLOW_STATS_VERSION, sizeof(s));
#define F(field, slot) s.field = flowc(r, slot);
	F(sess_entry, P15_FLC_SESS_ENTRY)
	F(sess_return, P15_FLC_SESS_RETURN)
	F(v_excl_self, P15_FLC_V_EXCL_SELF)
	F(v_excl_kthread, P15_FLC_V_EXCL_KTHREAD)
	F(v_empty, P15_FLC_V_EMPTY)
	F(v_failed, P15_FLC_V_FAILED)
	F(v_attempt, P15_FLC_V_ATTEMPT)
	F(sock_seen, P15_FLC_SOCK_SEEN)
	F(s_excl_self, P15_FLC_S_EXCL_SELF)
	F(s_excl_kthread, P15_FLC_S_EXCL_KTHREAD)
	F(s_no_file, P15_FLC_S_NO_FILE)
	F(s_empty, P15_FLC_S_EMPTY)
	F(s_failed, P15_FLC_S_FAILED)
	F(s_attempt, P15_FLC_S_ATTEMPT)
	F(read_emitted, P15_FLC_READ_EMITTED)
	F(write_emitted, P15_FLC_WRITE_EMITTED)
	F(send_emitted, P15_FLC_SEND_EMITTED)
	F(recv_emitted, P15_FLC_RECV_EMITTED)
	F(flow_lost, P15_FLC_FLOW_LOST)
	F(start_unknown, P15_FLC_START_UNKNOWN)
	F(unregistered, P15_FLC_UNREGISTERED)
	F(file_emitted, P15_FLC_FILE_EMITTED)
	F(file_lost, P15_FLC_FILE_LOST)
	F(file_map_full, P15_FLC_FILE_MAP_FULL)
#undef F
	s.flow_drained = atomic_load(&r->flow_drained);
	s.flow_invalid = atomic_load(&r->flow_invalid);
	s.flow_missed = atomic_load(&r->flow_missed) - r->flow_missed_base;
	append(w, P15W_RING_DAEMON, 1, &s, sizeof(s));
}

static void stats(struct p15_writer *w, uint64_t now)
{
	struct p15_stats s;

	fill_stats(w, &s, now);
	append(w, P15W_RING_DAEMON, 1, &s, sizeof(s));
	if (w->run->net)
		net_stats(w);
	if (w->run->files) {
		file_stats(w);
		flow_stats(w);
	}
	textfile(w, &s);
	w->prev_stats_ns = now;
	if (++w->stats_written % 10 == 0)
		clock_sync(w);
}

static void end_record(struct p15_writer *w)
{
	struct { struct p15_end e; char tail[P15_END_REASON_MAX + 8]; } buf;
	char why[200];
	size_t rl;
	int inv = p15_invariant_check(w->run, why, sizeof(why));
	char reason[256];

	if (atomic_load(&w->run->reason_set))
		snprintf(reason, sizeof(reason), "%s", w->run->reason);
	else
		snprintf(reason, sizeof(reason), "stop requested");
	rl = strlen(reason);
	memset(&buf, 0, sizeof(buf));
	p15_daemon_hdr(w->run, &buf.e, P15_T_END, P15_END_VERSION, (unsigned)((sizeof(buf.e) + rl + 7) & ~7u));
	buf.e.exit_code = (uint32_t)p15_run_exit_code(w->run);
	buf.e.run_state = (uint32_t)atomic_load(&w->run->state);
	buf.e.invariant = (uint32_t)inv;
	buf.e.signal = (uint32_t)atomic_load(&w->run->stop_signal);
	buf.e.closing_snapshot = atomic_load(&w->run->closing_result);
	buf.e.reason_full = (uint32_t)rl;
	buf.e.reason_len = (uint16_t)rl;
	memcpy(buf.tail, reason, rl);
	append(w, P15W_RING_DAEMON, 1, &buf, buf.e.h.len);
}

static void drain_queue(struct p15_writer *w)
{
	struct p15q_slot *s;

	while ((s = p15q_peek(&w->run->q))) {
		append(w, s->ring, s->count, s->buf, s->len);
		p15q_release(&w->run->q);
		if (w->run->cfg.writer_batch_ms) {
			atomic_fetch_add(&w->run->writer_beats, 1);       /* slow, not stuck (E-0162) */
			usleep(w->run->cfg.writer_batch_ms * 1000u);  /* TEST ONLY: config.test_writer_batch_ms */
		}
	}
}

/* ADR-0023 rule 1: the closing snapshot, on this thread because it owns the WAL. The batches the
 * drain published before the request go first, so the snapshot follows them in the WAL. */
static void closing_snapshot(struct p15_writer *w)
{
	if (w->run->cfg.writer_stall_ms)
		usleep(w->run->cfg.writer_stall_ms * 1000u);   /* TEST ONLY: config.test_writer_stall_ms in the header */
	int rc;

	drain_queue(w);
	rc = w->closing ? w->closing(w->closing_ctx, w->wal) : -ENOSYS;
	if (rc < 0 && rc != -ENOSYS)
		p15_fail(w->run, P15_EXIT_IO, "WAL append failed in the closing snapshot");
	atomic_store(&w->run->closing_result, rc == 0 ? 1 : rc < 0 ? rc : -EPROTO);
	atomic_store(&w->run->closing_req, P15_CLOSING_DONE);
}

int p15_writer_wait_ms(uint64_t stats_due, uint64_t now, uint64_t wal_due_ns)
{
	uint64_t ns = stats_due > now ? stats_due - now : 0;

	if (wal_due_ns < ns)
		ns = wal_due_ns;
	ns = (ns + 999999) / 1000000;   /* up: never wake before the deadline and spin */
	return ns < 1 ? 1 : ns > P15_WRITER_WAIT_MAX_MS ? P15_WRITER_WAIT_MAX_MS : (int)ns;
}

void *p15_writer_main(void *arg)
{
	struct p15_writer *w = arg;
	struct p15_run *r = w->run;
	uint64_t stats_ns = (uint64_t)r->cfg.stats_ms * 1000000ull;

	w->prev_stats_ns = p15_boot_ns();
	clock_sync(w);
	for (;;) {
		uint64_t now;

		atomic_fetch_add(&r->writer_beats, 1);   /* the stop's watchdog (E-0162) */
		if (p15q_wait(&r->q, p15_writer_wait_ms(w->prev_stats_ns + stats_ns, p15_boot_ns(), p15w_due_ns(w->wal))))
			p15_fail(r, P15_EXIT_OSERR, "writer: wait on the queue failed");
		drain_queue(w);
		if (atomic_load(&r->closing_req) == P15_CLOSING_ASKED)
			closing_snapshot(w);
		if (p15w_tick(w->wal))
			p15_fail(r, P15_EXIT_IO, "WAL tick (rotate or fdatasync) failed");
		now = p15_boot_ns();
		if (now - w->prev_stats_ns >= stats_ns)
			stats(w, now);
		if (atomic_load(&r->drain_done) && !p15q_peek(&r->q))
			break;
		if (atomic_load(&r->fatal_code) && atomic_load(&r->drain_done))
			break;
	}
	drain_queue(w);
	stats(w, p15_boot_ns());
	end_record(w);
	w->close_rc = p15w_close(w->wal);
	w->wal = NULL;
	atomic_store(&r->writer_exited, 1);
	return NULL;
}
