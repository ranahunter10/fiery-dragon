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

static int invariant(struct p15_run *r, char *why, size_t n);

int p15_invariant_check(struct p15_run *r, char *why, size_t n)
{
	int inv = invariant(r, why, n);

	atomic_store(&r->invariant, inv);
	if (inv == P15_INV_BROKEN)
		p15_run_set_state(r, P15_RUN_INVALID, why);
	return inv;
}

static int invariant(struct p15_run *r, char *why, size_t n)
{
	uint64_t emitted = 0, drained = 0;

	for (int t = 1; t < P15_SPINE_TYPES; t++) {
		uint64_t seen = bpfc(r, t, P15_CK_SEEN), em = bpfc(r, t, P15_CK_EMITTED);
		uint64_t lost = bpfc(r, t, P15_CK_RESERVE_FAILED) + bpfc(r, t, P15_CK_BUILD_FAILED);

		if (seen != em + lost) {
			snprintf(why, n, "type %d: seen %llu != emitted %llu + lost %llu", t, (unsigned long long)seen,
				 (unsigned long long)em, (unsigned long long)lost);
			return P15_INV_BROKEN;
		}
		emitted += em;
		drained += atomic_load(&r->drained[t]);
	}
	if (emitted != drained + atomic_load(&r->spine_invalid)) {
		snprintf(why, n, "emitted %llu != drained %llu + invalid %llu", (unsigned long long)emitted,
			 (unsigned long long)drained, (unsigned long long)atomic_load(&r->spine_invalid));
		return P15_INV_BROKEN;
	}
	if (drained != atomic_load(&r->spine_written) + atomic_load(&r->spine_drain_lost)) {
		snprintf(why, n, "drained %llu != written %llu + drain_lost %llu", (unsigned long long)drained,
			 (unsigned long long)atomic_load(&r->spine_written),
			 (unsigned long long)atomic_load(&r->spine_drain_lost));
		return P15_INV_BROKEN;
	}
	if (r->net) {
		uint64_t seen = netc(r, P15_CK_SEEN), em = netc(r, P15_CK_EMITTED);
		uint64_t out = netc(r, P15_CK_RESERVE_FAILED) + netc(r, P15_CK_EXCLUDED);

		if (seen != em + out) {
			snprintf(why, n, "NET: seen %llu != emitted %llu + reserve_failed/excluded %llu",
				 (unsigned long long)seen, (unsigned long long)em, (unsigned long long)out);
			return P15_INV_BROKEN;
		}
		if (em != atomic_load(&r->net_drained) + atomic_load(&r->net_invalid) ||
		    atomic_load(&r->net_drained) != atomic_load(&r->net_written) + atomic_load(&r->net_drain_lost)) {
			snprintf(why, n, "NET: emitted %llu, drained %llu, invalid %llu, written %llu, drain_lost %llu",
				 (unsigned long long)em, (unsigned long long)atomic_load(&r->net_drained),
				 (unsigned long long)atomic_load(&r->net_invalid),
				 (unsigned long long)atomic_load(&r->net_written),
				 (unsigned long long)atomic_load(&r->net_drain_lost));
			return P15_INV_BROKEN;
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
	s.bulk_ring_bytes = r->bulk_ring_bytes;
	append(w, P15W_RING_DAEMON, 1, &s, sizeof(s));
}

static void stats(struct p15_writer *w, uint64_t now)
{
	struct p15_stats s;

	fill_stats(w, &s, now);
	append(w, P15W_RING_DAEMON, 1, &s, sizeof(s));
	if (w->run->net)
		net_stats(w);
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
	}
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

		if (p15q_wait(&r->q, 100))
			p15_fail(r, P15_EXIT_OSERR, "writer: wait on the queue failed");
		drain_queue(w);
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
	return NULL;
}
