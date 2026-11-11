// SPDX-License-Identifier: MIT
/* The drain thread's work (ADR-0006 rule 4, ADR-0017 layers 2-4). See drain.h. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "counters.h"
#include "drain.h"
#include "p15_file.h"
#include "p15_records.h"
#include "records.h"
#include "wal.h"

void p15_daemon_hdr(const struct p15_run *r, void *rec, unsigned type, unsigned version, unsigned len)
{
	struct p15_hdr *h = rec;

	memset(h, 0, sizeof(*h));
	h->type = (__u16)type;
	h->version = (__u16)version;
	h->len = (__u16)len;
	h->ts_ns = p15_boot_ns();
	h->tgid = r->tgid;
	h->tid = (__u32)gettid();
	h->start_ns = r->start_ns;
}

static void publish(struct p15_drain *d)
{
	if (d->open && d->open->count)
		p15q_publish(&d->run->q);
	d->open = NULL;   /* an acquired but empty slot is simply acquired again next time */
}

/* How many more records of `ring` are certain to fit in its batch: the batch's free bytes over the
 * largest record of the schema. A batch of another ring, or one without that much room, is published
 * first and a fresh one acquired. 0: no batch is free (the queue is full; p15q_acquire counted it).
 *
 * This is asked BEFORE a ring is read, because a record cannot be handed back: libbpf advances the
 * consumer position before it calls the callback and stores it even when the callback fails
 * (third_party/libbpf/src/ringbuf.c, ringbuf_process_ring), so a record the callback refuses is
 * gone, uncounted (E-0173). */
uint32_t p15_drain_room(struct p15_drain *d, unsigned ring)
{
	if (d->open && (d->open->ring != ring || d->open->cap - d->open->len < P15_RECORD_MAX_SIZE))
		publish(d);
	if (!d->open) {
		d->open = p15q_acquire(&d->run->q, ring);
		if (!d->open)
			return 0;
	}
	return (d->open->cap - d->open->len) / P15_RECORD_MAX_SIZE;
}

/* Copy one record (len bytes) into a batch of `ring`. -ENOSPC if no batch is free: for a ring's
 * record that cannot happen after p15_drain_room, and the callbacks treat it as a bug. */
static int put(struct p15_drain *d, unsigned ring, const void *rec, uint32_t len)
{
	if (d->open && (d->open->ring != ring || d->open->len + len > d->open->cap))
		publish(d);
	if (!d->open) {
		d->open = p15q_acquire(&d->run->q, ring);
		if (!d->open)
			return -ENOSPC;
	}
	memcpy(d->open->buf + d->open->len, rec, len);
	d->open->len += len;
	d->open->count++;
	return 0;
}

static int on_spine(void *ctx, void *data, size_t size)
{
	struct p15_drain *d = ctx;
	const struct p15_hdr *h = data;
	const char *why;
	int rc;

	if (p15_rec_check(data, size, &why) || h->type >= P15_SPINE_TYPES || h->type == 0) {
		atomic_fetch_add(&d->run->spine_invalid, 1);
		p15_run_set_state(d->run, P15_RUN_INVALID, "a spine record failed its checks");
		return 0;                   /* consumed: never written */
	}
	rc = put(d, P15W_RING_SPINE, data, h->len);
	if (rc) {
		/* take() asked for room first, so this is a bug; the record is gone (libbpf has moved past
		 * it) and the books will not close: say why */
		p15_run_set_state(d->run, P15_RUN_INVALID, "a spine record had no room in its batch (a drain bug)");
		return 0;
	}
	atomic_fetch_add(&d->run->drained[h->type], 1);
	atomic_fetch_add(&d->run->spine_seq_next, 1);
	return 0;
}

static int read_counters(struct p15_drain *d, uint64_t sum[P15_CTR_MAX]);

static int on_bulk(void *ctx, void *data, size_t size)
{
	struct p15_drain *d = ctx;
	const struct p15_hdr *h = data;
	const char *why;
	int rc;

	int is_net = size >= sizeof(*h) && h->type == P15_T_NET;
	int is_file = size >= sizeof(*h) && p15_is_file_type(h->type);

	if (p15_rec_check(data, size, &why) || (!is_net && !is_file)) {
		/* a refused NET record on the NET books; anything else (file identity, or not even a known
		 * bulk type) on the file books, which own the ring when loaded */
		atomic_fetch_add(is_net || !d->run->files ? &d->run->net_invalid : &d->run->file_invalid, 1);
		p15_run_set_state(d->run, P15_RUN_DEGRADED, "a bulk record failed its checks");
		return 0;
	}
	rc = put(d, P15W_RING_BULK, data, h->len);
	if (rc) {
		p15_run_set_state(d->run, P15_RUN_INVALID, "a bulk record had no room in its batch (a drain bug)");
		return 0;
	}
	atomic_fetch_add(is_net ? &d->run->net_drained : &d->run->file_drained, 1);
	return 0;
}

static int read_map(const struct p15_counters *c, uint64_t sum[P15_CTR_MAX]);

/* The kernel's skip count of one program (bpf_prog_info.recursion_misses, ADR-0020 rule 3). */
static int prog_misses(int fd, uint64_t *out)
{
	struct bpf_prog_info info;
	__u32 len = sizeof(info);

	memset(&info, 0, sizeof(info));
	if (bpf_prog_get_info_by_fd(fd, &info, &len))
		return -errno;
	*out = info.recursion_misses;
	return 0;
}

/* The file programs' skips, absolute: the path fentry's (located: PATH_MISSING) and the kprobes' (lost). */
static int read_file_misses(const struct p15_run *r, uint64_t *fentry, uint64_t *kprobes)
{
	int rc;

	*fentry = *kprobes = 0;
	if (r->file_fentry_fd > 0 && (rc = prog_misses(r->file_fentry_fd, fentry)))
		return rc;
	for (int i = 0; i < r->n_file_kprobe; i++) {
		uint64_t v;

		if ((rc = prog_misses(r->file_kprobe_fd[i], &v)))
			return rc;
		*kprobes += v;
	}
	return 0;
}

/* Every program's skips, absolute: spine by record type, the network programs summed. */
static int read_misses(const struct p15_run *r, uint64_t spine[P15_SPINE_TYPES], uint64_t *net)
{
	int rc;

	for (int t = 0; t < P15_SPINE_TYPES; t++) {
		spine[t] = 0;
		if (r->miss_fd[t] > 0 && (rc = prog_misses(r->miss_fd[t], &spine[t])))
			return rc;
	}
	*net = 0;
	for (int i = 0; i < r->n_net_miss; i++) {
		uint64_t v;

		if ((rc = prog_misses(r->net_miss_fd[i], &v)))
			return rc;
		*net += v;
	}
	return 0;
}

int p15_drain_init(struct p15_drain *d, struct p15_run *run, int spine_rb_fd, int ctr_fd, int bulk_rb_fd,
		   int bulk_ctr_fd, int file_ctr_fd)
{
	memset(d, 0, sizeof(*d));
	d->run = run;
	if ((bulk_rb_fd >= 0) != (bulk_ctr_fd >= 0 || file_ctr_fd >= 0))
		return -EINVAL;                      /* the bulk ring and a counter map of its writers come together */
	d->ncpu = libbpf_num_possible_cpus();   /* the loader sized the counter maps with the same call */
	if (d->ncpu <= 0)
		return d->ncpu ? d->ncpu : -EINVAL;
	{
		int rc = p15_counters_map(&d->ctr, ctr_fd, d->ncpu);   /* ADR-0026: no map syscall from here on */

		if (rc)
			return rc;
		if (bulk_ctr_fd >= 0 && (rc = p15_counters_map(&d->bulk_ctr, bulk_ctr_fd, d->ncpu)))
			return rc;
		if (file_ctr_fd >= 0 && (rc = p15_counters_map(&d->file_ctr, file_ctr_fd, d->ncpu)))
			return rc;
	}
	d->rb = ring_buffer__new(spine_rb_fd, on_spine, d, NULL);
	if (!d->rb)
		return -errno;
	d->spine = ring_buffer__ring(d->rb, 0);
	if (bulk_rb_fd >= 0) {
		if (ring_buffer__add(d->rb, bulk_rb_fd, on_bulk, d))
			return -errno;
		d->bulk = ring_buffer__ring(d->rb, 1);
		if (bulk_ctr_fd >= 0) {
			int rc = read_map(&d->bulk_ctr, d->prev_bulk);

			if (rc)
				return rc;
			for (int k = 0; k < P15_CTR_MAX; k++) {
				run->bulk_base[k] = d->prev_bulk[k];
				atomic_store(&run->bulk[k], d->prev_bulk[k]);
			}
		}
		if (file_ctr_fd >= 0) {
			uint64_t fm;
			int rc = read_map(&d->file_ctr, d->prev_file);

			if (!rc)
				rc = read_file_misses(run, &fm, &d->prev_file_kprobe_missed);
			if (rc)
				return rc;
			for (int k = 0; k < P15_CTR_MAX; k++) {
				run->filec_base[k] = d->prev_file[k];
				atomic_store(&run->filec[k], d->prev_file[k]);
			}
			run->fentry_missed_base = fm;
			atomic_store(&run->fentry_missed, fm);
			run->file_kprobe_missed_base = d->prev_file_kprobe_missed;
			atomic_store(&run->file_kprobe_missed, d->prev_file_kprobe_missed);
		}
	}
	d->prev_read_ns = d->last_poll_ns = p15_boot_ns();
	/* the self-test's records were consumed by the self-test: the run's books start here */
	{
		int rc = read_counters(d, d->prev_ctr);

		if (rc)
			return rc;
		rc = read_misses(run, d->prev_missed, &d->prev_net_missed);
		if (rc)
			return rc;
		for (int t = 0; t < P15_SPINE_TYPES; t++) {
			run->missed_base[t] = d->prev_missed[t];
			atomic_store(&run->missed[t], d->prev_missed[t]);
		}
		run->net_missed_base = d->prev_net_missed;
		atomic_store(&run->net_missed, d->prev_net_missed);
		for (int k = 0; k < P15_CTR_MAX; k++) {
			run->bpf_base[k] = d->prev_ctr[k];
			atomic_store(&run->bpf[k], d->prev_ctr[k]);
		}
	}
	return 0;
}

void p15_drain_free(struct p15_drain *d)
{
	ring_buffer__free(d->rb);
	p15_counters_unmap(&d->ctr);
	p15_counters_unmap(&d->bulk_ctr);
	p15_counters_unmap(&d->file_ctr);
	d->rb = NULL;
}

/* Sum a counter map's rows, read through its mapping (ADR-0026). Kept fallible for the callers'
 * error paths, though a mapped read cannot fail. */
static int read_map(const struct p15_counters *c, uint64_t sum[P15_CTR_MAX])
{
	p15_counters_sum(c, sum);
	return 0;
}

static int read_counters(struct p15_drain *d, uint64_t sum[P15_CTR_MAX])
{
	return read_map(&d->ctr, sum);
}

static void emit_gap(struct p15_drain *d, uint64_t from, uint64_t to, const uint64_t *now_ctr, const uint64_t *now_missed)
{
	struct p15_gap g;
	uint64_t lost = 0;

	memset(&g, 0, sizeof(g));
#define DELTA(t, k) (now_ctr[P15_CTR_INDEX(t, k)] - d->prev_ctr[P15_CTR_INDEX(t, k)])
	g.fork_reserve_failed = DELTA(P15_T_FORK, P15_CK_RESERVE_FAILED);
	g.exec_reserve_failed = DELTA(P15_T_EXEC, P15_CK_RESERVE_FAILED);
	g.exit_reserve_failed = DELTA(P15_T_EXIT, P15_CK_RESERVE_FAILED);
	g.rename_reserve_failed = DELTA(P15_T_RENAME, P15_CK_RESERVE_FAILED);
	g.fork_build_failed = DELTA(P15_T_FORK, P15_CK_BUILD_FAILED);
	g.exec_build_failed = DELTA(P15_T_EXEC, P15_CK_BUILD_FAILED);
	g.exit_build_failed = DELTA(P15_T_EXIT, P15_CK_BUILD_FAILED);
	g.rename_build_failed = DELTA(P15_T_RENAME, P15_CK_BUILD_FAILED);
#undef DELTA
	g.fork_missed = now_missed[P15_T_FORK] - d->prev_missed[P15_T_FORK];
	g.exec_missed = now_missed[P15_T_EXEC] - d->prev_missed[P15_T_EXEC];
	g.exit_missed = now_missed[P15_T_EXIT] - d->prev_missed[P15_T_EXIT];
	g.rename_missed = now_missed[P15_T_RENAME] - d->prev_missed[P15_T_RENAME];
	lost = g.fork_reserve_failed + g.exec_reserve_failed + g.exit_reserve_failed + g.rename_reserve_failed +
	       g.fork_build_failed + g.exec_build_failed + g.exit_build_failed + g.rename_build_failed +
	       g.fork_missed + g.exec_missed + g.exit_missed + g.rename_missed;
	if (!lost)
		return;
	p15_daemon_hdr(d->run, &g, P15_T_GAP, P15_GAP_VERSION, sizeof(g));
	g.from_ns = from;
	g.to_ns = to;
	g.spine_seq = atomic_load(&d->run->spine_seq_next);
	p15_run_set_state(d->run, P15_RUN_INVALID, g.fork_missed + g.exec_missed + g.exit_missed + g.rename_missed
			  ? "spine events skipped by the kernel (recursion misses, GAP)" : "spine records lost (GAP)");
	/* a GAP must not wait behind a full queue silently: if no batch is free, retry next poll */
	if (put(d, P15W_RING_DAEMON, &g, sizeof(g))) {
		d->queue_full_now = 1;
		return;                     /* prev_ctr is not advanced, so the next GAP covers this loss too */
	}
	publish(d);
	atomic_fetch_add(&d->run->gap_records, 1);
	memcpy(d->prev_ctr, now_ctr, sizeof(d->prev_ctr));
	memcpy(d->prev_missed, now_missed, sizeof(d->prev_missed));
}

static void note_poll_gap(struct p15_drain *d, uint64_t now)
{
	static const uint64_t edge[P15_POLL_BUCKETS - 1] = { 100000, 1000000, 10000000, 100000000, 1000000000 };
	uint64_t gap = now - d->last_poll_ns, m = atomic_load(&d->run->poll_gap_max_ns);
	int b = 0;

	while (b < P15_POLL_BUCKETS - 1 && gap > edge[b])
		b++;
	atomic_fetch_add(&d->run->poll_hist[b], 1);
	while (gap > m && !atomic_compare_exchange_weak(&d->run->poll_gap_max_ns, &m, gap))
		;
	d->last_poll_ns = now;
}

int p15_spine_loss_changed(const uint64_t *prev_ctr, const uint64_t *now_ctr, const uint64_t *prev_missed,
			   const uint64_t *now_missed)
{
	int any = 0;

	for (int t = 1; t < P15_SPINE_TYPES; t++)
		any |= now_ctr[P15_CTR_INDEX(t, P15_CK_RESERVE_FAILED)] != prev_ctr[P15_CTR_INDEX(t, P15_CK_RESERVE_FAILED)] ||
		       now_ctr[P15_CTR_INDEX(t, P15_CK_BUILD_FAILED)] != prev_ctr[P15_CTR_INDEX(t, P15_CK_BUILD_FAILED)] ||
		       now_missed[t] != prev_missed[t];
	return any;
}

/* The file-identity counters after a poll (ADR-0015): a lost record or a skipped kprobe makes the
 * run DEGRADED; a skipped fentry does not (its open is written as PATH_MISSING). The live gauges'
 * high-water marks are kept here. */
static int after_poll_file(struct p15_drain *d)
{
	static const int lost[] = { P15_FC_OPEN_LOST, P15_FC_BACKING_LOST, P15_FC_MISSING_LOST, P15_FC_VERDICT_LOST,
				    P15_FC_CLOSE_LOST };
	uint64_t f[P15_CTR_MAX], fm, km, m;
	int rc = read_map(&d->file_ctr, f);

	if (!rc)
		rc = read_file_misses(d->run, &fm, &km);
	if (rc)
		return rc;
	for (int i = 0; i < P15_CTR_MAX; i++)
		atomic_store(&d->run->filec[i], f[i]);
	atomic_store(&d->run->fentry_missed, fm);
	atomic_store(&d->run->file_kprobe_missed, km);
	for (size_t i = 0; i < sizeof(lost) / sizeof(lost[0]); i++)
		if (f[lost[i]] != d->prev_file[lost[i]])
			p15_run_set_state(d->run, P15_RUN_DEGRADED, "file-identity records lost to a full bulk ring");
	if (km != d->prev_file_kprobe_missed)
		p15_run_set_state(d->run, P15_RUN_DEGRADED, "file-identity events skipped by the kernel (recursion misses)");
	/* a gauge's rows are read one by one, so a delete seen before its insert can wrap it for one
	 * read: such a value is not a high-water mark */
	m = atomic_load(&d->run->files_live_max);
	if (f[P15_FC_FILES_LIVE] > m && f[P15_FC_FILES_LIVE] < (1ull << 63))
		atomic_store(&d->run->files_live_max, f[P15_FC_FILES_LIVE]);
	m = atomic_load(&d->run->objs_live_max);
	if (f[P15_FC_OBJS_LIVE] > m && f[P15_FC_OBJS_LIVE] < (1ull << 63))
		atomic_store(&d->run->objs_live_max, f[P15_FC_OBJS_LIVE]);
	memcpy(d->prev_file, f, sizeof(f));
	d->prev_file_kprobe_missed = km;
	return 0;
}

static int after_poll(struct p15_drain *d)
{
	uint64_t now_ctr[P15_CTR_MAX], now_missed[P15_SPINE_TYPES], now_net_missed, from = d->prev_read_ns, to, fill, m;
	int rc;

	publish(d);
	fill = d->spine ? ring__avail_data_size(d->spine) : 0;
	m = atomic_load(&d->run->spine_fill_max);
	while (fill > m && !atomic_compare_exchange_weak(&d->run->spine_fill_max, &m, fill))
		;
	d->prev_read_ns = p15_boot_ns();
	rc = read_counters(d, now_ctr);
	if (!rc)
		rc = read_misses(d->run, now_missed, &now_net_missed);
	to = p15_boot_ns();
	if (rc)
		return rc;
	for (int t = 0; t < P15_SPINE_TYPES; t++)
		atomic_store(&d->run->missed[t], now_missed[t]);
	atomic_store(&d->run->net_missed, now_net_missed);
	if (now_net_missed != d->prev_net_missed)   /* network skips: counted, DEGRADED (ADR-0020 rule 3) */
		p15_run_set_state(d->run, P15_RUN_DEGRADED, "NET events skipped by the kernel (recursion misses)");
	d->prev_net_missed = now_net_missed;
	for (int k = 0; k < P15_CTR_MAX; k++)
		atomic_store(&d->run->bpf[k], now_ctr[k]);
	if (d->bulk && d->file_ctr.rows && (rc = after_poll_file(d)))
		return rc;
	if (d->bulk) {
		uint64_t f = ring__avail_data_size(d->bulk), bm = atomic_load(&d->run->bulk_fill_max);

		while (f > bm && !atomic_compare_exchange_weak(&d->run->bulk_fill_max, &bm, f))
			;
	}
	if (d->bulk && d->bulk_ctr.rows) {
		uint64_t b[P15_CTR_MAX];
		int k = P15_CTR_INDEX(P15_T_NET, P15_CK_RESERVE_FAILED);

		rc = read_map(&d->bulk_ctr, b);
		if (rc)
			return rc;
		for (int i = 0; i < P15_CTR_MAX; i++)
			atomic_store(&d->run->bulk[i], b[i]);
		if (b[k] != d->prev_bulk[k])           /* counted bulk loss: DEGRADED, never INVALID (ADR-0004 rule 4) */
			p15_run_set_state(d->run, P15_RUN_DEGRADED, "NET records lost to a full bulk ring");
		memcpy(d->prev_bulk, b, sizeof(b));
	}
	{
		if (p15_spine_loss_changed(d->prev_ctr, now_ctr, d->prev_missed, now_missed)) {
			emit_gap(d, from, to, now_ctr, now_missed);
		} else {
			memcpy(d->prev_ctr, now_ctr, sizeof(d->prev_ctr));
			memcpy(d->prev_missed, now_missed, sizeof(d->prev_missed));
		}
	}
	return 0;
}

/* Read one ring, never more than its batch has room for. What does not fit stays in the ring, which
 * absorbs the backlog (ADR-0017 layer 2); the kernel side counts a reserve that then fails. */
static int take(struct p15_drain *d, struct ring *r, unsigned wal_ring)
{
	int total = 0;

	for (;;) {
		uint32_t room = p15_drain_room(d, wal_ring);
		int got;

		if (!room) {
			if (ring__avail_data_size(r))
				d->queue_full_now = 1;
			return total;
		}
		got = ring__consume_n(r, room);
		if (got < 0)
			return got;
		total += got;
		if ((uint32_t)got < room)
			return total;       /* the ring is empty, or its next record is still being written */
	}
}

/* The spine first: when batches are scarce it gets the next free one. */
static int take_all(struct p15_drain *d)
{
	int n = d->spine ? take(d, d->spine, P15W_RING_SPINE) : 0, m;

	if (n < 0 || !d->bulk)
		return n;
	m = take(d, d->bulk, P15W_RING_BULK);
	return m < 0 ? m : n + m;
}

int p15_drain_poll(struct p15_drain *d, int timeout_ms)
{
	struct epoll_event ev[2];
	int n;

	d->queue_full_now = 0;
	/* Wait only: ring_buffer__poll would read the rings itself, without asking for room. Below the
	 * high-water mark records don't wake us (ADR-0020 rule 2), so the rings are read after every wait. */
	n = epoll_wait(ring_buffer__epoll_fd(d->rb), ev, 2, timeout_ms);
	if (n < 0 && errno != EINTR)
		return -errno;
	n = take_all(d);
	note_poll_gap(d, p15_boot_ns());
	if (n < 0)
		return n;
	n = after_poll(d);
	if (d->queue_full_now)
		usleep(1000);               /* the writer is behind: let it release batches (counted in q.full) */
	return n;
}

int p15_drain_finish(struct p15_drain *d)
{
	struct p15_watch wd = { 0 };
	int n, rc;

	do {
		d->queue_full_now = 0;
		n = take_all(d);
		publish(d);
		if (d->queue_full_now) {
			/* the writer is behind: wait for it, but not for a writer that stands still (E-0162) */
			if (p15_writer_stalled(d->run, &wd, p15_mono_ns()))
				return -ETIMEDOUT;
			usleep(1000);
		}
	} while (n > 0 || d->queue_full_now);
	if (n < 0)
		return n;
	rc = after_poll(d);
	atomic_store(&d->run->drain_done, 1);
	p15q_kick(&d->run->q);
	return rc;
}
