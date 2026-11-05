// SPDX-License-Identifier: MIT
/* The drain thread's work (ADR-0006 rule 4, ADR-0017 layers 2-4). See drain.h. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "drain.h"
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

/* Copy one record (len bytes) into a batch of `ring`. -ENOSPC if no batch is free. */
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
		d->queue_full_now = 1;
		return rc;                  /* left in the ring: libbpf does not advance past it */
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

	if (p15_rec_check(data, size, &why) || h->type != P15_T_NET) {
		atomic_fetch_add(&d->run->net_invalid, 1);
		p15_run_set_state(d->run, P15_RUN_DEGRADED, "a bulk record failed its checks");
		return 0;
	}
	rc = put(d, P15W_RING_BULK, data, h->len);
	if (rc) {
		d->queue_full_now = 1;
		return rc;
	}
	atomic_fetch_add(&d->run->net_drained, 1);
	return 0;
}

static int read_map(struct p15_drain *d, int fd, uint64_t sum[P15_CTR_MAX]);

int p15_drain_init(struct p15_drain *d, struct p15_run *run, int spine_rb_fd, int ctr_fd, int bulk_rb_fd,
		   int bulk_ctr_fd)
{
	memset(d, 0, sizeof(*d));
	d->run = run;
	d->ctr_fd = ctr_fd;
	d->ncpu = libbpf_num_possible_cpus();
	if (d->ncpu <= 0)
		return d->ncpu ? d->ncpu : -EINVAL;
	d->ctr_vals = calloc((size_t)P15_CTR_MAX * (size_t)d->ncpu, sizeof(uint64_t));
	d->ctr_keys = calloc(P15_CTR_MAX, sizeof(uint32_t));
	if (!d->ctr_vals || !d->ctr_keys)
		return -ENOMEM;
	d->rb = ring_buffer__new(spine_rb_fd, on_spine, d, NULL);
	if (!d->rb)
		return -errno;
	d->spine = ring_buffer__ring(d->rb, 0);
	d->bulk_ctr_fd = bulk_ctr_fd;
	if (bulk_rb_fd >= 0) {
		if (ring_buffer__add(d->rb, bulk_rb_fd, on_bulk, d))
			return -errno;
		d->bulk = ring_buffer__ring(d->rb, 1);
		{
			int rc = read_map(d, bulk_ctr_fd, d->prev_bulk);

			if (rc)
				return rc;
			for (int k = 0; k < P15_CTR_MAX; k++) {
				run->bulk_base[k] = d->prev_bulk[k];
				atomic_store(&run->bulk[k], d->prev_bulk[k]);
			}
		}
	}
	d->prev_read_ns = d->last_poll_ns = p15_boot_ns();
	/* the self-test's records were consumed by the self-test: the run's books start here */
	{
		int rc = read_counters(d, d->prev_ctr);

		if (rc)
			return rc;
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
	free(d->ctr_vals);
	free(d->ctr_keys);
	d->rb = NULL;
	d->ctr_vals = NULL;
	d->ctr_keys = NULL;
}

/* Read and sum a per-CPU counter map in one batch lookup. */
static int read_map(struct p15_drain *d, int fd, uint64_t sum[P15_CTR_MAX])
{
	__u32 count = P15_CTR_MAX, out_batch;
	int rc;

	rc = bpf_map_lookup_batch(fd, NULL, &out_batch, d->ctr_keys, d->ctr_vals, &count, NULL);
	if (rc && errno != ENOENT)
		return -errno;
	if (count != P15_CTR_MAX)
		return -EIO;
	for (uint32_t k = 0; k < P15_CTR_MAX; k++) {
		sum[k] = 0;
		for (int c = 0; c < d->ncpu; c++)
			sum[k] += d->ctr_vals[(size_t)k * (size_t)d->ncpu + (size_t)c];
	}
	return 0;
}

static int read_counters(struct p15_drain *d, uint64_t sum[P15_CTR_MAX])
{
	return read_map(d, d->ctr_fd, sum);
}

static void emit_gap(struct p15_drain *d, uint64_t from, uint64_t to, const uint64_t *now_ctr)
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
	lost = g.fork_reserve_failed + g.exec_reserve_failed + g.exit_reserve_failed + g.rename_reserve_failed +
	       g.fork_build_failed + g.exec_build_failed + g.exit_build_failed + g.rename_build_failed;
	if (!lost)
		return;
	p15_daemon_hdr(d->run, &g, P15_T_GAP, P15_GAP_VERSION, sizeof(g));
	g.from_ns = from;
	g.to_ns = to;
	g.spine_seq = atomic_load(&d->run->spine_seq_next);
	p15_run_set_state(d->run, P15_RUN_INVALID, "spine records lost (GAP)");
	/* a GAP must not wait behind a full queue silently: if no batch is free, retry next poll */
	if (put(d, P15W_RING_DAEMON, &g, sizeof(g))) {
		d->queue_full_now = 1;
		return;                     /* prev_ctr is not advanced, so the next GAP covers this loss too */
	}
	publish(d);
	atomic_fetch_add(&d->run->gap_records, 1);
	memcpy(d->prev_ctr, now_ctr, sizeof(d->prev_ctr));
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

static int after_poll(struct p15_drain *d)
{
	uint64_t now_ctr[P15_CTR_MAX], from = d->prev_read_ns, to, fill, m;
	int rc;

	publish(d);
	fill = d->spine ? ring__avail_data_size(d->spine) : 0;
	m = atomic_load(&d->run->spine_fill_max);
	while (fill > m && !atomic_compare_exchange_weak(&d->run->spine_fill_max, &m, fill))
		;
	d->prev_read_ns = p15_boot_ns();
	rc = read_counters(d, now_ctr);
	to = p15_boot_ns();
	if (rc)
		return rc;
	for (int k = 0; k < P15_CTR_MAX; k++)
		atomic_store(&d->run->bpf[k], now_ctr[k]);
	if (d->bulk) {
		uint64_t b[P15_CTR_MAX], f = ring__avail_data_size(d->bulk), bm = atomic_load(&d->run->bulk_fill_max);
		int k = P15_CTR_INDEX(P15_T_NET, P15_CK_RESERVE_FAILED);

		while (f > bm && !atomic_compare_exchange_weak(&d->run->bulk_fill_max, &bm, f))
			;
		rc = read_map(d, d->bulk_ctr_fd, b);
		if (rc)
			return rc;
		for (int i = 0; i < P15_CTR_MAX; i++)
			atomic_store(&d->run->bulk[i], b[i]);
		if (b[k] != d->prev_bulk[k])           /* counted bulk loss: DEGRADED, never INVALID (ADR-0004 rule 4) */
			p15_run_set_state(d->run, P15_RUN_DEGRADED, "NET records lost to a full bulk ring");
		memcpy(d->prev_bulk, b, sizeof(b));
	}
	{
		int any = 0;

		for (int t = 1; t < P15_SPINE_TYPES; t++)
			any |= now_ctr[P15_CTR_INDEX(t, P15_CK_RESERVE_FAILED)] != d->prev_ctr[P15_CTR_INDEX(t, P15_CK_RESERVE_FAILED)] ||
			       now_ctr[P15_CTR_INDEX(t, P15_CK_BUILD_FAILED)] != d->prev_ctr[P15_CTR_INDEX(t, P15_CK_BUILD_FAILED)];
		if (any)
			emit_gap(d, from, to, now_ctr);
		else
			memcpy(d->prev_ctr, now_ctr, sizeof(d->prev_ctr));
	}
	return 0;
}

int p15_drain_poll(struct p15_drain *d, int timeout_ms)
{
	int n;

	d->queue_full_now = 0;
	n = ring_buffer__poll(d->rb, timeout_ms);
	note_poll_gap(d, p15_boot_ns());
	if (n < 0 && n != -ENOSPC && n != -EINTR)
		return n;
	n = after_poll(d);
	if (d->queue_full_now)
		usleep(1000);               /* the writer is behind: let it release batches (counted in q.full) */
	return n;
}

int p15_drain_finish(struct p15_drain *d)
{
	int n, rc;

	do {
		d->queue_full_now = 0;
		n = ring_buffer__consume(d->rb);
		publish(d);
		if (d->queue_full_now)
			usleep(1000);
	} while (n > 0 || d->queue_full_now);
	if (n < 0 && n != -ENOSPC)
		return n;
	rc = after_poll(d);
	atomic_store(&d->run->drain_done, 1);
	p15q_kick(&d->run->q);
	return rc;
}
