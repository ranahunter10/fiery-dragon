// SPDX-License-Identifier: MIT
/*
 * p15d_path: what each step of p15d's user-space path costs per record, without the kernel.
 *
 * The VM measured p15d at about 250 ns of CPU per open+close above idle (two records, E-0310's
 * evidence) and eAudit's collector at a median 48 ns per syscall (R-042 §4.3). This harness splits
 * p15d's share into the steps the code takes for every record, with p15d's own functions:
 *
 *   check   p15_rec_check on the record, as the drain's callback does (drain.c on_bulk)
 *   copy    the copy into the open batch (drain.c put)
 *   queue   p15q_acquire/publish/peek/release, per batch, divided by the records in it
 *   crc     p15_crc32c over the batch's payload (wal.c p15w_append checksums it)
 *   append  p15w_append of the whole batch to a WAL in DIR (CRC, header, writev; no fdatasync,
 *           sync_ns is set to an hour), divided by the records in it
 *   pipe    the whole path on two threads as p15d runs it, drain thread -> queue -> writer
 *           thread with the queue's eventfd, CPU (both threads, getrusage) per record
 *
 * Records are FLOW v1 (the fixed size a transfer writes) and CLOSE v1, alternating, so a batch
 * holds what an open+close and a transfer write. Each step is timed over ROUNDS rounds of about
 * 2^20 records; the median ns per record is printed with the minimum and maximum.
 *
 * Usage: p15d_path DIR [ROUNDS] [BATCH_KB]     DIR: an empty directory (tmpfs: no disk in the figure)
 *
 * Limits: a hot cache and one record shape; the kernel side (the ring, the epoll wake-ups) is not
 * here. The figures of the container are not the VM's; only relative steps carry over (INF).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "crc32c.h"
#include "p15_records.h"
#include "queue.h"
#include "records.h"
#include "wal.h"

#define NREC (1u << 20)
#define MAXR 15

static unsigned char flow_rec[sizeof(struct p15_flow_v1)], close_rec[sizeof(struct p15_close_v1)];
static uint32_t batch_cap;

static uint64_t now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

static uint64_t cpu_ns(void)
{
	struct rusage u;

	getrusage(RUSAGE_SELF, &u);
	return (uint64_t)(u.ru_utime.tv_sec + u.ru_stime.tv_sec) * 1000000000ull +
	       (uint64_t)(u.ru_utime.tv_usec + u.ru_stime.tv_usec) * 1000ull;
}

static void mk(unsigned char *b, unsigned type, unsigned len)
{
	struct p15_hdr *h = (void *)b;

	memset(b, 0, len);
	h->type = (uint16_t)type;
	h->version = 1;
	h->len = (uint16_t)len;
	h->ts_ns = 123456789;
	h->tgid = h->tid = 4242;
	h->start_ns = 99;
}

static const unsigned char *rec(uint32_t i, uint32_t *len)
{
	*len = i & 1 ? sizeof(close_rec) : sizeof(flow_rec);
	return i & 1 ? close_rec : flow_rec;
}

/* one batch's worth of records into buf; returns its length and the count */
static uint32_t fill(unsigned char *buf, uint32_t start, uint32_t *count)
{
	uint32_t off = 0, n = 0, len;

	for (;;) {
		const unsigned char *r = rec(start + n, &len);

		if (off + len > batch_cap)
			break;
		memcpy(buf + off, r, len);
		off += len;
		n++;
	}
	*count = n;
	return off;
}

static int cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return x < y ? -1 : x > y;
}

static void report(const char *name, double *v, int n)
{
	qsort(v, (size_t)n, sizeof(*v), cmp);
	printf("%-7s %8.1f ns/record  (min %.1f, max %.1f, %d rounds)\n", name, v[n / 2], v[0], v[n - 1], n);
}

static volatile uint32_t sink;

/* Closed segments are removed between rounds, so DIR (tmpfs) holds about one segment. */
static void prune(const char *dir, struct p15w *w)
{
	struct stat cur, st;
	struct dirent *e;
	char path[4096];
	DIR *d = opendir(dir);

	if (!d || fstat(p15w_fd(w), &cur))
		abort();
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		if (!stat(path, &st) && S_ISREG(st.st_mode) && st.st_ino != cur.st_ino && unlink(path))
			abort();
	}
	closedir(d);
}

static double step_check(void)
{
	const char *why;
	uint32_t len, bad = 0;
	uint64_t t0 = now_ns();

	for (uint32_t i = 0; i < NREC; i++) {
		const unsigned char *r = rec(i, &len);

		bad += p15_rec_check(r, len, &why) != 0;
	}
	sink = bad;
	return (double)(now_ns() - t0) / NREC;
}

static double step_copy(unsigned char *batch)
{
	uint32_t off = 0, len;
	uint64_t t0 = now_ns();

	for (uint32_t i = 0; i < NREC; i++) {
		const unsigned char *r = rec(i, &len);

		if (off + len > batch_cap)
			off = 0;
		memcpy(batch + off, r, len);
		off += len;
	}
	sink = batch[off / 2];
	return (double)(now_ns() - t0) / NREC;
}

static double step_queue(struct p15q *q, uint32_t per_batch)
{
	uint32_t batches = NREC / per_batch;
	uint64_t t0 = now_ns();

	for (uint32_t i = 0; i < batches; i++) {
		struct p15q_slot *s = p15q_acquire(q, 1);

		if (!s)
			abort();
		s->count = per_batch;
		p15q_publish(q);
		if (!p15q_peek(q))
			abort();
		p15q_release(q);
	}
	return (double)(now_ns() - t0) / ((double)batches * per_batch);
}

static double step_crc(const unsigned char *buf, uint32_t len, uint32_t per_batch)
{
	uint32_t batches = NREC / per_batch, c = 0;
	uint64_t t0 = now_ns();

	for (uint32_t i = 0; i < batches; i++)
		c ^= p15_crc32c(0, buf, len);
	sink = c;
	return (double)(now_ns() - t0) / ((double)batches * per_batch);
}

static double step_append(struct p15w *w, const unsigned char *buf, uint32_t len, uint32_t per_batch)
{
	uint32_t batches = NREC / per_batch;
	uint64_t t0 = now_ns();

	for (uint32_t i = 0; i < batches; i++)
		if (p15w_append(w, 1, per_batch, buf, len))
			abort();
	return (double)(now_ns() - t0) / ((double)batches * per_batch);
}

/* ---- the two-thread pipeline, as p15d: the drain fills batches, the writer appends them ---- */
struct pipe_ctx {
	struct p15q *q;
	struct p15w *w;
	uint32_t records;
	_Atomic int done;
};

static void *writer_thread(void *arg)
{
	struct pipe_ctx *c = arg;

	for (;;) {
		struct p15q_slot *s = p15q_peek(c->q);

		if (!s) {
			if (atomic_load(&c->done) && !p15q_peek(c->q))
				break;
			if (p15q_wait(c->q, 100))   /* as p15d's writer: sleep on the queue's eventfd */
				abort();
			continue;
		}
		if (p15w_append(c->w, s->ring, s->count, s->buf, s->len))
			abort();
		p15q_release(c->q);
	}
	return NULL;
}

static double step_pipe(struct p15q *q, struct p15w *w)
{
	struct pipe_ctx c = { .q = q, .w = w, .records = NREC };
	const char *why;
	pthread_t t;
	uint32_t i = 0, len;
	uint64_t c0 = cpu_ns();
	struct p15q_slot *s = NULL;

	if (pthread_create(&t, NULL, writer_thread, &c))
		abort();
	while (i < NREC) {
		const unsigned char *r = rec(i, &len);

		if (p15_rec_check(r, len, &why))
			abort();
		if (s && s->len + len > s->cap) {
			p15q_publish(q);
			s = NULL;
		}
		while (!s && !(s = p15q_acquire(q, 1)))
			usleep(100);        /* the queue is full: the drain waits, as p15d's does */
		memcpy(s->buf + s->len, r, len);
		s->len += len;
		s->count++;
		i++;
	}
	if (s)
		p15q_publish(q);
	atomic_store(&c.done, 1);
	p15q_kick(q);
	pthread_join(t, NULL);
	return (double)(cpu_ns() - c0) / NREC;
}

int main(int argc, char **argv)
{
	double v[6][MAXR];
	int rounds = argc > 2 ? atoi(argv[2]) : 9;
	unsigned char *batch;
	uint32_t per_batch, len;
	struct p15q q;
	struct p15w *w;
	struct p15w_opts o = { 0 };
	const char *why;

	if (argc < 2 || rounds < 1 || rounds > MAXR) {
		fprintf(stderr, "usage: %s DIR [ROUNDS 1..%d] [BATCH_KB]\n", argv[0], MAXR);
		return 2;
	}
	batch_cap = (argc > 3 ? (uint32_t)atoi(argv[3]) : 1024) * 1024u;
	mk(flow_rec, P15_T_FLOW, sizeof(flow_rec));
	((struct p15_flow_v1 *)flow_rec)->kind = 1;
	((struct p15_flow_v1 *)flow_rec)->count = 1;
	((struct p15_flow_v1 *)flow_rec)->bytes = 4096;
	((struct p15_flow_v1 *)flow_rec)->reason = P15_FLOW_REASON_SINGLE;
	mk(close_rec, P15_T_CLOSE, sizeof(close_rec));
	if (p15_rec_check(flow_rec, sizeof(flow_rec), &why) || p15_rec_check(close_rec, sizeof(close_rec), &why)) {
		fprintf(stderr, "the bench's records fail p15_rec_check: %s\n", why ? why : "?");
		return 1;
	}
	batch = malloc(batch_cap);
	if (!batch || p15q_init(&q, 16, batch_cap))
		return 1;
	len = fill(batch, 0, &per_batch);
	o.dir = argv[1];
	o.max_bytes = 64ull << 20;   /* p15d's default --rotate-mb: rotation is part of the cost */
	o.max_ns = 3600ull * 1000000000ull;
	o.sync_ns = 3600ull * 1000000000ull;
	if (p15w_open(&w, &o)) {
		fprintf(stderr, "p15w_open %s failed (an empty directory is needed)\n", argv[1]);
		return 1;
	}
	printf("p15d_path: FLOW %zu B and CLOSE %zu B alternating, %u records a %u KiB batch, crc32c=%s, %u records a round\n",
	       sizeof(flow_rec), sizeof(close_rec), per_batch, batch_cap / 1024, p15_crc32c_impl(), NREC);
	for (int r = 0; r < rounds; r++) {
		v[0][r] = step_check();
		v[1][r] = step_copy(batch);
		v[2][r] = step_queue(&q, per_batch);
		v[3][r] = step_crc(batch, len, per_batch);
		v[4][r] = step_append(w, batch, len, per_batch);
		v[5][r] = step_pipe(&q, w);
		prune(argv[1], w);
	}
	report("check", v[0], rounds);
	report("copy", v[1], rounds);
	report("queue", v[2], rounds);
	report("crc", v[3], rounds);
	report("append", v[4], rounds);
	report("pipe", v[5], rounds);
	printf("sum of the single-thread steps (check + copy + queue + append): %.1f ns/record; pipe is CPU of both threads\n",
	       v[0][rounds / 2] + v[1][rounds / 2] + v[2][rounds / 2] + v[4][rounds / 2]);
	if (p15w_close(w))
		return 1;
	free(batch);
	p15q_free(&q);
	return sink == 0xdeadbeef;
}
