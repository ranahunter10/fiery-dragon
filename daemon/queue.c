// SPDX-License-Identifier: MIT
/* Bounded SPSC batch queue (ADR-0017 layer 2). See queue.h for the contract. */
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "queue.h"

int p15q_init(struct p15q *q, uint32_t n, uint32_t cap)
{
	memset(q, 0, sizeof(*q));
	q->efd = -1;
	if (n < 2 || cap < 32)
		return -EINVAL;
	q->slots = calloc(n, sizeof(*q->slots));
	if (!q->slots)
		return -ENOMEM;
	q->n = n;
	for (uint32_t i = 0; i < n; i++) {
		q->slots[i].cap = cap;
		q->slots[i].buf = malloc(cap);
		if (!q->slots[i].buf) {
			p15q_free(q);
			return -ENOMEM;
		}
	}
	q->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (q->efd < 0) {
		int rc = -errno;

		p15q_free(q);
		return rc;
	}
	return 0;
}

void p15q_free(struct p15q *q)
{
	if (q->slots)
		for (uint32_t i = 0; i < q->n; i++)
			free(q->slots[i].buf);
	free(q->slots);
	q->slots = NULL;
	if (q->efd >= 0)
		close(q->efd);
	q->efd = -1;
}

struct p15q_slot *p15q_acquire(struct p15q *q, unsigned ring)
{
	uint64_t h = atomic_load_explicit(&q->head, memory_order_relaxed);
	uint64_t t = atomic_load_explicit(&q->tail, memory_order_acquire);
	struct p15q_slot *s;

	if (h - t >= q->n) {
		atomic_fetch_add_explicit(&q->full, 1, memory_order_relaxed);
		return NULL;
	}
	s = &q->slots[h % q->n];
	s->ring = ring;
	s->count = 0;
	s->len = 0;
	return s;
}

void p15q_publish(struct p15q *q)
{
	uint64_t h = atomic_load_explicit(&q->head, memory_order_relaxed) + 1;
	uint64_t one = 1;
	uint32_t d, m;

	atomic_store_explicit(&q->head, h, memory_order_release);
	d = (uint32_t)(h - atomic_load_explicit(&q->tail, memory_order_acquire));
	m = atomic_load_explicit(&q->depth_max, memory_order_relaxed);
	while (d > m && !atomic_compare_exchange_weak_explicit(&q->depth_max, &m, d, memory_order_relaxed,
							       memory_order_relaxed))
		;
	/* a full eventfd counter (impossible at 2^64-1) is the only failure; the consumer also polls */
	if (write(q->efd, &one, sizeof(one)) < 0)
		return;
}

struct p15q_slot *p15q_peek(struct p15q *q)
{
	uint64_t t = atomic_load_explicit(&q->tail, memory_order_relaxed);
	uint64_t h = atomic_load_explicit(&q->head, memory_order_acquire);

	return t == h ? NULL : &q->slots[t % q->n];
}

void p15q_release(struct p15q *q)
{
	atomic_store_explicit(&q->tail, atomic_load_explicit(&q->tail, memory_order_relaxed) + 1,
			      memory_order_release);
}

int p15q_wait(struct p15q *q, int timeout_ms)
{
	struct pollfd p = { .fd = q->efd, .events = POLLIN };
	uint64_t v;

	if (p15q_peek(q))
		return 0;
	if (poll(&p, 1, timeout_ms) < 0)
		return errno == EINTR ? 0 : -errno;
	if ((p.revents & POLLIN) && read(q->efd, &v, sizeof(v)) < 0 && errno != EAGAIN)
		return -errno;
	return 0;
}

uint32_t p15q_depth(struct p15q *q)
{
	return (uint32_t)(atomic_load_explicit(&q->head, memory_order_acquire) -
			  atomic_load_explicit(&q->tail, memory_order_acquire));
}

void p15q_kick(struct p15q *q)
{
	uint64_t one = 1;

	if (write(q->efd, &one, sizeof(one)) < 0)
		return;
}
