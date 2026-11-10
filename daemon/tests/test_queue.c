// SPDX-License-Identifier: MIT
/*
 * Unit tests for the SPSC batch queue (daemon/queue.c), single-threaded and with a real
 * producer and consumer thread. Run under ThreadSanitizer with `make test-c-tsan`.
 */
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "queue.h"

static int failures;

#define EXPECT(cond, msg) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

static void test_single_thread(void)
{
	struct p15q q;
	struct p15q_slot *s;

	EXPECT(p15q_init(&q, 1, 64) != 0, "fewer than 2 slots refused");
	EXPECT(p15q_init(&q, 3, 64) == 0, "init");
	EXPECT(p15q_peek(&q) == NULL && p15q_depth(&q) == 0, "empty");
	for (int i = 0; i < 3; i++) {
		s = p15q_acquire(&q, (unsigned)i);
		EXPECT(s && s->count == 0 && s->len == 0 && s->ring == (unsigned)i && s->cap == 64, "acquire");
		if (s) {
			s->buf[0] = (uint8_t)(10 + i);
			s->len = 1;
			s->count = 1;
		}
		p15q_publish(&q);
	}
	EXPECT(p15q_acquire(&q, 0) == NULL && q.full == 1, "full: NULL, counted");
	EXPECT(p15q_depth(&q) == 3 && q.depth_max == 3, "depth and its high-water");
	for (int i = 0; i < 3; i++) {
		s = p15q_peek(&q);
		EXPECT(s && s->buf[0] == 10 + i && s->ring == (unsigned)i, "FIFO order");
		p15q_release(&q);
	}
	EXPECT(p15q_peek(&q) == NULL, "empty again");
	s = p15q_acquire(&q, 1);
	EXPECT(s && s->len == 0 && s->count == 0, "a reused slot comes back empty");
	EXPECT(p15q_wait(&q, 0) == 0, "wait with nothing published returns");
	p15q_free(&q);
}

#define N_ITEMS 200000

static void *producer(void *arg)
{
	struct p15q *q = arg;

	for (uint32_t i = 0; i < N_ITEMS;) {
		struct p15q_slot *s = p15q_acquire(q, i % 3);

		if (!s)
			continue;           /* full: the real drain leaves records in the ring and retries */
		memcpy(s->buf, &i, sizeof(i));
		s->len = sizeof(i);
		s->count = 1;
		p15q_publish(q);
		i++;
	}
	return NULL;
}

static void test_two_threads(void)
{
	struct p15q q;
	pthread_t t;
	uint32_t expect = 0, bad = 0;

	if (p15q_init(&q, 8, 32) != 0) {
		EXPECT(0, "init");
		return;
	}
	EXPECT(pthread_create(&t, NULL, producer, &q) == 0, "producer thread");
	while (expect < N_ITEMS) {
		struct p15q_slot *s = p15q_peek(&q);
		uint32_t v;

		if (!s) {
			if (p15q_wait(&q, 10))
				bad++;
			continue;
		}
		memcpy(&v, s->buf, sizeof(v));
		bad += v != expect || s->ring != expect % 3 || s->count != 1;
		expect++;
		p15q_release(&q);
	}
	pthread_join(t, NULL);
	EXPECT(bad == 0, "every item arrives once, in order, with its ring");
	EXPECT(p15q_peek(&q) == NULL && p15q_depth(&q) == 0, "drained");
	EXPECT(q.depth_max <= 8, "depth never above capacity");
	printf("two threads: %u items, queue full %llu times, depth max %u\n", N_ITEMS,
	       (unsigned long long)q.full, q.depth_max);
	p15q_free(&q);
}

/* A queue that stops moving (a publish that never advances head, a release that never advances
 * tail) hangs the two-thread test instead of failing it. The deadline turns that into a failed
 * check, so a mutation sweep counts it as killed and a guest freeze stays a TIMEOUT (E-0159). The
 * test takes well under a second; TSan's slowdown is far inside 30 s. */
static void deadline(int sig)
{
	static const char msg[] = "FAIL daemon/tests/test_queue.c: no progress within 30 s (the queue stopped moving)\n";

	(void)sig;
	(void)!write(1, msg, sizeof(msg) - 1);
	_exit(1);   /* exit-ok: test deadline, the queue stopped moving (E-0159) */
}

int main(void)
{
	signal(SIGALRM, deadline);
	alarm(30);
	test_single_thread();
	test_two_threads();
	printf("%s: %d failures\n", __FILE__, failures);
	return failures != 0;
}
