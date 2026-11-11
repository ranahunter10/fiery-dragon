// SPDX-License-Identifier: MIT
/*
 * prim_cost: run each building block of prim_cost.bpf.c in a timed loop (root).
 *
 *   prim_cost ROUNDS ITERS [CPU]
 *
 * Per round, every primitive runs ITERS iterations in one BPF_PROG_RUN, in an order rotated each
 * round, after one untimed warm-up round (round -1). The time is taken inside the program, around
 * the loop. The ring is emptied (untimed) after every run, so a reservation never fails for a full
 * ring. One "row" line per run; summarize.py subtracts the empty loop and makes the report.
 * After every round, one "host" line: the thread-CPU time of 100,000 getppid() calls, timed as
 * bench/open_cost times its null syscalls. It is the run's own record of how fast the host was
 * (E-0180: a run on a throttled host is not told apart from a good one by the costs alone).
 * Exit 0 if every iteration of every run did what it should.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "prim_cost.skel.h"

static const char *const NAME[] = { "empty", "ring_reserve_submit", "ring_reserve_discard", "ring_output", "hash_lookup",
				    "hash_update_delete", "counter", "percpu_copy", "ktime" };
#define NPRIM ((int)(sizeof(NAME) / sizeof(NAME[0])))

static int on_sample(void *ctx, void *data, size_t size)
{
	(void)data;
	(void)size;
	(*(unsigned long long *)ctx)++;
	return 0;
}

#define NULLSYS_N 100000L

/* Thread-CPU ns of NULLSYS_N null syscalls: the host-speed control of every round. */
static unsigned long long nullsys_ns(void)
{
	struct timespec a, b;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &a);
	for (long i = 0; i < NULLSYS_N; i++)
		syscall(SYS_getppid);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &b);
	return (unsigned long long)((b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec));
}

static int run(int fd)
{
	LIBBPF_OPTS(bpf_test_run_opts, o);

	return bpf_prog_test_run_opts(fd, &o) ? -errno : (int)o.retval;
}

int main(int argc, char **argv)
{
	struct prim_cost_bpf *s;
	struct ring_buffer *rb;
	unsigned long long seen = 0, sent = 0;
	long rounds, iters, cpu;
	cpu_set_t set;
	int bad = 0, rc;

	if (argc != 3 && argc != 4) {
		fprintf(stderr, "usage: prim_cost ROUNDS ITERS [CPU]\n");
		return 2;
	}
	rounds = atol(argv[1]);
	iters = atol(argv[2]);
	cpu = argc == 4 ? atol(argv[3]) : sysconf(_SC_NPROCESSORS_ONLN) - 1;
	if (rounds < 1 || iters < 1 || iters > 30000 || cpu < 0) {
		fprintf(stderr, "prim_cost: ROUNDS >= 1, 1 <= ITERS <= 30000 (the ring must hold one run), CPU >= 0\n");
		return 2;
	}
	CPU_ZERO(&set);
	CPU_SET((int)cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set)) {
		fprintf(stderr, "prim_cost: cannot pin to cpu %ld: %s\n", cpu, strerror(errno));
		return 1;
	}
	s = prim_cost_bpf__open_and_load();
	if (!s) {
		fprintf(stderr, "prim_cost: load failed: %s\n", strerror(errno));
		return 1;
	}
	rb = ring_buffer__new(bpf_map__fd(s->maps.rb), on_sample, &seen, NULL);
	if (!rb || (rc = run(bpf_program__fd(s->progs.prim_fill)))) {
		fprintf(stderr, "prim_cost: setup failed\n");
		return 1;
	}
	printf("config cpu=%ld rounds=%ld iters=%ld\n", cpu, rounds, iters);
	s->bss->iters = (unsigned)iters;
	for (long r = -1; r < rounds; r++) {
		for (int k = 0; k < NPRIM; k++) {
			int p = (int)((k + (r + 1)) % NPRIM);

			s->bss->which = (unsigned)p;
			s->bss->out_ns = s->bss->out_ok = 0;
			rc = run(bpf_program__fd(s->progs.prim_run));
			if (rc) {
				fprintf(stderr, "prim_cost: run failed: %d\n", rc);
				return 1;
			}
			printf("row round=%ld prim=%s n=%ld ns=%llu ok=%llu\n", r, NAME[p], iters,
			       (unsigned long long)s->bss->out_ns, (unsigned long long)s->bss->out_ok);
			if (s->bss->out_ok != (unsigned long long)iters)
				bad++;
			if (p == 1 || p == 3)
				sent += (unsigned long long)iters;
			ring_buffer__consume(rb);
		}
		printf("host round=%ld nullsys_n=%ld ns=%llu\n", r, NULLSYS_N, nullsys_ns());
	}
	printf("ring sent=%llu consumed=%llu %s\n", sent, seen, sent == seen ? "ok" : "FAIL");
	ring_buffer__free(rb);
	prim_cost_bpf__destroy(s);
	return bad || sent != seen;
}
