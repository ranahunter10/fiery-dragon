// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * recur_probe: measure how many of our own children's exec and exit events the kernel skips
 * (bpf_prog_info.recursion_misses, E-0089) for each hook type and wake-up design, under the
 * same fork/exec burst. See recur_probe.bpf.c for the variants.
 *
 *   recur_probe [ROUNDS] [EXECS] [WORKERS]       (root; defaults 3, 2000, 2 x online CPUs)
 *
 * Each round runs every variant once, in a rotated order (ADR-0018: interleave, don't batch).
 * Per run it prints one "row" line: how many of the EXECS children the program ran for (exec
 * and exit), how many the kernel counted as skipped, how many records reached the reader, and
 * how long the burst took. Exit 0 if every run's books close (seen + kernel misses >= what
 * our children did, and every record that was output was read), 1 otherwise.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "recur_probe.skel.h"

extern char **environ;

struct variant {
	const char *name;
	int hook;          /* 0 tp_btf, 1 tp_btf + preempt off, 2 classic tracepoint */
	unsigned wake;     /* 0 every record, 1 never (poll), 2 adaptive */
	int rt;            /* reader at SCHED_FIFO 1, as p15d's drain */
};

static const struct variant V[] = {
	{ "btf/wake/rt (today)", 0, 0, 1 },
	{ "btf/wake/normal",     0, 0, 0 },
	{ "btf/nowake/rt",       0, 1, 1 },
	{ "btf/adaptive/rt",     0, 2, 1 },
	{ "btf+preemptoff/wake/rt", 1, 0, 1 },
	{ "tracepoint/wake/rt",  2, 0, 1 },
	{ "tracepoint/nowake/rt", 2, 1, 1 },
};
#define NV (int)(sizeof(V) / sizeof(V[0]))

struct reader {
	struct ring_buffer *rb;
	const struct variant *v;
	atomic_int stop;
	unsigned long long ours, all;
	int err;
};

static unsigned me;

static int on_rec(void *ctx, void *data, size_t size)
{
	struct reader *r = ctx;
	const unsigned *u = data;

	if (size >= 8 && u[1] == me)
		r->ours++;
	r->all++;
	return 0;
}

static void *reader_main(void *arg)
{
	struct reader *r = arg;
	struct sched_param sp = { .sched_priority = 1 };
	struct timespec five_ms = { 0, 5 * 1000 * 1000 };

	if (r->v->rt && pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp)) {
		r->err = 1;
		return NULL;
	}
	while (!atomic_load(&r->stop)) {
		int n;

		if (r->v->wake == 1) {          /* never woken: poll on a 5 ms timer */
			n = ring_buffer__consume(r->rb);
			nanosleep(&five_ms, NULL);
		} else {                         /* woken by records, or by a 10 ms timeout */
			n = ring_buffer__poll(r->rb, r->v->wake == 2 ? 10 : 100);
		}
		if (n < 0 && n != -EINTR) {
			r->err = 1;
			break;
		}
	}
	if (ring_buffer__consume(r->rb) < 0)
		r->err = 1;
	return NULL;
}

struct worker {
	int n;
	int failed;
};

static void *worker_main(void *arg)
{
	struct worker *w = arg;
	char *argv[] = { "/bin/true", "recur-probe-child", "padding-to-a-realistic-argv-length-0123456789", NULL };

	for (int i = 0; i < w->n; i++) {
		pid_t pid;
		int st;

		if (posix_spawn(&pid, "/bin/true", NULL, NULL, argv, environ) || waitpid(pid, &st, 0) != pid)
			w->failed++;
	}
	return NULL;
}

static unsigned long long misses(struct bpf_program *p)
{
	struct bpf_prog_info info;
	__u32 len = sizeof(info);

	memset(&info, 0, sizeof(info));
	if (bpf_prog_get_info_by_fd(bpf_program__fd(p), &info, &len))
		return ~0ull;
	return info.recursion_misses;
}

static unsigned long long counter(struct recur_probe_bpf *s, __u32 k)
{
	int ncpu = libbpf_num_possible_cpus();
	unsigned long long sum = 0, *vals = calloc((size_t)ncpu, sizeof(*vals));

	if (!vals || bpf_map_lookup_elem(bpf_map__fd(s->maps.cnt), &k, vals))
		sum = ~0ull;
	else
		for (int c = 0; c < ncpu; c++)
			sum += vals[c];
	free(vals);
	return sum;
}

static double now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

/* one run of one variant; returns 0 if its books close */
static int run(const struct variant *v, int round, int execs, int workers)
{
	struct bpf_program *pe, *px, *p;
	struct recur_probe_bpf *s = recur_probe_bpf__open();
	struct reader rd = { .v = v };
	struct worker *w = calloc((size_t)workers, sizeof(*w));
	pthread_t rt, *wt = calloc((size_t)workers, sizeof(*wt));
	unsigned long long es, xs, em, xm, of;
	int failed = 0, bad = 0;
	double t0, t1;

	if (!s || !w || !wt)
		return fprintf(stderr, "open failed\n"), 1;
	s->rodata->harness_tgid = me;
	s->rodata->wake_mode = v->wake;
	s->rodata->adaptive_bytes = 256 * 1024;
	pe = v->hook == 0 ? s->progs.btf_exec : v->hook == 1 ? s->progs.btfp_exec : s->progs.tp_exec;
	px = v->hook == 0 ? s->progs.btf_exit : v->hook == 1 ? s->progs.btfp_exit : s->progs.tp_exit;
	bpf_object__for_each_program(p, s->obj)
		bpf_program__set_autoload(p, p == pe || p == px);
	if (recur_probe_bpf__load(s) || !bpf_program__attach(pe) || !bpf_program__attach(px)) {
		fprintf(stderr, "%s: load or attach failed (%s)\n", v->name, strerror(errno));
		recur_probe_bpf__destroy(s);
		return 1;
	}
	rd.rb = ring_buffer__new(bpf_map__fd(s->maps.rb), on_rec, &rd, NULL);
	if (!rd.rb || pthread_create(&rt, NULL, reader_main, &rd))
		return fprintf(stderr, "reader failed\n"), 1;
	usleep(100 * 1000);
	t0 = now_ms();
	for (int i = 0; i < workers; i++) {
		w[i].n = execs / workers + (i < execs % workers);
		pthread_create(&wt[i], NULL, worker_main, &w[i]);
	}
	for (int i = 0; i < workers; i++) {
		pthread_join(wt[i], NULL);
		failed += w[i].failed;
	}
	t1 = now_ms();
	usleep(200 * 1000);
	em = misses(pe);
	xm = misses(px);
	atomic_store(&rd.stop, 1);
	pthread_join(rt, NULL);
	es = counter(s, 0);
	xs = counter(s, 1);
	of = counter(s, 2);
	/* the books: every child exec'd and exited, so seen + skipped must reach execs; and every
	 * record the programs output reached the reader (no ring loss to confuse the count) */
	bad = failed || rd.err || of || es + em < (unsigned long long)execs || xs + xm < (unsigned long long)execs;
	printf("row variant=\"%s\" round=%d execs=%d spawn_failed=%d exec_seen=%llu exec_missed=%d "
	       "exec_kernel_misses=%llu exit_seen=%llu exit_missed=%d exit_kernel_misses=%llu "
	       "read_ours=%llu read_all=%llu out_failed=%llu burst_ms=%.0f books=%s\n",
	       v->name, round, execs, failed, es, execs - (int)es, em, xs, execs - (int)xs, xm, rd.ours, rd.all,
	       of, t1 - t0, bad ? "BROKEN" : "closed");
	fflush(stdout);
	ring_buffer__free(rd.rb);
	recur_probe_bpf__destroy(s);
	free(w);
	free(wt);
	return bad;
}

int main(int argc, char **argv)
{
	int rounds = argc > 1 ? atoi(argv[1]) : 3, execs = argc > 2 ? atoi(argv[2]) : 2000;
	int workers = argc > 3 ? atoi(argv[3]) : 2 * (int)sysconf(_SC_NPROCESSORS_ONLN);
	int bad = 0;

	if (rounds < 1 || execs < workers || workers < 1) {
		fprintf(stderr, "usage: recur_probe [ROUNDS>=1] [EXECS>=WORKERS] [WORKERS>=1]\n");
		return 2;
	}
	me = (unsigned)getpid();
	printf("recur_probe: kernel %s; %d rounds x %d variants x %d execs, %d workers, %ld CPUs\n",
	       getenv("P15_UNAME") ? getenv("P15_UNAME") : "(set P15_UNAME)", rounds, NV, execs, workers,
	       sysconf(_SC_NPROCESSORS_ONLN));
	for (int r = 0; r < rounds; r++)
		for (int k = 0; k < NV; k++)
			bad |= run(&V[(k + r) % NV], r, execs, workers);
	printf("recur_probe: %s\n", bad ? "FAIL (a run's books did not close; see rows)" : "PASS (every run's books closed)");
	return bad;
}
