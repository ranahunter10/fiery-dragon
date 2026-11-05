// SPDX-License-Identifier: MIT
/*
 * hook_cost: what the classic-tracepoint hook path costs against tp_btf, per event, paired by
 * round (ADR-0020 confirmation 5; ADR-0018 rule 2).
 *
 *   hook_cost SPINE_OBJ ROUNDS RENAMES EXECS      (root)
 *
 * Two events, each timed in every arm of every round, in an order rotated each round:
 *   rename  RENAMES x prctl(PR_SET_NAME): the harness's own thread CPU time (and wall time)
 *   exec    EXECS x fork + exec of /bin/true + wait: the children's CPU time (getrusage), where
 *           the hook runs, and wall time
 * Arms:
 *   none, none2  nothing attached: the untraced arm and its A/A control
 *   tp, btf      hook_cost.bpf.c's trivial body on tracepoint/ and on tp_btf/
 *   spine        (exec only) the shipped spine EXEC program, SPINE_OBJ's spine_exec, alone
 * The process is pinned to one CPU, and so are its children. Every traced arm's hits must equal
 * its events (the spine arm: its EXEC records of our /bin/true children), and the untraced
 * arms must see none. One "row" line per arm; summarize.py turns them into the ADR-0018 report.
 * Each round also times a null syscall (getppid, 10^6 calls), ADR-0018 rule 3.2's baseline.
 * Exit 0 if every arm's books close.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "hook_cost.skel.h"
#include "records.h"

#define CHILD_ARG "p15-hook-cost"

enum event { EV_RENAME, EV_EXEC };
enum arm { A_NONE, A_NONE2, A_TP, A_BTF, A_SPINE, A_N };
static const char *const arm_name[A_N] = { "none", "none2", "tp", "btf", "spine" };

struct harness {
	struct hook_cost_bpf *hk;
	struct bpf_object *spine;
	struct ring_buffer *spine_rb;
	unsigned long long spine_ours;     /* EXEC records of our children seen in the spine ring */
	unsigned long long spine_bad;      /* records that fail p15_rec_check */
};

static long long ns(const struct timespec *a, const struct timespec *b)
{
	return (long long)(b->tv_sec - a->tv_sec) * 1000000000ll + (b->tv_nsec - a->tv_nsec);
}

static long long rusage_ns(const struct rusage *r)
{
	return ((long long)r->ru_utime.tv_sec + r->ru_stime.tv_sec) * 1000000000ll +
	       ((long long)r->ru_utime.tv_usec + r->ru_stime.tv_usec) * 1000ll;
}

static int on_spine(void *ctx, void *data, size_t size)
{
	struct harness *h = ctx;
	const struct p15_exec *r = data;
	const char *why;
	const __u8 *a;
	__u16 alen;

	if (p15_rec_check(data, size, &why)) {
		h->spine_bad++;
		return 0;
	}
	if (r->h.type != P15_T_EXEC)
		return 0;
	a = p15_exec_argv(r, &alen);
	if (alen == sizeof("true") + sizeof(CHILD_ARG) && !memcmp(a + sizeof("true"), CHILD_ARG, sizeof(CHILD_ARG)))
		h->spine_ours++;
	return 0;
}

static int open_spine(struct harness *h, const char *path)
{
	struct bpf_program *p;

	h->spine = bpf_object__open_file(path, NULL);
	if (!h->spine) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return -1;
	}
	bpf_object__for_each_program(p, h->spine)
		if (strcmp(bpf_program__name(p), "spine_exec") && bpf_program__set_autoload(p, false))
			return -1;
	if (bpf_object__load(h->spine)) {
		fprintf(stderr, "load %s: %s\n", path, strerror(errno));
		return -1;
	}
	h->spine_rb = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(h->spine, "spine_rb")), on_spine, h,
				       NULL);
	return h->spine_rb ? 0 : -1;
}

static struct bpf_program *prog_for(struct harness *h, enum event ev, enum arm a)
{
	if (a == A_TP)
		return ev == EV_RENAME ? h->hk->progs.tp_rename : h->hk->progs.tp_exec;
	if (a == A_BTF)
		return ev == EV_RENAME ? h->hk->progs.btf_rename : h->hk->progs.btf_exec;
	if (a == A_SPINE)
		return bpf_object__find_program_by_name(h->spine, "spine_exec");
	return NULL;
}

static __u64 hits_total(struct harness *h)
{
	__u64 sum = 0, v;

	for (__u32 k = 0; k < 4; k++)
		if (!bpf_map_lookup_elem(bpf_map__fd(h->hk->maps.hits), &k, &v))
			sum += v;
	return sum;
}

static void hits_reset(struct harness *h)
{
	__u64 zero = 0;

	for (__u32 k = 0; k < 4; k++)
		if (bpf_map_update_elem(bpf_map__fd(h->hk->maps.hits), &k, &zero, BPF_ANY))
			fprintf(stderr, "warn: hits reset failed\n");
}

static int run_renames(int n, long long *cpu, long long *wall)
{
	struct timespec c0, c1, w0, w1;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c0);
	clock_gettime(CLOCK_MONOTONIC, &w0);
	for (int i = 0; i < n; i++)
		if (prctl(PR_SET_NAME, (i & 1) ? "p15-hc-a" : "p15-hc-b", 0, 0, 0))
			return -1;
	clock_gettime(CLOCK_MONOTONIC, &w1);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c1);
	*cpu = ns(&c0, &c1);
	*wall = ns(&w0, &w1);
	return 0;
}

static int run_execs(int n, long long *cpu, long long *wall)
{
	struct rusage r0, r1;
	struct timespec w0, w1;

	getrusage(RUSAGE_CHILDREN, &r0);
	clock_gettime(CLOCK_MONOTONIC, &w0);
	for (int i = 0; i < n; i++) {
		pid_t c = fork();
		int st;

		if (c == 0) {
			execl("/bin/true", "true", CHILD_ARG, (char *)NULL);
			_exit(127);
		}
		if (c < 0 || waitpid(c, &st, 0) != c || !WIFEXITED(st) || WEXITSTATUS(st))
			return -1;
	}
	clock_gettime(CLOCK_MONOTONIC, &w1);
	getrusage(RUSAGE_CHILDREN, &r1);
	*cpu = rusage_ns(&r1) - rusage_ns(&r0);
	*wall = ns(&w0, &w1);
	return 0;
}

/* one arm of one round; returns 0 if its books close */
static int arm(struct harness *h, int round, enum event ev, enum arm a, int n)
{
	struct bpf_program *p = prog_for(h, ev, a);
	struct bpf_link *link = NULL;
	long long cpu = 0, wall = 0;
	unsigned long long got, before = h->spine_ours;
	int rc;

	hits_reset(h);
	if (p && !(link = bpf_program__attach(p))) {
		fprintf(stderr, "attach %s/%s: %s\n", ev == EV_RENAME ? "rename" : "exec", arm_name[a], strerror(errno));
		return 1;
	}
	rc = ev == EV_RENAME ? run_renames(n, &cpu, &wall) : run_execs(n, &cpu, &wall);
	if (link && bpf_link__destroy(link))
		fprintf(stderr, "warn: link destroy failed\n");
	if (h->spine_rb && ring_buffer__consume(h->spine_rb) < 0)
		rc = -1;
	got = a == A_SPINE ? h->spine_ours - before : hits_total(h);
	printf("row round=%d event=%s arm=%s n=%d cpu_ns=%lld wall_ns=%lld hits=%llu\n", round,
	       ev == EV_RENAME ? "rename" : "exec", arm_name[a], n, cpu, wall, got);
	if (rc)
		return 1;
	return (a == A_NONE || a == A_NONE2) ? got != 0 : got != (unsigned long long)n;
}

static void null_syscall(int round)
{
	struct timespec a, b;
	const long n = 1000000;

	clock_gettime(CLOCK_MONOTONIC, &a);
	for (long i = 0; i < n; i++)
		syscall(SYS_getppid);
	clock_gettime(CLOCK_MONOTONIC, &b);
	printf("nullsys round=%d calls=%ld total_ns=%lld\n", round, n, ns(&a, &b));
}

static int pin_to_one_cpu(void)
{
	cpu_set_t set;
	int cpu = -1;

	if (sched_getaffinity(0, sizeof(set), &set))
		return -1;
	for (int i = 0; i < CPU_SETSIZE; i++)
		if (CPU_ISSET(i, &set))
			cpu = i;                    /* the last allowed CPU */
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set) ? -1 : cpu;
}

int main(int argc, char **argv)
{
	struct harness h = { 0 };
	int rounds, renames, execs, cpu, bad = 0;
	static const enum arm rename_arms[] = { A_NONE, A_NONE2, A_TP, A_BTF };
	static const enum arm exec_arms[] = { A_NONE, A_NONE2, A_TP, A_BTF, A_SPINE };

	if (argc != 5 || (rounds = atoi(argv[2])) <= 0 || (renames = atoi(argv[3])) <= 0 ||
	    (execs = atoi(argv[4])) <= 0) {
		fprintf(stderr, "usage: %s SPINE_OBJ ROUNDS RENAMES EXECS\n", argv[0]);
		return 2;
	}
	if ((cpu = pin_to_one_cpu()) < 0) {
		fprintf(stderr, "pin: %s\n", strerror(errno));
		return 1;
	}
	if (!(h.hk = hook_cost_bpf__open())) {
		fprintf(stderr, "open hook_cost: %s\n", strerror(errno));
		return 1;
	}
	h.hk->rodata->harness_tgid = (__u32)getpid();
	if (hook_cost_bpf__load(h.hk) || open_spine(&h, argv[1])) {
		fprintf(stderr, "load: %s\n", strerror(errno));
		return 1;
	}
	printf("hook_cost: libbpf %s, pinned to CPU %d, %d rounds, %d renames and %d execs per arm\n",
	       libbpf_version_string(), cpu, rounds, renames, execs);
	/* untimed warm-up (ADR-0012): one pass of every arm, books still checked */
	for (int k = 0; k < 4; k++)
		bad |= arm(&h, -1, EV_RENAME, rename_arms[k], renames / 10 + 1);
	for (int k = 0; k < 5; k++)
		bad |= arm(&h, -1, EV_EXEC, exec_arms[k], execs / 10 + 1);
	for (int r = 0; r < rounds; r++) {
		null_syscall(r);
		for (int k = 0; k < 4; k++)
			bad |= arm(&h, r, EV_RENAME, rename_arms[(r + k) % 4], renames);
		for (int k = 0; k < 5; k++)
			bad |= arm(&h, r, EV_EXEC, exec_arms[(r + k) % 5], execs);
	}
	printf("hook_cost: %s (spine records failing p15_rec_check: %llu)\n", bad || h.spine_bad ? "FAIL" : "ok",
	       h.spine_bad);
	ring_buffer__free(h.spine_rb);
	bpf_object__close(h.spine);
	hook_cost_bpf__destroy(h.hk);
	return bad || h.spine_bad;
}
