// SPDX-License-Identifier: MIT
/*
 * flow_cost: what step 2b's read hook costs per vfs_read call with each way of keeping FLOW's
 * start time, paired by round (step 2b design checks §2 and §4; decision waiting 13; ADR-0018
 * rule 2), and whether option A's start time is right.
 *
 *   flow_cost ROUNDS READS CHECKS      (root)
 *
 * Arms (flow_cost.bpf.c): none and none2 (nothing attached: the untraced arm and its A/A control),
 * session (E-0138's anchor), ts (option A without a record), count (ts plus the per-task count of
 * open calls that the end of a run needs, bpf/include/p15_flow.h), end_rec (option D: a FLOW with its
 * end time only), ts_rec (option A with the FLOW). Per round, every arm runs READS x
 * read(/dev/zero, 1 byte) on the harness's own thread, pinned to one CPU, in an order rotated each
 * round, after one untimed warm-up of every arm. The primary metric is the thread's CPU time, the
 * secondary wall time. A drain thread on another CPU consumes the ring as it fills, and checks
 * every FLOW (type, length, kind, bytes 1, first_ts <= last_ts, START_UNKNOWN exactly in end_rec).
 *
 * Books per arm: hits equal READS; the untraced arms see none; no return without its cookie; no
 * lost start time, no failed storage creation, no failed reservation; the record arms' drained
 * FLOWs equal READS, each valid. Skip counters per arm: its program's recursion_misses and the
 * link's kprobe_multi.missed.
 *
 * Before the rounds, the check pass: CHECKS reads with ts_rec attached, each bracketed by
 * CLOCK_BOOTTIME before and after; the i-th FLOW must have before <= first_ts <= last_ts <= after
 * (a "check" line). Each round also times a null syscall (getppid, 10^6 calls), ADR-0018 rule 3.2.
 * Exit 0 only if every book closes and the check passes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "p15_records.h"
#include "flow_cost.skel.h"

enum { H_SESSION, H_TS, H_END_REC, H_TS_REC, H_NOCOOKIE, H_TS_LOST, H_TS_CREATE_FAILED, H_RESERVE_FAILED, H_COUNT,
       H_COUNT_LOST, H_N };
enum arm { A_NONE, A_NONE2, A_SESSION, A_TS, A_COUNT, A_END_REC, A_TS_REC, A_N };
static const char *const arm_name[A_N] = { "none", "none2", "session", "ts", "count", "end_rec", "ts_rec" };
static const int arm_hit[A_N] = { -1, -1, H_SESSION, H_TS, H_COUNT, H_END_REC, H_TS_REC };

/* the drain thread's view: records seen and refused since the last reset, and the check pass */
static struct ring_buffer *rb;
static atomic_int stop, want_unknown;
static atomic_ullong drained, refused;
static __u64 *check_first, *check_last;
static atomic_ullong check_n;
static unsigned long long check_cap;

static long long ns(const struct timespec *a, const struct timespec *b)
{
	return (long long)(b->tv_sec - a->tv_sec) * 1000000000ll + (b->tv_nsec - a->tv_nsec);
}

static __u64 boot_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_BOOTTIME, &t);
	return (__u64)t.tv_sec * 1000000000ull + (__u64)t.tv_nsec;
}

static int on_flow(void *ctx, void *data, size_t size)
{
	const struct p15_flow_v1 *r = data;
	int unknown = atomic_load(&want_unknown);
	unsigned long long i;

	(void)ctx;
	if (size < sizeof(*r) || r->h.type != P15_T_FLOW || r->h.len != sizeof(*r) || r->kind != P15_FLOW_KIND_READ ||
	    r->bytes != 1 || r->count != 1 || r->first_ts > r->last_ts ||
	    !!(r->fflags & P15_FF_START_UNKNOWN) != !!unknown || (unknown && r->first_ts != r->last_ts)) {
		atomic_fetch_add(&refused, 1);
		return 0;
	}
	atomic_fetch_add(&drained, 1);
	i = atomic_load(&check_n);
	if (check_first && i < check_cap) {
		check_first[i] = r->first_ts;
		check_last[i] = r->last_ts;
		atomic_store(&check_n, i + 1);
	}
	return 0;
}

static void *drain(void *arg)
{
	(void)arg;
	while (!atomic_load(&stop))
		if (ring_buffer__consume(rb) < 0)
			break;
	ring_buffer__consume(rb);
	return NULL;
}

/* wait until the drain has taken everything submitted (the ring is empty) */
static void drain_wait(struct flow_cost_bpf *s)
{
	struct ring *r = ring_buffer__ring(rb, 0);

	(void)s;
	while (r && ring__avail_data_size(r))
		sched_yield();
}

static __u64 hit(struct flow_cost_bpf *s, __u32 k)
{
	__u64 v = 0;

	if (bpf_map_lookup_elem(bpf_map__fd(s->maps.hits), &k, &v))
		fprintf(stderr, "warn: hits[%u] lookup failed\n", k);
	return v;
}

static int hits_reset(struct flow_cost_bpf *s)
{
	__u64 zero = 0;

	for (__u32 k = 0; k < H_N; k++)
		if (bpf_map_update_elem(bpf_map__fd(s->maps.hits), &k, &zero, BPF_ANY))
			return -1;
	atomic_store(&drained, 0);
	atomic_store(&refused, 0);
	return 0;
}

static unsigned long long prog_rmiss(const struct bpf_program *p)
{
	struct bpf_prog_info info = { 0 };
	__u32 len = sizeof(info);

	if (bpf_prog_get_info_by_fd(bpf_program__fd(p), &info, &len)) {
		fprintf(stderr, "warn: prog info %s: %s\n", bpf_program__name(p), strerror(errno));
		return 0;
	}
	return info.recursion_misses;
}

static unsigned long long link_lmiss(const struct bpf_link *l)
{
	struct bpf_link_info info = { 0 };
	__u32 len = sizeof(info);

	if (bpf_link_get_info_by_fd(bpf_link__fd(l), &info, &len)) {
		fprintf(stderr, "warn: link info: %s\n", strerror(errno));
		return 0;
	}
	return info.type == BPF_LINK_TYPE_KPROBE_MULTI ? info.kprobe_multi.missed : 0;
}

static struct bpf_program *arm_prog(struct flow_cost_bpf *s, enum arm a)
{
	switch (a) {
	case A_SESSION: return s->progs.rd_session;
	case A_TS: return s->progs.rd_ts;
	case A_COUNT: return s->progs.rd_count;
	case A_END_REC: return s->progs.rd_end_rec;
	case A_TS_REC: return s->progs.rd_ts_rec;
	default: return NULL;
	}
}

static int run_reads(int fd, int n, long long *cpu, long long *wall)
{
	struct timespec c0, c1, w0, w1;
	char b;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c0);
	clock_gettime(CLOCK_MONOTONIC, &w0);
	for (int i = 0; i < n; i++)
		if (read(fd, &b, 1) != 1)
			return -1;
	clock_gettime(CLOCK_MONOTONIC, &w1);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c1);
	*cpu = ns(&c0, &c1);
	*wall = ns(&w0, &w1);
	return 0;
}

/* one arm of one round; returns 0 if its books close */
static int arm(struct flow_cost_bpf *s, int fd, int round, enum arm a, int n)
{
	struct bpf_program *p = arm_prog(s, a);
	struct bpf_link *l = NULL;
	unsigned long long rm0 = 0, rm1 = 0, lm0 = 0, lm1 = 0;
	long long cpu = 0, wall = 0;
	int rc = 0, rec = a == A_END_REC || a == A_TS_REC;
	__u64 got, lost;
	unsigned long long dr, rf;

	if (hits_reset(s)) {
		fprintf(stderr, "hits reset: %s\n", strerror(errno));
		return 1;
	}
	atomic_store(&want_unknown, a == A_END_REC);
	if (p) {
		rm0 = prog_rmiss(p);
		if (!(l = bpf_program__attach(p))) {
			fprintf(stderr, "attach %s: %s\n", bpf_program__name(p), strerror(errno));
			return 1;
		}
		lm0 = link_lmiss(l);
	}
	if (run_reads(fd, n, &cpu, &wall))
		rc = 1;
	if (p) {
		rm1 = prog_rmiss(p);
		lm1 = link_lmiss(l);
		if (bpf_link__destroy(l))
			fprintf(stderr, "warn: link destroy failed\n");
	}
	drain_wait(s);
	got = arm_hit[a] < 0 ? hit(s, H_SESSION) + hit(s, H_TS) + hit(s, H_END_REC) + hit(s, H_TS_REC) + hit(s, H_COUNT)
			     : hit(s, (__u32)arm_hit[a]);
	lost = hit(s, H_NOCOOKIE) + hit(s, H_TS_LOST) + hit(s, H_TS_CREATE_FAILED) + hit(s, H_RESERVE_FAILED) +
	       hit(s, H_COUNT_LOST);
	dr = atomic_load(&drained);
	rf = atomic_load(&refused);
	printf("row round=%d event=read arm=%s n=%d cpu_ns=%lld wall_ns=%lld hits=%llu lost=%llu drained=%llu refused=%llu "
	       "rmiss=%llu lmiss=%llu\n", round, arm_name[a], n, cpu, wall, (unsigned long long)got,
	       (unsigned long long)lost, dr, rf, rm1 - rm0, lm1 - lm0);
	if (rc || lost || rf)
		return 1;
	if (dr != (rec ? (unsigned long long)n : 0))
		return 1;
	return arm_hit[a] < 0 ? got != 0 : got != (__u64)n;
}

/* option A's start time against the reads' own CLOCK_BOOTTIME brackets */
static int check_pass(struct flow_cost_bpf *s, int fd, int n)
{
	__u64 *before = calloc((size_t)n, sizeof(*before)), *after = calloc((size_t)n, sizeof(*after));
	struct bpf_link *l;
	unsigned long long got, bad = 0;
	char b;
	int rc = 1;

	check_first = calloc((size_t)n, sizeof(*check_first));
	check_last = calloc((size_t)n, sizeof(*check_last));
	if (!before || !after || !check_first || !check_last || hits_reset(s))
		goto out;
	check_cap = (unsigned long long)n;
	atomic_store(&check_n, 0);
	atomic_store(&want_unknown, 0);
	if (!(l = bpf_program__attach(s->progs.rd_ts_rec))) {
		fprintf(stderr, "attach rd_ts_rec: %s\n", strerror(errno));
		goto out;
	}
	for (int i = 0; i < n; i++) {
		before[i] = boot_ns();
		if (read(fd, &b, 1) != 1)
			break;
		after[i] = boot_ns();
	}
	if (bpf_link__destroy(l))
		fprintf(stderr, "warn: link destroy failed\n");
	drain_wait(s);
	got = atomic_load(&check_n);
	for (unsigned long long i = 0; i < got && i < (unsigned long long)n; i++)
		bad += !(before[i] <= check_first[i] && check_first[i] <= check_last[i] && check_last[i] <= after[i]);
	rc = got != (unsigned long long)n || bad || atomic_load(&refused) || hit(s, H_TS_LOST) || hit(s, H_TS_CREATE_FAILED);
	printf("check reads=%d flows=%llu outside=%llu refused=%llu ts_lost=%llu create_failed=%llu %s\n", n, got, bad,
	       (unsigned long long)atomic_load(&refused), (unsigned long long)hit(s, H_TS_LOST),
	       (unsigned long long)hit(s, H_TS_CREATE_FAILED), rc ? "FAIL" : "ok");
out:
	check_cap = 0;
	free(before);
	free(after);
	free(check_first);
	free(check_last);
	check_first = check_last = NULL;
	return rc;
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

/* the reads on the last allowed CPU, the drain on the first: two CPUs, as p15d and a workload */
static int cpus(int *first, int *last)
{
	cpu_set_t set;

	*first = *last = -1;
	if (sched_getaffinity(0, sizeof(set), &set))
		return -1;
	for (int i = 0; i < CPU_SETSIZE; i++)
		if (CPU_ISSET(i, &set)) {
			if (*first < 0)
				*first = i;
			*last = i;
		}
	return *first == *last ? -1 : 0;
}

static int pin(pthread_t t, int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return pthread_setaffinity_np(t, sizeof(set), &set);
}

int main(int argc, char **argv)
{
	struct flow_cost_bpf *s;
	pthread_t dt;
	int rounds, reads, checks, cpu_r, cpu_d, fd, bad = 0;

	if (argc != 4 || (rounds = atoi(argv[1])) <= 0 || (reads = atoi(argv[2])) <= 0 || (checks = atoi(argv[3])) <= 0) {
		fprintf(stderr, "usage: %s ROUNDS READS CHECKS\n", argv[0]);
		return 2;
	}
	if (cpus(&cpu_d, &cpu_r)) {
		fprintf(stderr, "flow_cost needs two CPUs (the reads and the drain)\n");
		return 1;
	}
	if ((fd = open("/dev/zero", O_RDONLY | O_CLOEXEC)) < 0) {
		fprintf(stderr, "open /dev/zero: %s\n", strerror(errno));
		return 1;
	}
	if (!(s = flow_cost_bpf__open())) {
		fprintf(stderr, "open flow_cost: %s\n", strerror(errno));
		return 1;
	}
	s->rodata->harness_tgid = (__u32)getpid();
	if (flow_cost_bpf__load(s)) {
		fprintf(stderr, "load: %s\n", strerror(errno));
		return 1;
	}
	if (!(rb = ring_buffer__new(bpf_map__fd(s->maps.flows), on_flow, NULL, NULL))) {
		fprintf(stderr, "ring: %s\n", strerror(errno));
		return 1;
	}
	if (pthread_create(&dt, NULL, drain, NULL) || pin(dt, cpu_d) || pin(pthread_self(), cpu_r)) {
		fprintf(stderr, "threads: %s\n", strerror(errno));
		return 1;
	}
	printf("flow_cost: libbpf %s, reads on CPU %d, drain on CPU %d, %d rounds, %d reads per arm, %d arms, "
	       "FLOW %zu bytes\n", libbpf_version_string(), cpu_r, cpu_d, rounds, reads, A_N, sizeof(struct p15_flow_v1));
	bad |= check_pass(s, fd, checks);
	for (int k = 0; k < A_N; k++)                   /* untimed warm-up (ADR-0012), books still checked */
		bad |= arm(s, fd, -1, (enum arm)k, reads / 10 + 1);
	for (int r = 0; r < rounds; r++) {
		null_syscall(r);
		for (int k = 0; k < A_N; k++)
			bad |= arm(s, fd, r, (enum arm)((r + k) % A_N), reads);
	}
	atomic_store(&stop, 1);
	pthread_join(dt, NULL);
	printf("flow_cost: %s\n", bad ? "FAIL" : "ok");
	ring_buffer__free(rb);
	flow_cost_bpf__destroy(s);
	close(fd);
	return bad;
}
