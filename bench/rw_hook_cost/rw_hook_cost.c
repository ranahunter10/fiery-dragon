// SPDX-License-Identifier: MIT
/*
 * rw_hook_cost: what each candidate hook type costs on the read path, per call, paired by
 * round (ADR-0015/ADR-0005 decision 1a and N5; ADR-0018 rule 2), and whether a kprobe.session
 * and a fentry can share one function (design check O2).
 *
 *   rw_hook_cost ROUNDS READS OPENS [--no-trampoline] [--no-session]      (root)
 *
 * Per round, every arm runs READS x read(/dev/zero, 1 byte) on the harness's own thread, in an
 * order rotated each round, after one untimed warm-up of every arm. The primary metric is the
 * thread's CPU time, the secondary wall time. Arms:
 *   none, none2   nothing attached: the untraced arm and its A/A control
 *   fentry, fexit trampolines on vfs_read                      (left out with --no-trampoline)
 *   kpm           kprobe.multi entry only
 *   pair          kprobe.multi entry + kretprobe.multi return, two links, a per-thread stash
 *   session       kprobe.session, one link, a per-call cookie (left out with --no-session, for
 *                 kernels whose session kfuncs differ from 7.0's, such as the dev container's)
 * Books per arm: a traced arm's hits equal READS, the untraced arms see none, and the pair and
 * session arms report no return without its entry. Each traced arm also reports the kernel's
 * skip counters read after it: the programs' recursion_misses and, for kprobe.multi links, the
 * link's kprobe_multi.missed. One "row" line per arm; summarize.py makes the ADR-0018 report.
 * Each round also times a null syscall (getppid, 10^6 calls), ADR-0018 rule 3.2's baseline.
 * Before the rounds, a kprobe.session and a fentry are attached together on security_file_open
 * and OPENS x open(/dev/null) + close must give OPENS hits to each (a "coexist" line; skipped
 * with either option). Exit 0 if every book closes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "rw_hook_cost.skel.h"

enum { H_FENTRY, H_FEXIT, H_KPM, H_PAIR, H_SESSION, H_PAIR_NOSTASH, H_SESSION_NOCOOKIE, H_PAIR_STASH_FULL,
       H_OPEN_SESSION, H_OPEN_FENTRY, H_N };
enum arm { A_NONE, A_NONE2, A_FENTRY, A_FEXIT, A_KPM, A_PAIR, A_SESSION, A_N };
static const char *const arm_name[A_N] = { "none", "none2", "fentry", "fexit", "kpm", "pair", "session" };
static const int arm_hit[A_N] = { -1, -1, H_FENTRY, H_FEXIT, H_KPM, H_PAIR, H_SESSION };

struct skips {
	unsigned long long rmiss;   /* sum of the arm's programs' recursion_misses */
	unsigned long long lmiss;   /* sum of the arm's kprobe.multi links' kprobe_multi.missed */
};

static long long ns(const struct timespec *a, const struct timespec *b)
{
	return (long long)(b->tv_sec - a->tv_sec) * 1000000000ll + (b->tv_nsec - a->tv_nsec);
}

static __u64 hit(struct rw_hook_cost_bpf *s, __u32 k)
{
	__u64 v = 0;

	if (bpf_map_lookup_elem(bpf_map__fd(s->maps.hits), &k, &v))
		fprintf(stderr, "warn: hits[%u] lookup failed\n", k);
	return v;
}

static int hits_reset(struct rw_hook_cost_bpf *s)
{
	__u64 zero = 0;

	for (__u32 k = 0; k < H_N; k++)
		if (bpf_map_update_elem(bpf_map__fd(s->maps.hits), &k, &zero, BPF_ANY))
			return -1;
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

/* the programs of one arm (at most two) */
static int arm_progs(struct rw_hook_cost_bpf *s, enum arm a, struct bpf_program *p[2])
{
	p[0] = p[1] = NULL;
	switch (a) {
	case A_FENTRY: p[0] = s->progs.rd_fentry; break;
	case A_FEXIT: p[0] = s->progs.rd_fexit; break;
	case A_KPM: p[0] = s->progs.rd_kpm; break;
	case A_PAIR: p[0] = s->progs.rd_pair_entry; p[1] = s->progs.rd_pair_return; break;
	case A_SESSION: p[0] = s->progs.rd_session; break;
	default: break;
	}
	return p[0] ? (p[1] ? 2 : 1) : 0;
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
static int arm(struct rw_hook_cost_bpf *s, int fd, int round, enum arm a, int n)
{
	struct bpf_program *p[2];
	struct bpf_link *l[2] = { NULL, NULL };
	struct skips before = { 0 }, after = { 0 };
	long long cpu = 0, wall = 0;
	int np = arm_progs(s, a, p), rc = 0;
	__u64 got, orphan;

	if (hits_reset(s)) {
		fprintf(stderr, "hits reset: %s\n", strerror(errno));
		return 1;
	}
	for (int i = 0; i < np; i++) {
		before.rmiss += prog_rmiss(p[i]);
		if (!(l[i] = bpf_program__attach(p[i]))) {
			fprintf(stderr, "attach %s: %s\n", bpf_program__name(p[i]), strerror(errno));
			rc = 1;
			goto out;
		}
		before.lmiss += link_lmiss(l[i]);
	}
	if (run_reads(fd, n, &cpu, &wall))
		rc = 1;
	for (int i = 0; i < np; i++) {
		after.rmiss += prog_rmiss(p[i]);
		after.lmiss += link_lmiss(l[i]);
	}
out:
	for (int i = 0; i < np; i++)
		if (l[i] && bpf_link__destroy(l[i]))
			fprintf(stderr, "warn: link destroy failed\n");
	got = arm_hit[a] < 0 ? hit(s, H_FENTRY) + hit(s, H_FEXIT) + hit(s, H_KPM) + hit(s, H_PAIR) + hit(s, H_SESSION)
			     : hit(s, (__u32)arm_hit[a]);
	orphan = hit(s, H_PAIR_NOSTASH) + hit(s, H_SESSION_NOCOOKIE) + hit(s, H_PAIR_STASH_FULL);
	printf("row round=%d event=read arm=%s n=%d cpu_ns=%lld wall_ns=%lld hits=%llu orphan=%llu rmiss=%llu lmiss=%llu\n",
	       round, arm_name[a], n, cpu, wall, (unsigned long long)got, (unsigned long long)orphan,
	       after.rmiss - before.rmiss, after.lmiss - before.lmiss);
	if (rc)
		return 1;
	if (orphan)
		return 1;
	return arm_hit[a] < 0 ? got != 0 : got != (__u64)n;
}

/* a kprobe.session and a fentry on the same function at once (design check O2) */
static int coexist(struct rw_hook_cost_bpf *s, int opens)
{
	struct bpf_link *ls, *lf = NULL;
	int rc = 1;
	__u64 hs, hf;

	if (hits_reset(s))
		return 1;
	if (!(ls = bpf_program__attach(s->progs.open_session))) {
		fprintf(stderr, "attach open_session: %s\n", strerror(errno));
		return 1;
	}
	if (!(lf = bpf_program__attach(s->progs.open_fentry))) {
		fprintf(stderr, "attach open_fentry: %s\n", strerror(errno));
		goto out;
	}
	for (int i = 0; i < opens; i++) {
		int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);

		if (fd < 0 || close(fd))
			goto out;
	}
	rc = 0;
out:
	if (lf && bpf_link__destroy(lf))
		fprintf(stderr, "warn: link destroy failed\n");
	if (bpf_link__destroy(ls))
		fprintf(stderr, "warn: link destroy failed\n");
	hs = hit(s, H_OPEN_SESSION);
	hf = hit(s, H_OPEN_FENTRY);
	rc |= hs != (__u64)opens || hf != (__u64)opens;
	printf("coexist function=security_file_open opens=%d session=%llu fentry=%llu %s\n", opens,
	       (unsigned long long)hs, (unsigned long long)hf, rc ? "FAIL" : "ok");
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
	struct rw_hook_cost_bpf *s;
	enum arm arms[A_N];
	int rounds, reads, opens, cpu, fd, na = 0, bad = 0, notramp = 0, nosession = 0, usage = argc < 4;

	for (int i = 4; i < argc; i++) {
		if (!strcmp(argv[i], "--no-trampoline"))
			notramp = 1;
		else if (!strcmp(argv[i], "--no-session"))
			nosession = 1;
		else
			usage = 1;
	}
	if (usage || (rounds = atoi(argv[1])) <= 0 || (reads = atoi(argv[2])) <= 0 || (opens = atoi(argv[3])) <= 0) {
		fprintf(stderr, "usage: %s ROUNDS READS OPENS [--no-trampoline] [--no-session]\n", argv[0]);
		return 2;
	}
	for (int a = 0; a < A_N; a++)
		if ((!notramp || (a != A_FENTRY && a != A_FEXIT)) && (!nosession || a != A_SESSION))
			arms[na++] = (enum arm)a;
	if ((cpu = pin_to_one_cpu()) < 0) {
		fprintf(stderr, "pin: %s\n", strerror(errno));
		return 1;
	}
	if ((fd = open("/dev/zero", O_RDONLY | O_CLOEXEC)) < 0) {
		fprintf(stderr, "open /dev/zero: %s\n", strerror(errno));
		return 1;
	}
	if (!(s = rw_hook_cost_bpf__open())) {
		fprintf(stderr, "open rw_hook_cost: %s\n", strerror(errno));
		return 1;
	}
	s->rodata->harness_tgid = (__u32)getpid();
	if (notramp && (bpf_program__set_autoload(s->progs.rd_fentry, false) ||
			bpf_program__set_autoload(s->progs.rd_fexit, false) ||
			bpf_program__set_autoload(s->progs.open_fentry, false))) {
		fprintf(stderr, "autoload: %s\n", strerror(errno));
		return 1;
	}
	if (nosession && (bpf_program__set_autoload(s->progs.rd_session, false) ||
			  bpf_program__set_autoload(s->progs.open_session, false))) {
		fprintf(stderr, "autoload: %s\n", strerror(errno));
		return 1;
	}
	if (rw_hook_cost_bpf__load(s)) {
		fprintf(stderr, "load: %s\n", strerror(errno));
		return 1;
	}
	printf("rw_hook_cost: libbpf %s, pinned to CPU %d, %d rounds, %d reads per arm, %d arms%s%s\n",
	       libbpf_version_string(), cpu, rounds, reads, na, notramp ? " (no trampolines)" : "",
	       nosession ? " (no session)" : "");
	if (!notramp && !nosession)
		bad |= coexist(s, opens);
	/* untimed warm-up (ADR-0012): one pass of every arm, books still checked */
	for (int k = 0; k < na; k++)
		bad |= arm(s, fd, -1, arms[k], reads / 10 + 1);
	for (int r = 0; r < rounds; r++) {
		null_syscall(r);
		for (int k = 0; k < na; k++)
			bad |= arm(s, fd, r, arms[(r + k) % na], reads);
	}
	printf("rw_hook_cost: %s\n", bad ? "FAIL" : "ok");
	rw_hook_cost_bpf__destroy(s);
	close(fd);
	return bad;
}
