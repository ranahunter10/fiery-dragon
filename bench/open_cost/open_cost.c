// SPDX-License-Identifier: MIT
/*
 * open_cost: the workload of the open-cost measurement (STATE decision 22a.4; ADR-0018 rule 2).
 * It only opens and closes files and times itself; run.py runs it with and without p15d.
 *
 *   open_cost DIR SAME DISTINCT [CPU]
 *
 * Pinned to CPU (the last online one if not given), on one thread, in this order:
 *   nullsys    10^6 x getppid(): ADR-0018 rule 3.2's baseline
 *   same       SAME x (open(DIR/same, O_RDONLY | O_CLOEXEC); close): the steady state, an object
 *              and a path capture has already seen
 *   distinct   DISTINCT x (open(DIR/d/<i>); close), each file once: with a capture started just
 *              before, every open is the first sighting of its object (its facts go in the record)
 * The files must exist (run.py makes them): creating them is not what is measured.
 * One "row" line per event: the thread's CPU time (the primary metric) and wall time. The first
 * line names the pid, so the reader can find this process's records in the WAL. Exit 0 if every
 * open and close succeeded.
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

#define NULLSYS 1000000L

static long long now_ns(clockid_t c)
{
	struct timespec t;

	clock_gettime(c, &t);
	return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void row(const char *event, long n, long long cpu0, long long wall0)
{
	printf("row event=%s n=%ld cpu_ns=%lld wall_ns=%lld\n", event, n, now_ns(CLOCK_THREAD_CPUTIME_ID) - cpu0,
	       now_ns(CLOCK_MONOTONIC) - wall0);
}

static long arg(const char *s, const char *what)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno || *end || end == s || v < 0) {
		fprintf(stderr, "open_cost: bad %s '%s'\n", what, s);
		exit(2);
	}
	return v;
}

int main(int argc, char **argv)
{
	char path[4096];
	long long cpu0, wall0;
	long same, distinct, cpu, i;
	cpu_set_t set;
	int fd;

	if (argc != 4 && argc != 5) {
		fprintf(stderr, "usage: open_cost DIR SAME DISTINCT [CPU]\n");
		return 2;
	}
	same = arg(argv[2], "SAME");
	distinct = arg(argv[3], "DISTINCT");
	cpu = argc == 5 ? arg(argv[4], "CPU") : sysconf(_SC_NPROCESSORS_ONLN) - 1;
	CPU_ZERO(&set);
	CPU_SET((int)cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set)) {
		fprintf(stderr, "open_cost: cannot pin to cpu %ld: %s\n", cpu, strerror(errno));
		return 1;
	}
	printf("workload pid=%d cpu=%ld same=%ld distinct=%ld nullsys=%ld\n", getpid(), cpu, same, distinct, NULLSYS);

	cpu0 = now_ns(CLOCK_THREAD_CPUTIME_ID);
	wall0 = now_ns(CLOCK_MONOTONIC);
	for (i = 0; i < NULLSYS; i++)
		syscall(SYS_getppid);
	row("nullsys", NULLSYS, cpu0, wall0);

	if (snprintf(path, sizeof(path), "%s/same", argv[1]) >= (int)sizeof(path)) {
		fprintf(stderr, "open_cost: DIR too long\n");
		return 2;
	}
	cpu0 = now_ns(CLOCK_THREAD_CPUTIME_ID);
	wall0 = now_ns(CLOCK_MONOTONIC);
	for (i = 0; i < same; i++) {
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0 || close(fd)) {
			fprintf(stderr, "open_cost: %s: %s\n", path, strerror(errno));
			return 1;
		}
	}
	row("same", same, cpu0, wall0);

	cpu0 = now_ns(CLOCK_THREAD_CPUTIME_ID);
	wall0 = now_ns(CLOCK_MONOTONIC);
	for (i = 0; i < distinct; i++) {
		snprintf(path, sizeof(path), "%s/d/%ld", argv[1], i);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0 || close(fd)) {
			fprintf(stderr, "open_cost: %s: %s\n", path, strerror(errno));
			return 1;
		}
	}
	row("distinct", distinct, cpu0, wall0);
	return 0;
}
