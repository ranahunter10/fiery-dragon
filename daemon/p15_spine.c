// SPDX-License-Identifier: MIT
/*
 * p15-spine: load and attach the spine programs (ADR-0003), then
 *
 *   p15-spine selftest        run the load-time self-test once; exit 0 only if it passes
 *   p15-spine dump SECONDS    run the self-test, then print every spine record for SECONDS
 *
 * This is the Phase-1 step-3 tool; the drain-and-WAL daemon (p15d, step 4) reuses its parts.
 * Counters are printed at the end, after detaching: any RESERVE_FAILED or BUILD_FAILED, or
 * SEEN != EMITTED + RESERVE_FAILED + BUILD_FAILED for any type, fails the run.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "p15_counters.h"
#include "records.h"
#include "selftest.h"
#include "spine.skel.h"

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

/* the format attribute lets -Wformat=2 check callers instead of flagging the forwarded fmt */
__attribute__((format(printf, 2, 0)))
static int print_libbpf(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	return level == LIBBPF_DEBUG ? 0 : vfprintf(stderr, fmt, ap);
}

struct dump_ctx {
	unsigned long long records, invalid;
};

static int on_dump(void *ctx, void *data, size_t size)
{
	struct dump_ctx *d = ctx;
	char line[1600];
	const char *why;

	if (p15_rec_check(data, size, &why)) {
		d->invalid++;
		printf("INVALID (%s), %zu bytes\n", why, size);
		return 0;
	}
	d->records++;
	p15_rec_format(data, line, sizeof(line));
	printf("%s\n", line);
	return 0;
}

/* Sum the per-CPU counters. Returns 0 if no spine record was lost and every type's books close. */
static int print_counters(struct spine_bpf *skel)
{
	static const char *types[] = { "?", "FORK", "EXEC", "EXIT", "RENAME" };
	int ncpu = libbpf_num_possible_cpus(), fd = bpf_map__fd(skel->maps.spine_counters), bad = 0;
	__u64 *vals, sum[P15_CTR_MAX] = { 0 };

	if (ncpu <= 0 || !(vals = calloc(ncpu, sizeof(*vals))))
		return -1;
	for (__u32 k = 0; k < P15_CTR_MAX; k++) {
		if (bpf_map_lookup_elem(fd, &k, vals)) {
			free(vals);
			return -1;
		}
		for (int c = 0; c < ncpu; c++)
			sum[k] += vals[c];
	}
	free(vals);
	printf("counters: type    seen  emitted  reserve_failed  build_failed  read_failed  truncated\n");
	for (int t = 1; t <= 4; t++) {
		__u64 seen = sum[P15_CTR_INDEX(t, P15_CK_SEEN)], em = sum[P15_CTR_INDEX(t, P15_CK_EMITTED)],
		      rf = sum[P15_CTR_INDEX(t, P15_CK_RESERVE_FAILED)], bf = sum[P15_CTR_INDEX(t, P15_CK_BUILD_FAILED)];

		printf("          %-6s %6llu %8llu %15llu %13llu %12llu %10llu%s\n", types[t], (unsigned long long)seen,
		       (unsigned long long)em, (unsigned long long)rf, (unsigned long long)bf,
		       (unsigned long long)sum[P15_CTR_INDEX(t, P15_CK_READ_FAILED)],
		       (unsigned long long)sum[P15_CTR_INDEX(t, P15_CK_TRUNCATED)],
		       rf || bf ? "   <- spine records lost: run invalid" :
		       seen != em + rf + bf ? "   <- seen != emitted + reserve_failed + build_failed" : "");
		/* read after detach (quiescent), so the books must close exactly (ADR-0006 rule 6) */
		bad |= rf != 0 || bf != 0 || seen != em + rf + bf;
	}
	return bad;
}

int main(int argc, char **argv)
{
	struct spine_bpf *skel;
	int failed, rc = 1;

	if (argc < 2 || (strcmp(argv[1], "selftest") && strcmp(argv[1], "dump")) ||
	    (!strcmp(argv[1], "dump") && (argc != 3 || atoi(argv[2]) <= 0))) {
		fprintf(stderr, "usage: %s selftest | %s dump SECONDS\n", argv[0], argv[0]);
		return 2;
	}
	libbpf_set_print(print_libbpf);
	skel = spine_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "load failed: %s\n", strerror(errno));
		return 1;
	}
	if (spine_bpf__attach(skel)) {
		fprintf(stderr, "attach failed: %s\n", strerror(errno));
		goto out;
	}
	printf("p15-spine: libbpf %s, 4 programs attached\n", libbpf_version_string());

	failed = p15_selftest_run(bpf_map__fd(skel->maps.spine_rb), stdout);
	if (failed < 0)
		printf("selftest: FAIL (could not run: %s)\n", strerror(-failed));
	else
		printf("selftest: %s (%d failed checks)\n", failed == 0 ? "PASS" : "FAIL", failed);
	if (failed != 0)
		goto out_counters;

	if (!strcmp(argv[1], "dump")) {
		struct dump_ctx d = { 0 };
		struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.spine_rb), on_dump, &d, NULL);
		time_t end = time(NULL) + atoi(argv[2]);

		if (!rb)
			goto out_counters;
		signal(SIGINT, on_signal);
		signal(SIGTERM, on_signal);
		while (!stop && time(NULL) < end)
			ring_buffer__poll(rb, 100);
		ring_buffer__consume(rb);
		ring_buffer__free(rb);
		printf("dump: %llu records, %llu invalid\n", d.records, d.invalid);
		if (d.invalid)
			goto out_counters;
	}
	rc = 0;
out_counters:
	/* detaching unregisters the tracepoints synchronously: no program runs after it returns */
	spine_bpf__detach(skel);
	if (print_counters(skel))
		rc = 1;
out:
	spine_bpf__destroy(skel);
	return rc;
}
