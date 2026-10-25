// SPDX-License-Identifier: MIT
/*
 * exec_cost: the CPU cost of the spine's EXEC program, built three ways (ADR-0017 layer 1:
 * FIXED reserves the maximum, OUTPUT copies from per-CPU scratch, DYNPTR reserves exactly and
 * reads argv straight into the ring). Each way is the production bpf/progs/spine.bpf.c compiled
 * with -DP15_EXEC_WAY=N, so the code measured is the code shipped.
 *
 *   exec_cost OBJDIR ROUNDS EXECS ARGV_BYTES...      (root)
 *
 * OBJDIR holds spine-fixed.bpf.o, spine-output.bpf.o and spine-dynptr.bpf.o. For each way it
 * first runs the load-time self-test (all four programs attached) and prints the verdict. Then,
 * per round and per argv size, it measures every way once, in an order rotated each round:
 * load the object with only spine_exec, attach it, exec /bin/true EXECS times with an argv of
 * ARGV_BYTES bytes, and read the program's run_cnt and run_time_ns (bpf_stats, enabled for the
 * whole run). Every record is checked: it passes p15_rec_check, and its ring size is its len
 * (OUTPUT, DYNPTR) or the maximum (FIXED). One "row" line per measurement; summarize.py turns
 * them into the report. Each round also times a null syscall (getppid, 10^6 calls), the
 * same-session baseline ADR-0018 rule 3.2 asks per-event costs to be given against.
 * Exit 0 if every way loaded, the self-test verdicts are as expected (FIXED fails exactly its
 * ring-size check, the others pass) and every measurement saw all its execs with correct records.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "records.h"
#include "selftest.h"

static const char *const ways[3] = { "fixed", "output", "dynptr" };

struct tally {
	unsigned want_argv;          /* argv bytes of our execs */
	int fixed;                   /* the FIXED way: records take the maximum */
	unsigned long long ours, foreign, invalid, wrong_size, wrong_argv;
};

static int on_rec(void *ctx, void *data, size_t size)
{
	struct tally *t = ctx;
	const struct p15_exec *r = data;
	const char *why;
	__u16 fl;
	const __u8 *f;

	if (p15_rec_check(data, size, &why) || r->h.type != P15_T_EXEC) {
		t->invalid++;
		return 0;
	}
	f = p15_exec_filename(r, &fl);
	if (fl != 9 || memcmp(f, "/bin/true", 9) || r->argv_full != t->want_argv) {
		t->foreign++;            /* another process's exec: its run counts in run_cnt too */
		return 0;
	}
	t->ours++;
	t->wrong_size += size != (t->fixed ? (size_t)P15_EXEC_MAX_SIZE : (size_t)r->h.len);
	t->wrong_argv += r->argv_len != t->want_argv || (r->h.flags & (P15_F_TRUNCATED | P15_F_READ_FAILED));
	return 0;
}

static struct bpf_object *open_way(const char *dir, int way, int exec_only)
{
	char path[512];
	struct bpf_object *o;
	struct bpf_program *p;

	snprintf(path, sizeof(path), "%s/spine-%s.bpf.o", dir, ways[way]);
	o = bpf_object__open_file(path, NULL);
	if (!o) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return NULL;
	}
	bpf_object__for_each_program(p, o)
		if (exec_only && strcmp(bpf_program__name(p), "spine_exec") &&
		    bpf_program__set_autoload(p, false)) {
			bpf_object__close(o);
			return NULL;
		}
	if (bpf_object__load(o)) {
		fprintf(stderr, "load %s: %s\n", path, strerror(errno));
		bpf_object__close(o);
		return NULL;
	}
	return o;
}

/* attach every loaded program; links are freed with the object's programs by the caller */
static int attach_all(struct bpf_object *o, struct bpf_link **links, int max)
{
	struct bpf_program *p;
	int n = 0;

	bpf_object__for_each_program(p, o) {
		if (!bpf_program__autoload(p))
			continue;
		if (n == max || !(links[n] = bpf_program__attach(p)))
			return -1;
		n++;
	}
	return n;
}

static void detach(struct bpf_link **links, int n)
{
	for (int i = 0; i < n; i++)
		if (bpf_link__destroy(links[i]))
			fprintf(stderr, "warn: link destroy failed\n");
}

static int selftest_way(const char *dir, int way)
{
	struct bpf_object *o = open_way(dir, way, 0);
	struct bpf_link *links[8];
	FILE *null = fopen("/dev/null", "w");
	int n, failed = -1;

	if (o && null && (n = attach_all(o, links, 8)) == 4) {
		failed = p15_selftest_run(bpf_map__fd(bpf_object__find_map_by_name(o, "spine_rb")), null);
		detach(links, n);
	}
	if (null)
		fclose(null);
	bpf_object__close(o);
	printf("selftest way=%s %s failed_checks=%d\n", ways[way], failed == 0 ? "PASS" : "FAIL", failed);
	return failed;
}

static void null_syscall(int round)
{
	struct timespec a, b;
	const long n = 1000000;

	clock_gettime(CLOCK_MONOTONIC, &a);
	for (long i = 0; i < n; i++)
		syscall(SYS_getppid);
	clock_gettime(CLOCK_MONOTONIC, &b);
	printf("nullsys round=%d calls=%ld total_ns=%lld\n", round, n,
	       (long long)(b.tv_sec - a.tv_sec) * 1000000000ll + (b.tv_nsec - a.tv_nsec));
}

static int measure(const char *dir, int round, int way, int execs, unsigned argv_bytes, const char *arg)
{
	struct tally t = { .want_argv = argv_bytes, .fixed = way == 0 };
	struct bpf_object *o = open_way(dir, way, 1);
	struct bpf_link *link[1];
	struct ring_buffer *rb = NULL;
	struct bpf_prog_info info;
	__u32 ilen = sizeof(info);
	int rc = -1, pfd;

	if (!o || attach_all(o, link, 1) != 1)
		goto out;
	rb = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(o, "spine_rb")), on_rec, &t, NULL);
	if (!rb)
		goto out_detach;
	for (int i = 0; i < execs; i++) {
		pid_t c = fork();
		int st;

		if (c == 0) {
			execl("/bin/true", "true", arg, (char *)NULL);
			_exit(127);
		}
		if (c < 0 || waitpid(c, &st, 0) != c || !WIFEXITED(st) || WEXITSTATUS(st)) {
			fprintf(stderr, "exec %d failed\n", i);
			goto out_detach;
		}
		if (i % 256 == 255 && ring_buffer__consume(rb) < 0)
			goto out_detach;
	}
	if (ring_buffer__consume(rb) < 0)
		goto out_detach;
	pfd = bpf_program__fd(bpf_object__find_program_by_name(o, "spine_exec"));
	memset(&info, 0, sizeof(info));
	if (bpf_prog_get_info_by_fd(pfd, &info, &ilen))
		goto out_detach;
	printf("row round=%d way=%s argv=%u execs=%d run_cnt=%llu run_time_ns=%llu ours=%llu foreign=%llu "
	       "invalid=%llu wrong_size=%llu wrong_argv=%llu\n", round, ways[way], argv_bytes, execs,
	       (unsigned long long)info.run_cnt, (unsigned long long)info.run_time_ns, t.ours, t.foreign, t.invalid,
	       t.wrong_size, t.wrong_argv);
	rc = t.ours == (unsigned long long)execs && !t.invalid && !t.wrong_size && !t.wrong_argv ? 0 : 1;
out_detach:
	detach(link, 1);
out:
	ring_buffer__free(rb);
	bpf_object__close(o);
	return rc;
}

int main(int argc, char **argv)
{
	int rounds, execs, stats_fd, bad = 0, nsizes = argc - 4;
	unsigned sizes[16];
	char *args[16];

	if (argc < 5 || nsizes > 16 || (rounds = atoi(argv[2])) <= 0 || (execs = atoi(argv[3])) <= 0) {
		fprintf(stderr, "usage: %s OBJDIR ROUNDS EXECS ARGV_BYTES...\n", argv[0]);
		return 2;
	}
	for (int i = 0; i < nsizes; i++) {
		int a = atoi(argv[4 + i]);

		/* argv = "true\0" + one argument of (a - 6) bytes + "\0": a bytes, at most the record's maximum */
		if (a < 7 || a > P15_EXEC_ARGV_MAX) {
			fprintf(stderr, "ARGV_BYTES must be 7..%d\n", P15_EXEC_ARGV_MAX);
			return 2;
		}
		sizes[i] = a;
		if (!(args[i] = calloc(1, a - 5)))
			return 1;
		memset(args[i], 'x', a - 6);
	}
	stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
	if (stats_fd < 0) {
		fprintf(stderr, "bpf_enable_stats: %s\n", strerror(errno));
		return 1;
	}
	printf("exec_cost: libbpf %s, %d rounds x %d execs, ways fixed/output/dynptr\n", libbpf_version_string(),
	       rounds, execs);
	for (int w = 0; w < 3; w++) {
		int failed = selftest_way(argv[1], w);

		bad |= w == 0 ? failed != 1 : failed != 0;   /* FIXED: only the ring-size check fails */
	}
	for (int r = 0; r < rounds; r++) {
		null_syscall(r);
		for (int s = 0; s < nsizes; s++)
			for (int k = 0; k < 3; k++)
				bad |= measure(argv[1], r, (r + k) % 3, execs, sizes[s], args[s]) != 0;
	}
	close(stats_fd);
	for (int i = 0; i < nsizes; i++)
		free(args[i]);
	printf("exec_cost: %s\n", bad ? "FAIL (see above)" : "ok");
	return bad;
}
