// SPDX-License-Identifier: MIT
/*
 * open_sections: where the file programs' time goes, section by section, and how often the kernel
 * skips the path program when tasks contend for the CPUs (STATE decisions waiting 1 and 2). root.
 *
 *   open_sections single ROUNDS N DIR [CPU]
 *   open_sections contend WORKERS N DIR
 *
 * Both load build/file_prof.bpf.o: file.bpf.c built with -DP15_PROFILE (bpf/include/p15_prof.h),
 * attached as p15d attaches it (path fentry, session, close, inode free; not the FD iterator), with
 * the bulk ring read by this program. DIR/same must exist (bench/open_cost's run.py makes it).
 *
 * single: pinned to CPU (the last online one by default), ROUNDS rounds after one untimed warm-up
 *   (round -1); each round is N x open(DIR/same) + close, the ring read every 4,096 opens. Per round,
 *   one "row" line per section: its samples and total ns, this process's runs only; then a "host"
 *   line, 100,000 getppid() timed on the thread's CPU clock (the host-speed control, E-0181).
 * contend: WORKERS processes, not pinned, each N x open(DIR/same) + close, while this process reads
 *   the ring. One "contend" line: the counters' change over the run (fentry runs, session entries,
 *   OPENs written with PATH_MISSING because the path program did not run, records lost), the records
 *   read from the ring by type, and the programs' recursion_misses and links' kprobe_multi.missed.
 *   These count every task's opens, not only the workers'. Then one "walk" line (ADR-0029): the
 *   counters of the session return's walk, the OPENs read with PATH_WALKED, and of those naming a
 *   file called "same", how many name DIR/same (resolved) exactly and how many another path.
 * Last line: "books ok" when the ring handed over every record the counters say was written (OPEN
 * = OPEN_EMITTED + MISSING_EMITTED, CLOSE = CLOSE_EMITTED) and nothing was lost, and in contend
 * mode the walked OPENs read equal the WALKED counter and none of DIR/same is wrong; else
 * "books FAIL", exit 1.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "counters.h"
#include "p15_file.h"
#include "p15_prof.h"
#include "p15_records.h"
#include "p15_snap.h"   /* before the skeleton: its .bss holds struct p15_fd_books */
#include "file_prof.skel.h"

static const char *const SEC_NAME[P15_PROF__N] = {
	"empty", "open_all", "open_claim", "open_hdr", "open_facts", "open_obj", "open_file", "open_dpath",
	"open_output", "sess_entry", "sess_file", "sess_return", "free_all", "free_lookup", "free_ring", "free_delete",
};

struct books {
	unsigned long long open, close, other, walked, target, target_wrong;
	const char *want;   /* DIR/same, resolved: what a walked OPEN of it must say */
	size_t want_len;
};

static int on_rec(void *ctx, void *data, size_t size)
{
	struct books *b = ctx;
	const struct p15_hdr *h = data;

	if (size < sizeof(*h))
		b->other++;
	else if (h->type == P15_T_OPEN) {
		const struct p15_open *o = data;

		b->open++;
		if (size >= sizeof(*o) && (o->fflags & P15_FF_PATH_WALKED)) {
			const char *pth = (const char *)(o + 1) + o->facts_len;

			b->walked++;
			if (b->want && sizeof(*o) + o->facts_len + o->path_len <= size && o->path_len >= 5 &&
			    !memcmp(pth + o->path_len - 5, "/same", 5)) {
				b->target++;
				if (o->path_len != b->want_len || memcmp(pth, b->want, b->want_len))
					b->target_wrong++;
			}
		}
	}
	else if (h->type == P15_T_CLOSE)
		b->close++;
	else
		b->other++;
	return 0;
}

static unsigned long long nullsys_ns(long n)
{
	struct timespec a, b;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &a);
	for (long i = 0; i < n; i++)
		syscall(SYS_getppid);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &b);
	return (unsigned long long)((b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec));
}

static int open_close(const char *path, long n)
{
	for (long i = 0; i < n; i++) {
		int fd = open(path, O_RDONLY | O_CLOEXEC);

		if (fd < 0 || close(fd)) {
			fprintf(stderr, "open_sections: %s: %s\n", path, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static unsigned long long prog_misses(const struct bpf_program *p)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

	return bpf_prog_get_info_by_fd(bpf_program__fd(p), &info, &len) ? ~0ull : info.recursion_misses;
}

static unsigned long long link_missed(const struct bpf_link *l)
{
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);

	if (!l || bpf_link_get_info_by_fd(bpf_link__fd(l), &info, &len))
		return ~0ull;
	return info.type == BPF_LINK_TYPE_KPROBE_MULTI ? info.kprobe_multi.missed : 0;
}

int main(int argc, char **argv)
{
	struct file_prof_bpf *s;
	struct ring_buffer *rb;
	struct p15_counters ctr = { 0 };
	struct books b = { 0 };
	uint64_t c0[P15_CTR_MAX], c1[P15_CTR_MAX];
	char path[4096], want[4096];
	int single, ncpu, rc = 0;
	long rounds = 0, workers = 0, n;

	if (argc < 5 || argc > 6 || (strcmp(argv[1], "single") && strcmp(argv[1], "contend")) ||
	    (!strcmp(argv[1], "contend") && argc != 5)) {
		fprintf(stderr, "usage: open_sections single ROUNDS N DIR [CPU] | open_sections contend WORKERS N DIR\n");
		return 2;
	}
	single = !strcmp(argv[1], "single");
	(single ? &rounds : &workers)[0] = atol(argv[2]);
	n = atol(argv[3]);
	if ((single ? rounds : workers) < 1 || n < 1 ||
	    snprintf(path, sizeof(path), "%s/same", argv[4]) >= (int)sizeof(path) || access(path, R_OK)) {
		fprintf(stderr, "open_sections: ROUNDS or WORKERS >= 1, N >= 1, and %s readable\n", path);
		return 2;
	}
	ncpu = libbpf_num_possible_cpus();
	s = file_prof_bpf__open();
	if (!s || ncpu <= 0 || p15_counters_configure(s->maps.file_counters, &s->rodata->file_counters_ncpu, ncpu)) {
		fprintf(stderr, "open_sections: open failed\n");
		return 1;
	}
	s->rodata->file_wake_bytes = bpf_map__max_entries(s->maps.bulk_rb) / 4;   /* as p15d (ADR-0020 rule 2) */
	bpf_program__set_autoattach(s->progs.file_fd_iter, false);
	if (file_prof_bpf__load(s) || p15_counters_map(&ctr, bpf_map__fd(s->maps.file_counters), ncpu) ||
	    file_prof_bpf__attach(s)) {
		fprintf(stderr, "open_sections: load or attach failed: %s\n", strerror(errno));
		return 1;
	}
	rb = ring_buffer__new(bpf_map__fd(s->maps.bulk_rb), on_rec, &b, NULL);
	if (!rb) {
		fprintf(stderr, "open_sections: ring_buffer__new failed\n");
		return 1;
	}
	ring_buffer__consume(rb);
	b = (struct books){ 0 };
	if (realpath(path, want)) {
		b.want = want;
		b.want_len = strlen(want);
	}
	p15_counters_sum(&ctr, c0);
	printf("config mode=%s %s=%ld n=%ld ncpu=%d dir=%s\n", argv[1], single ? "rounds" : "workers",
	       single ? rounds : workers, n, ncpu, argv[4]);

	if (single) {
		long cpu = argc == 6 ? atol(argv[5]) : sysconf(_SC_NPROCESSORS_ONLN) - 1;
		cpu_set_t set;

		CPU_ZERO(&set);
		CPU_SET((int)cpu, &set);
		if (cpu < 0 || sched_setaffinity(0, sizeof(set), &set)) {
			fprintf(stderr, "open_sections: cannot pin to cpu %ld\n", cpu);
			return 1;
		}
		s->bss->p15_prof_tgid = (__u32)getpid();
		for (long r = -1; r < rounds && !rc; r++) {
			memset((void *)s->bss->p15_prof_ns, 0, sizeof(s->bss->p15_prof_ns));
			memset((void *)s->bss->p15_prof_n, 0, sizeof(s->bss->p15_prof_n));
			for (long done = 0; done < n && !rc; done += 4096) {
				rc = open_close(path, n - done < 4096 ? n - done : 4096);
				ring_buffer__consume(rb);
			}
			for (int k = 0; k < P15_PROF__N; k++)
				printf("row round=%ld sec=%s n=%llu ns=%llu\n", r, SEC_NAME[k],
				       (unsigned long long)s->bss->p15_prof_n[k], (unsigned long long)s->bss->p15_prof_ns[k]);
			printf("host round=%ld nullsys_n=100000 ns=%llu\n", r, nullsys_ns(100000));
		}
	} else {
		unsigned long long m0[3], m1[3], l0[3], l1[3];
		const struct bpf_program *pr[3] = { s->progs.file_open_path, s->progs.file_open_session, s->progs.file_free };
		const struct bpf_link *lk[3] = { s->links.file_open_path, s->links.file_open_session, s->links.file_free };
		int live = 0, status;

		for (int k = 0; k < 3; k++)
			m0[k] = prog_misses(pr[k]), l0[k] = link_missed(lk[k]);
		for (long w = 0; w < workers; w++) {
			pid_t pid = fork();

			if (pid == 0)
				_exit(open_close(path, n) ? 1 : 0);   /* exit-ok: a forked workload child */
			if (pid < 0) {
				fprintf(stderr, "open_sections: fork: %s\n", strerror(errno));
				rc = -1;
				break;
			}
			live++;
		}
		while (live > 0) {
			pid_t pid = waitpid(-1, &status, WNOHANG);

			if (pid > 0) {
				live--;
				if (!WIFEXITED(status) || WEXITSTATUS(status))
					rc = -1;
				continue;
			}
			ring_buffer__poll(rb, 10);
			ring_buffer__consume(rb);
		}
		ring_buffer__consume(rb);
		p15_counters_sum(&ctr, c1);
		for (int k = 0; k < 3; k++)
			m1[k] = prog_misses(pr[k]), l1[k] = link_missed(lk[k]);
#define D(k) (unsigned long long)(c1[(k)] - c0[(k)])
		printf("contend workers=%ld n=%ld opens=%ld fentry_run=%llu session_entry=%llu session_no_inode=%llu "
		       "missing=%llu open_emitted=%llu open_lost=%llu missing_lost=%llu close_emitted=%llu close_lost=%llu "
		       "rmiss_path=%llu rmiss_session=%llu rmiss_free=%llu lmiss_session=%llu lmiss_free=%llu\n",
		       workers, n, workers * n, D(P15_FC_FENTRY_RUN), D(P15_FC_SESSION_ENTRY), D(P15_FC_SESSION_NO_INODE),
		       D(P15_FC_MISSING_EMITTED), D(P15_FC_OPEN_EMITTED), D(P15_FC_OPEN_LOST), D(P15_FC_MISSING_LOST),
		       D(P15_FC_CLOSE_EMITTED), D(P15_FC_CLOSE_LOST), m1[0] - m0[0], m1[1] - m0[1], m1[2] - m0[2],
		       l1[1] - l0[1], l1[2] - l0[2]);
		ring_buffer__consume(rb);
		printf("walk walked=%llu walk_unnamed=%llu walk_raced=%llu walk_truncated=%llu rec_walked=%llu target=%llu "
		       "target_wrong=%llu\n",
		       D(P15_FC_WALKED), D(P15_FC_WALK_UNNAMED), D(P15_FC_WALK_RACED), D(P15_FC_WALK_TRUNCATED), b.walked,
		       b.target, b.target_wrong);
	}
	ring_buffer__consume(rb);
	p15_counters_sum(&ctr, c1);
	{
		int ok = !rc && b.open == D(P15_FC_OPEN_EMITTED) + D(P15_FC_MISSING_EMITTED) &&
			 b.close == D(P15_FC_CLOSE_EMITTED) && !D(P15_FC_OPEN_LOST) && !D(P15_FC_MISSING_LOST) &&
			 !D(P15_FC_CLOSE_LOST) && (single || (b.walked == D(P15_FC_WALKED) && !b.target_wrong && b.want));

		printf("books %s open=%llu close=%llu other=%llu\n", ok ? "ok" : "FAIL", b.open, b.close, b.other);
		rc = ok ? 0 : 1;
	}
#undef D
	ring_buffer__free(rb);
	p15_counters_unmap(&ctr);
	file_prof_bpf__destroy(s);
	return rc;
}
