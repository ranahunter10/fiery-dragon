// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include "selftest.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "records.h"

int p15_rec_list_add(struct p15_rec_list *l, const void *data, size_t size)
{
	const char *why;
	void *copy;

	if (p15_rec_check(data, size, &why)) {
		l->invalid++;
		return 0;
	}
	if (l->n == l->cap) {
		size_t cap = l->cap ? 2 * l->cap : 64;
		void **r = realloc(l->recs, cap * sizeof(*r));

		if (!r) {
			l->dropped_oom++;
			return -ENOMEM;
		}
		l->recs = r;
		l->cap = cap;
	}
	copy = malloc(((const struct p15_hdr *)data)->len);
	if (!copy) {
		l->dropped_oom++;
		return -ENOMEM;
	}
	memcpy(copy, data, ((const struct p15_hdr *)data)->len);
	l->recs[l->n++] = copy;
	return 0;
}

void p15_rec_list_free(struct p15_rec_list *l)
{
	for (size_t i = 0; i < l->n; i++)
		free(l->recs[i]);
	free(l->recs);
	memset(l, 0, sizeof(*l));
}

/* ------------------------------------------------------------------ evaluation */

struct ctx {
	FILE *log;
	int failed;
};

static void check(struct ctx *c, int ok, const char *what)
{
	fprintf(c->log, "  %s  %s\n", ok ? "ok  " : "FAIL", what);
	if (!ok)
		c->failed++;
}

static const struct p15_hdr *H(const struct p15_rec_list *l, size_t i)
{
	return l->recs[i];
}

/* the unique record of `type` from `tgid` that satisfies `pred`; NULL unless exactly one */
static const void *only(const struct p15_rec_list *l, __u16 type, __u32 tgid,
			int (*pred)(const void *, const struct p15_selftest_expect *),
			const struct p15_selftest_expect *e, size_t *count)
{
	const void *hit = NULL;

	*count = 0;
	for (size_t i = 0; i < l->n; i++) {
		if (H(l, i)->type == type && H(l, i)->tgid == tgid && (!pred || pred(l->recs[i], e))) {
			hit = l->recs[i];
			(*count)++;
		}
	}
	return *count == 1 ? hit : NULL;
}

static int fork_of_child(const void *r, const struct p15_selftest_expect *e)
{
	return ((const struct p15_fork *)r)->child_tgid == e->child;
}

static int fork_of_grandchild(const void *r, const struct p15_selftest_expect *e)
{
	return ((const struct p15_fork *)r)->child_tgid == e->grandchild;
}

static int comm_is(const char comm[16], const char *want)
{
	return strncmp(comm, want, 16) == 0 && (strlen(want) >= 16 || comm[strlen(want)] == '\0');
}

int p15_selftest_eval(const struct p15_rec_list *l, const struct p15_selftest_expect *e, FILE *log)
{
	struct ctx c = { log, 0 };
	const struct p15_fork *fc, *fg;
	const struct p15_exec *ex;
	const struct p15_exit *xc, *xg;
	const struct p15_rename *rn[2] = { NULL, NULL };
	size_t n, n_child = 0, n_grand = 0, n_ren = 0;
	__u64 s_child = 0, s_grand = 0;
	int start_ok = 1;
	char what[160];

	check(&c, l->invalid == 0, "every record passes the length checks (none invalid)");
	check(&c, l->dropped_oom == 0, "no record dropped for lack of memory");

	fc = only(l, P15_T_FORK, e->daemon_tgid, fork_of_child, e, &n);
	snprintf(what, sizeof(what), "exactly one FORK of the child by the daemon (found %zu)", n);
	check(&c, fc != NULL, what);
	if (fc) {
		check(&c, fc->kind == 1, "  ... as a new process (kind 1)");
		s_child = fc->child_start_ns;
	}

	for (size_t i = 0; i < l->n; i++) {
		const struct p15_hdr *h = H(l, i);

		if (h->tgid == e->child) {
			n_child++;
			start_ok &= h->start_ns == s_child;
			if (h->type == P15_T_RENAME && n_ren < 2)
				rn[n_ren] = l->recs[i];
			n_ren += h->type == P15_T_RENAME;
		}
	}
	check(&c, start_ok && s_child != 0, "every child record carries the start_ns its FORK announced (ADR-0009)");
	snprintf(what, sizeof(what), "exactly 5 records from the child: 2 RENAME, FORK, EXEC, EXIT (found %zu)", n_child);
	check(&c, n_child == 5, what);
	snprintf(what, sizeof(what), "exactly 2 RENAMEs from the child (found %zu)", n_ren);
	check(&c, n_ren == 2, what);
	if (n_ren == 2) {
		check(&c, comm_is(rn[0]->old_comm, e->daemon_comm) && comm_is(rn[0]->new_comm, P15_ST_NAME),
		      "  ... first: daemon comm -> \"" P15_ST_NAME "\" (prctl)");
		check(&c, comm_is(rn[1]->old_comm, P15_ST_NAME) && comm_is(rn[1]->new_comm, "true"),
		      "  ... second: \"" P15_ST_NAME "\" -> \"true\" (exec)");
	}

	fg = only(l, P15_T_FORK, e->child, fork_of_grandchild, e, &n);
	snprintf(what, sizeof(what), "exactly one FORK of the grandchild by the child (found %zu)", n);
	check(&c, fg != NULL, what);
	if (fg) {
		check(&c, fg->kind == 1 && fg->child_start_ns != s_child, "  ... a new process with its own start_ns");
		s_grand = fg->child_start_ns;
	}

	ex = only(l, P15_T_EXEC, e->child, NULL, e, &n);
	snprintf(what, sizeof(what), "exactly one EXEC from the child (found %zu)", n);
	check(&c, ex != NULL, what);
	if (ex) {
		static const char argv[] = "true\0" P15_ST_NAME;   /* sizeof includes the final NUL */
		__u16 fl, al;
		const __u8 *f = p15_exec_filename(ex, &fl), *a = p15_exec_argv(ex, &al);

		check(&c, fl == strlen(P15_ST_EXE) && memcmp(f, P15_ST_EXE, fl) == 0 &&
			  ex->filename_full == strlen(P15_ST_EXE),
		      "  ... filename \"" P15_ST_EXE "\", not truncated");
		check(&c, al == sizeof(argv) && memcmp(a, argv, al) == 0 && ex->argv_full == sizeof(argv),
		      "  ... argv \"true\\0" P15_ST_NAME "\\0\" from the kernel's copy, not truncated");
		check(&c, ex->h.flags == 0 && ex->old_tid == e->child, "  ... no flags; old_tid is the child");
	}

	xc = only(l, P15_T_EXIT, e->child, NULL, e, &n);
	snprintf(what, sizeof(what), "exactly one EXIT from the child (found %zu)", n);
	check(&c, xc != NULL, what);
	if (xc)
		check(&c, xc->group_dead == 1 && xc->exit_code == 0, "  ... group_dead, exit status 0");

	for (size_t i = 0; i < l->n; i++)
		n_grand += H(l, i)->tgid == e->grandchild;
	xg = only(l, P15_T_EXIT, e->grandchild, NULL, e, &n);
	snprintf(what, sizeof(what), "the grandchild's only record is one EXIT (records %zu, EXITs %zu)", n_grand, n);
	check(&c, xg != NULL && n_grand == 1, what);
	if (xg)
		check(&c, xg->group_dead == 1 && xg->exit_code == (P15_ST_GRANDCHILD_EXIT << 8) &&
			  xg->h.start_ns == s_grand,
		      "  ... group_dead, exit status 7, start_ns as its FORK announced");

	if (fg && ex && xc && n_ren == 2)
		check(&c, rn[0]->h.ts_ns <= fg->h.ts_ns && fg->h.ts_ns <= rn[1]->h.ts_ns &&
			  rn[1]->h.ts_ns <= ex->h.ts_ns && ex->h.ts_ns <= xc->h.ts_ns,
		      "child order by time: RENAME, FORK, RENAME, EXEC, EXIT");
	return c.failed;
}

/* ------------------------------------------------------------------ running it */

static int on_record(void *ctx, void *data, size_t size)
{
	int rc = p15_rec_list_add(ctx, data, size);

	/*
	 * A record not stored is already counted (dropped_oom) and fails the test. Returning
	 * the error would only stop libbpf early: it has consumed the record either way.
	 */
	(void)rc;
	return 0;
}

static double now_s(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

static void child_main(int wfd)
{
	pid_t g;

	prctl(PR_SET_NAME, P15_ST_NAME);
	g = fork();
	if (g == 0)
		_exit(P15_ST_GRANDCHILD_EXIT);   /* exit-ok: self-test grandchild */
	if (g < 0 || write(wfd, &g, sizeof(g)) != sizeof(g))
		_exit(120);                      /* exit-ok: self-test child */
	waitpid(g, NULL, 0);
	execl(P15_ST_EXE, "true", P15_ST_NAME, (char *)NULL);
	_exit(127);                              /* exit-ok: self-test child, exec failed */
}

int p15_selftest_run(int spine_rb_fd, FILE *log)
{
	struct p15_rec_list l = { 0 };
	struct p15_selftest_expect e = { 0 };
	struct ring_buffer *rb;
	int p[2], st, failed, rc;
	pid_t child, g = 0;
	double quiet_since, deadline;
	size_t last_n;
	FILE *f;

	rb = ring_buffer__new(spine_rb_fd, on_record, &l, NULL);
	if (!rb) {
		rc = -errno;
		fprintf(log, "selftest: ring_buffer__new failed: %s\n", strerror(-rc));
		return rc;
	}
	ring_buffer__consume(rb);          /* forget records from before the test */
	p15_rec_list_free(&l);
	e.daemon_tgid = getpid();
	f = fopen("/proc/self/comm", "r");
	if (!f || !fgets(e.daemon_comm, sizeof(e.daemon_comm), f)) {
		rc = f ? -EIO : -errno;
		fprintf(log, "selftest: cannot read /proc/self/comm\n");
		if (f)
			fclose(f);
		ring_buffer__free(rb);
		return rc;
	}
	fclose(f);
	e.daemon_comm[strcspn(e.daemon_comm, "\n")] = '\0';

	if (pipe2(p, O_CLOEXEC) < 0) {
		rc = -errno;
		ring_buffer__free(rb);
		return rc;
	}
	child = fork();
	if (child < 0) {
		rc = -errno;
		close(p[0]);
		close(p[1]);
		ring_buffer__free(rb);
		return rc;
	}
	if (child == 0) {
		close(p[0]);
		child_main(p[1]);
	}
	close(p[1]);
	if (read(p[0], &g, sizeof(g)) != sizeof(g))
		g = 0;
	close(p[0]);
	waitpid(child, &st, 0);
	e.child = child;
	e.grandchild = g;

	/* collect until 300 ms without a new record, at most 3 s */
	deadline = now_s() + 3.0;
	quiet_since = now_s();
	last_n = 0;
	while (now_s() < deadline) {
		ring_buffer__poll(rb, 50);
		if (l.n + l.invalid != last_n) {
			last_n = l.n + l.invalid;
			quiet_since = now_s();
		} else if (now_s() - quiet_since > 0.3) {
			break;
		}
	}
	ring_buffer__free(rb);

	fprintf(log, "selftest: daemon %u, child %u, grandchild %u; %zu records collected, %zu invalid\n",
		e.daemon_tgid, e.child, e.grandchild, l.n, l.invalid);
	check(&(struct ctx){ log, 0 }, WIFEXITED(st) && WEXITSTATUS(st) == 0, "test child exited 0");
	failed = p15_selftest_eval(&l, &e, log);
	if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0) || !g)
		failed++;
	for (size_t i = 0; i < l.n; i++) {
		const struct p15_hdr *h = l.recs[i];
		char line[1600];

		if (h->tgid == e.child || h->tgid == e.grandchild ||
		    (h->type == P15_T_FORK && ((const struct p15_fork *)h)->child_tgid == e.child)) {
			p15_rec_format(h, line, sizeof(line));
			fprintf(log, "    %s\n", line);
		}
	}
	p15_rec_list_free(&l);
	return failed;
}
