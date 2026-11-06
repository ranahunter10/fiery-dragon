// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include "selftest.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
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
	l->size_not_len += size != ((const struct p15_hdr *)data)->len;
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

/* the kernel's internal dev_t (include/linux/kdev_t.h, MKDEV) from a userspace one */
static __u32 kdev(dev_t d)
{
	return (__u32)(major(d) << 20 | minor(d));
}

int p15_selftest_exec_facts(const char *path, struct p15_selftest_exec_facts *f)
{
	char real[PATH_MAX];
	const char *base;
	struct statfs sf;
	struct stat st;
	uid_t ru, eu, su;
	gid_t rg, eg, sg;

	memset(f, 0, sizeof(*f));
	if (stat(path, &st) < 0 || statfs(path, &sf) < 0 || !realpath(path, real))
		return -errno;
	if (getresuid(&ru, &eu, &su) < 0 || getresgid(&rg, &eg, &sg) < 0)
		return -errno;
	f->ino = st.st_ino;
	f->dev = kdev(st.st_dev);
	f->nlink = (__u32)st.st_nlink;
	f->fs_magic = (__u32)sf.f_type;
	f->mode = st.st_mode;
	f->uid = st.st_uid;
	f->gid = st.st_gid;
	f->ctime_ns = (__u64)st.st_ctim.tv_sec * 1000000000ull + (__u64)st.st_ctim.tv_nsec;
	f->mtime_ns = (__u64)st.st_mtim.tv_sec * 1000000000ull + (__u64)st.st_mtim.tv_nsec;
	f->cred[0] = ru; f->cred[1] = eu; f->cred[2] = rg; f->cred[3] = eg;
	f->cred[4] = (__u32)setfsuid((uid_t)-1);   /* an invalid id changes nothing and returns the current one */
	f->cred[5] = (__u32)setfsgid((gid_t)-1);
	base = strrchr(real, '/');
	base = base ? base + 1 : real;
	if (strlen(base) >= sizeof(f->name))
		return -ENAMETOOLONG;   /* the record would carry it truncated; the test's exe must fit */
	memcpy(f->name, base, strlen(base) + 1);
	for (int fd = 0; fd < 3; fd++) {
		if (fstat(fd, &st) < 0)
			continue;   /* closed: the record's four fields are zero too */
		f->std_ino[fd] = st.st_ino;
		f->std_dev[fd] = kdev(st.st_dev);
		f->std_rdev[fd] = kdev(st.st_rdev);
		f->std_mode[fd] = st.st_mode;
	}
	return 0;
}

/* EXEC v2's provenance facts against what the daemon saw (ADR-0025). One check line per group,
 * so a failure names the group. */
static void check_exec_facts(struct ctx *c, const struct p15_exec *ex, const struct p15_selftest_exec_facts *f)
{
	const __u32 cred[6] = { ex->uid, ex->euid, ex->gid, ex->egid, ex->fsuid, ex->fsgid };
	const __u64 ino[3] = { ex->stdin_ino, ex->stdout_ino, ex->stderr_ino };
	const __u32 dev[3] = { ex->stdin_dev, ex->stdout_dev, ex->stderr_dev };
	const __u32 rdev[3] = { ex->stdin_rdev, ex->stdout_rdev, ex->stderr_rdev };
	const __u32 mode[3] = { ex->stdin_mode, ex->stdout_mode, ex->stderr_mode };
	int streams = 1;
	char what[160];
	__u16 nl;
	const __u8 *nm = p15_exec_exe_name(ex, &nl);

	check(c, ex->exe_ino == f->ino && ex->exe_dev == f->dev, "  ... exe ino and dev as stat(2) gives them");
	check(c, ex->exe_nlink == f->nlink && ex->exe_mode == f->mode && ex->exe_uid == f->uid && ex->exe_gid == f->gid,
	      "  ... exe nlink, mode and owner as stat(2) gives them");
	check(c, ex->exe_fs_magic == f->fs_magic, "  ... exe filesystem magic as statfs(2) gives it");
	snprintf(what, sizeof(what), "  ... exe ctime and mtime as stat(2) gives them (record %llu %llu, stat %llu %llu)",
		 (unsigned long long)ex->exe_ctime_ns, (unsigned long long)ex->exe_mtime_ns,
		 (unsigned long long)f->ctime_ns, (unsigned long long)f->mtime_ns);
	check(c, ex->exe_ctime_ns == f->ctime_ns && ex->exe_mtime_ns == f->mtime_ns, what);
	check(c, nl == strlen(f->name) && memcmp(nm, f->name, nl) == 0 && ex->exe_name_full == nl,
	      "  ... exe_name is the basename of the resolved path, not truncated");
	check(c, memcmp(cred, f->cred, sizeof(cred)) == 0, "  ... uid, euid, gid, egid, fsuid, fsgid are the daemon's");
	for (int i = 0; i < 3; i++)
		streams &= ino[i] == f->std_ino[i] && dev[i] == f->std_dev[i] && rdev[i] == f->std_rdev[i] &&
			   mode[i] == f->std_mode[i];
	check(c, streams, "  ... fds 0, 1, 2 are the daemon's (ino, dev, rdev, mode as fstat(2) gives them)");
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
	snprintf(what, sizeof(what), "every record takes exactly its len in the ring (ADR-0017; %zu do not)",
		 l->size_not_len);
	check(&c, l->size_not_len == 0, what);

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
		check(&c, ex->h.version == P15_EXEC_VERSION, "  ... the current EXEC version (v2, ADR-0025)");
		if (ex->h.version == P15_EXEC_VERSION)   /* v2 fields are only read from a v2 record */
			check_exec_facts(&c, ex, &e->exe);
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

int p15_selftest_run_ex(int spine_rb_fd, FILE *log, __u64 *daemon_start_ns, __u64 *consumed)
{
	__u64 before;

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
	ring_buffer__consume(rb);          /* forget records from before the test (counted in *consumed) */
	before = l.n + l.invalid + l.dropped_oom;
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
	rc = p15_selftest_exec_facts(P15_ST_EXE, &e.exe);
	if (rc) {
		fprintf(log, "selftest: cannot stat %s: %s\n", P15_ST_EXE, strerror(-rc));
		ring_buffer__free(rb);
		return rc;
	}

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
		ring_buffer__consume(rb);   /* records don't wake the reader below the high-water mark (ADR-0020) */
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
	if (consumed)                      /* every record this test took from the ring: the run's books need it */
		*consumed = before + l.n + l.invalid + l.dropped_oom;
	if (daemon_start_ns) {
		*daemon_start_ns = 0;
		for (size_t i = 0; i < l.n; i++) {
			const struct p15_hdr *h = l.recs[i];

			if (h->type == P15_T_FORK && h->tgid == e.daemon_tgid &&
			    ((const struct p15_fork *)h)->child_tgid == e.child) {
				*daemon_start_ns = h->start_ns;
				break;
			}
		}
	}
	p15_rec_list_free(&l);
	return failed;
}

int p15_selftest_run(int spine_rb_fd, FILE *log)
{
	return p15_selftest_run_ex(spine_rb_fd, log, NULL, NULL);
}
