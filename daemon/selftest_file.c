// SPDX-License-Identifier: MIT
/* The file-identity self-test (ADR-0015 confirmation 1). See selftest_file.h. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "p15_records.h"
#include "records.h"
#include "selftest_file.h"

#define MAXR 32
#define SELFTEST_TRIES 5

struct coll {
	unsigned char r[MAXR][P15_OPEN_MAX_SIZE];   /* this process's file records, as received */
	int n, other, invalid, overflow;
	unsigned me;
	unsigned long long file, net;               /* records taken from the ring, by books */
};

static struct coll c;   /* 135 KiB: not on the stack */

static int on_rec(void *ctx, void *data, size_t size)
{
	const struct p15_hdr *h = data;
	const char *why;

	(void)ctx;
	if (!p15_is_file_type(h->type)) {
		c.net++;                    /* NET records of the shared ring: on the NET books */
		return 0;
	}
	c.file++;
	if (p15_rec_check(data, size, &why)) {
		c.invalid++;
		return 0;
	}
	if (h->tgid != c.me) {
		c.other++;                  /* someone else's opens during the test: ignored */
		return 0;
	}
	if (c.n < MAXR)
		memcpy(c.r[c.n++], data, h->len);
	else
		c.overflow++;
	return 0;
}

static int check(FILE *log, int ok, const char *what)
{
	fprintf(log, "  %-4s file: %s\n", ok ? "ok" : "FAIL", what);
	return !ok;
}

static const struct p15_open *open_rec(int i)
{
	const struct p15_hdr *h = (const void *)c.r[i];

	return h->type == P15_T_OPEN ? (const void *)h : NULL;
}

static const char *path_of(const struct p15_open *r, unsigned *len)
{
	*len = r->path_len;
	return (const char *)(r + 1) + r->facts_len;
}

/* The n-th OPEN whose path is p, or (p == NULL) the n-th OPEN with an empty path and obj. */
static const struct p15_open *find_open(const char *p, __u64 obj, int nth)
{
	for (int i = 0; i < c.n; i++) {
		const struct p15_open *r = open_rec(i);
		unsigned len;
		const char *rp;

		if (!r)
			continue;
		rp = path_of(r, &len);
		if (p ? (len == strlen(p) && !memcmp(rp, p, len)) : (len == 0 && r->obj == obj))
			if (nth-- == 0)
				return r;
	}
	return NULL;
}

static const struct p15_close *find_close(__u64 fid)
{
	for (int i = 0; i < c.n; i++) {
		const struct p15_close *r = (const void *)c.r[i];

		if (r->h.type == P15_T_CLOSE && r->fid == fid)
			return r;
	}
	return NULL;
}

static int facts_match(const struct p15_open *r, const struct stat *st, const struct statfs *sf)
{
	const struct p15_part_objfacts *f = (const void *)(r + 1);

	return r->facts_len == sizeof(*f) && f->ino == st->st_ino && (f->dev >> 20) == major(st->st_dev) &&
	       (f->dev & 0xfffff) == minor(st->st_dev) && f->mode == st->st_mode && f->nlink == st->st_nlink &&
	       f->fs_magic == (__u32)sf->f_type && f->seen == 1;
}

/* Poll until the CLOSE of `fid` arrived (the last record the test waits for) or 2 s passed. */
static void wait_close(struct ring_buffer *rb, __u64 fid)
{
	for (int i = 0; i < 100 && !(fid && find_close(fid)); i++) {
		ring_buffer__poll(rb, 20);
		ring_buffer__consume(rb);   /* records don't wake the reader below the high-water mark (ADR-0020) */
		if (!fid)
			break;
	}
}

int p15_selftest_file(int bulk_rb_fd, int no_path_fentry, FILE *log, unsigned long long *file_consumed,
		      unsigned long long *net_consumed)
{
	char dir[] = "/tmp/p15d-selftest-XXXXXX", rdir[PATH_MAX], f1[PATH_MAX + 8], fifo[PATH_MAX + 8];
	const struct p15_open *a, *b, *q;
	struct ring_buffer *rb;
	struct stat st;
	struct statfs sf;
	int fd = -1, failed = 0, rc = 0, made = 0, fifo_made = 0, try = 0, skipped;

	memset(&c, 0, sizeof(c));
	c.me = (unsigned)getpid();
	rb = ring_buffer__new(bulk_rb_fd, on_rec, NULL, NULL);
	if (!rb)
		return -errno;
	ring_buffer__consume(rb);           /* records from before the test: on the books, not examined */
	c.n = c.other = c.invalid = c.overflow = 0;
	if (!mkdtemp(dir) || !realpath(dir, rdir)) {
		rc = -errno;
		goto out;
	}
	made = 1;
again:
	snprintf(f1, sizeof(f1), "%s/f1-%d", rdir, try);
	snprintf(fifo, sizeof(fifo), "%s/fifo-%d", rdir, try);
	fd = open(f1, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	if (fd < 0 || write(fd, "p15d\n", 5) != 5) {
		rc = -errno;
		goto out;
	}
	close(fd);
	fd = open(f1, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) || fstatfs(fd, &sf)) {
		rc = -errno;
		goto out;
	}
	close(fd);
	fd = -1;
	if (mkfifo(fifo, 0600)) {
		rc = -errno;
		goto out;
	}
	fifo_made = 1;
	fd = open(fifo, O_WRONLY | O_NONBLOCK | O_CLOEXEC);   /* no reader: ->open fails with ENXIO (K1, K2) */
	if (fd >= 0 || errno != ENXIO) {
		rc = fd >= 0 ? -EEXIST : -errno;
		goto out;
	}
	fd = -1;
	ring_buffer__consume(rb);
	if (no_path_fentry) {
		/* every open is written by the session return with the walked path (ADR-0029 confirmation 2) */
		q = find_open(fifo, 0, 0);
		wait_close(rb, q ? q->fid : 0);
		a = find_open(f1, 0, 0);
		b = find_open(f1, 0, 1);
		q = find_open(fifo, 0, 0);
		fprintf(log, "selftest file (no path fentry): %d own records, %d of other processes, %d invalid\n", c.n,
			c.other, c.invalid);
		failed += check(log, c.invalid == 0 && c.overflow == 0, "every record passes the checks");
		failed += check(log, a && (a->fflags & P15_FF_PATH_WALKED) && !(a->fflags & P15_FF_PATH_RACED) &&
				     !(a->h.flags & P15_F_TRUNCATED) && a->verdict == 0 && (a->fflags & P15_FF_OBJ_NEW) &&
				     facts_match(a, &st, &sf) && (a->f_flags & O_ACCMODE) == O_WRONLY,
				"the create is an OPEN with PATH_WALKED and its whole path, verdict 0, the facts of fstat");
		failed += check(log, a && b && (b->fflags & P15_FF_PATH_WALKED) && !(b->fflags & P15_FF_OBJ_NEW) &&
				     b->obj == a->obj && b->fid != a->fid,
				"the reopen too: walked, the same object without its facts again, its own open-file id");
		failed += check(log, q && (q->fflags & P15_FF_PATH_WALKED) && find_close(q->fid) &&
				     (find_close(q->fid)->fflags & P15_FF_NEVER_OPENED),
				"the FIFO: walked, and its CLOSE is NEVER_OPENED");
		wait_close(rb, a ? a->fid : 0);
		failed += check(log, a && find_close(a->fid) && find_close(a->fid)->obj == a->obj,
				"the create's CLOSE names its object: the return filled in what the session's entry left (E-0190)");
		goto out;
	}
	/* The fentry is preemptible: when another task is preempted inside it on this CPU, the kernel
	 * skips it for us (ADR-0020) and the session return writes our open, walked (ADR-0029). That is
	 * the design working, not a failure: try again, up to SELFTEST_TRIES times. If every try was
	 * skipped (a machine opening files flat out while p15d starts), the fallback record itself is
	 * checked instead, so a busy host does not stop the daemon from starting. */
	skipped = 0;
	for (int i = 0; i < c.n; i++)
		if (open_rec(i) && (open_rec(i)->fflags & (P15_FF_PATH_MISSING | P15_FF_PATH_WALKED)))
			skipped++;
	if (skipped && try + 1 < SELFTEST_TRIES) {
		fprintf(log, "selftest file: try %d: the kernel skipped the path fentry for %d of our opens; again\n", try, skipped);
		ring_buffer__poll(rb, 20);
		ring_buffer__consume(rb);
		unlink(f1);
		unlink(fifo);
		fifo_made = 0;
		c.n = c.other = 0;
		try++;
		goto again;
	}
	if (skipped) {
		a = NULL;
		for (int i = 0; i < c.n; i++)
			if ((q = open_rec(i)) && (q->fflags & P15_FF_PATH_WALKED) && q->verdict == 0)
				a = q;
		fprintf(log, "selftest file: the path fentry was skipped on all %d tries; checking the fallback record\n",
			SELFTEST_TRIES);
		failed += check(log, c.invalid == 0 && c.overflow == 0, "every record passes the checks");
		failed += check(log, a != NULL, "a skipped open is written by the session return with PATH_WALKED, verdict 0");
		goto out;
	}
	a = find_open(f1, 0, 0);
	b = find_open(f1, 0, 1);
	q = find_open(fifo, 0, 0);
	wait_close(rb, q ? q->fid : 0);
	fprintf(log, "selftest file: %s; %d own records, %d of other processes, %d invalid\n", f1, c.n, c.other, c.invalid);
	failed += check(log, c.invalid == 0 && c.overflow == 0, "every record passes the checks");
	if (!a || !b || !q) {
		failed += check(log, 0, "an OPEN with its path for the create, the reopen and the FIFO");
		goto out;
	}
	failed += check(log, (a->fflags & P15_FF_OBJ_NEW) && facts_match(a, &st, &sf),
			"the create's OPEN carries the object's facts, equal to fstat and fstatfs");
	failed += check(log, !(a->fflags & (P15_FF_PATH_MISSING | P15_FF_FULL_SIZE | P15_FF_PATH_ERROR)) &&
			     !(a->h.flags & P15_F_TRUNCATED) && (a->f_flags & O_ACCMODE) == O_WRONLY,
			"written by the fentry with the full path; f_flags O_WRONLY");
	failed += check(log, b->obj == a->obj && b->fid != a->fid && !(b->fflags & P15_FF_OBJ_NEW) &&
			     (b->f_flags & O_ACCMODE) == O_RDONLY,
			"the reopen: the same object without its facts again, its own open-file id, O_RDONLY");
	failed += check(log, find_close(a->fid) && !(find_close(a->fid)->fflags & P15_FF_NEVER_OPENED) &&
			     find_close(b->fid) && find_close(a->fid)->obj == a->obj,
			"a CLOSE for each open file, opened");
	failed += check(log, find_close(q->fid) && (find_close(q->fid)->fflags & P15_FF_NEVER_OPENED),
			"the FIFO open that failed in ->open ends with CLOSE NEVER_OPENED");
	failed += check(log, a->h.tgid == c.me && a->h.start_ns && a->h.start_ns == q->h.start_ns,
			"every record names this process (ADR-0009)");
out:
	if (fd >= 0)
		close(fd);
	if (fifo_made)
		unlink(fifo);
	if (made) {
		unlink(f1);
		rmdir(dir);
	}
	ring_buffer__consume(rb);
	ring_buffer__free(rb);
	*file_consumed = c.file;
	*net_consumed = c.net;
	return rc ? rc : failed;
}
