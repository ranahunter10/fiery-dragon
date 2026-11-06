// SPDX-License-Identifier: MIT
/*
 * Unit tests for the snapshot's framing and books (daemon/snapshot_frame.c): records split across
 * reads, a record that fails its check, one from another snapshot, a WAL that refuses, a stream
 * that can't be framed, output cut inside a record, and the closing rule of the books.
 * No root, no BPF. Run: make test-c
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "records.h"
#include "snapshot.h"

static int failures;

#define EXPECT(cond, msg) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

/* One PROC record of snapshot 7 (opening) with `path` and `argv`, at out; returns its len. */
static unsigned mk_proc(unsigned char *out, unsigned tgid, const char *path, const char *argv, size_t argv_len)
{
	struct p15_proc *r = (void *)out;      /* the current version (v2) */
	size_t pl = strlen(path);
	unsigned len = (unsigned)((sizeof(*r) + pl + argv_len + 7) & ~(size_t)7);

	memset(out, 0, len);
	r->h.type = P15_T_PROC;
	r->h.version = P15_PROC_VERSION;
	r->h.len = (__u16)len;
	r->h.ts_ns = 1000 + tgid;
	r->h.tgid = r->h.tid = tgid;
	r->h.start_ns = 50 + tgid;
	r->parent_tgid = 1;
	r->parent_start_ns = 3;
	r->snap_id = 7;
	r->kind = P15_SNAP_OPENING;
	memcpy(r->comm, "proc", 4);
	r->exe_path_len = r->exe_path_full = (__u16)pl;
	r->argv_len = r->argv_full = (__u16)argv_len;
	memcpy(out + sizeof(*r), path, pl);
	memcpy(out + sizeof(*r) + pl, argv, argv_len);
	return len;
}

/* the sink: remembers the tgids put, refuses when told to */
static unsigned put_tgids[64], nput;
static int refuse;

static int put(void *ctx, const void *rec, uint32_t len)
{
	const struct p15_hdr *h = rec;

	(void)ctx;
	(void)len;
	if (refuse)
		return -EIO;
	if (nput < 64)
		put_tgids[nput++] = h->tgid;
	return 0;
}

static struct p15_snap_frame f;
static struct p15_snap_done_v1 done;

static void start(void)
{
	memset(&done, 0, sizeof(done));
	nput = 0;
	refuse = 0;
	p15_snap_frame_init(&f, 7, P15_SNAP_OPENING, &done, put, NULL);
}

/* feed `n` bytes of `src` in pieces of `step` bytes, as reads of the iterator would */
static void feed(const unsigned char *src, size_t n, size_t step)
{
	for (size_t o = 0; o < n; o += step) {
		size_t k = n - o < step ? n - o : step;

		memcpy(f.buf + f.have, src + o, k);
		p15_snap_frame_feed(&f, k);
	}
}

static unsigned char stream[8192];

static void test_split_reads(void)
{
	size_t n = 0;

	n += mk_proc(stream + n, 10, "/usr/bin/a", "a\0-x\0", 5);
	n += mk_proc(stream + n, 11, "/usr/bin/bb", "bb\0", 3);
	n += mk_proc(stream + n, 12, "", "", 0);
	for (size_t step = 1; step <= n; step = step * 3 + 1) {
		start();
		feed(stream, n, step);
		p15_snap_frame_end(&f);
		EXPECT(done.entries == 3 && done.invalid == 0 && done.error == 0, "three records, whatever the read size");
		EXPECT(nput == 3 && put_tgids[0] == 10 && put_tgids[2] == 12, "in order");
		EXPECT(f.have == 0, "nothing left over");
	}
}

static void test_invalid_and_foreign(void)
{
	size_t n = 0, second;
	struct p15_proc *r;

	n += mk_proc(stream + n, 20, "/a", "a\0", 2);
	second = n;
	n += mk_proc(stream + n, 21, "/b", "b\0", 2);
	n += mk_proc(stream + n, 22, "/c", "c\0", 2);
	n += mk_proc(stream + n, 23, "/d", "d\0", 2);
	r = (void *)(stream + second);
	r->reserved = 1;                                   /* fails p15_rec_check */
	r = (void *)(stream + second + r->h.len);
	r->snap_id = 6;                                    /* from another snapshot */
	r = (void *)((unsigned char *)r + r->h.len);
	r->kind = P15_SNAP_CLOSING;                        /* the other kind */
	start();
	feed(stream, n, 100);
	p15_snap_frame_end(&f);
	EXPECT(done.entries == 1 && done.invalid == 3, "a bad record, a foreign id and a foreign kind are invalid");
	EXPECT(done.error == 0, "framing held: the invalid ones are counted, the stream goes on");
}

static void test_refused(void)
{
	size_t n = 0;

	n += mk_proc(stream + n, 30, "/a", "", 0);
	n += mk_proc(stream + n, 31, "/b", "", 0);
	start();
	refuse = 1;
	feed(stream, n, n);
	p15_snap_frame_end(&f);
	EXPECT(done.unwritten == 2 && done.entries == 0, "records the sink refuses are unwritten");
}

static void test_framing_lost(void)
{
	size_t n = 0;
	struct p15_hdr *h;

	n += mk_proc(stream + n, 40, "/a", "", 0);
	h = (void *)(stream + n);
	n += mk_proc(stream + n, 41, "/b", "", 0);
	n += mk_proc(stream + n, 42, "/c", "", 0);
	h->len = 12;                                       /* can't be a record: no way to find the next */
	start();
	feed(stream, n, 64);
	p15_snap_frame_end(&f);
	EXPECT(done.entries == 1 && done.invalid == 1 && done.error == -EPROTO, "framing lost: one invalid, then stop");
	EXPECT(f.lost == 1, "the rest is not read");
}

static void test_cut_short(void)
{
	size_t n = mk_proc(stream, 50, "/a", "abc\0", 4);

	start();
	feed(stream, n - 8, 16);
	p15_snap_frame_end(&f);
	EXPECT(done.entries == 0 && done.invalid == 1 && done.error == -EPROTO, "output ending inside a record");
}

static void test_books(void)
{
	struct p15_snap_done_v1 d;
	struct p15_snap_books b = { .tasks = 90, .threads = 22, .emitted = 68, .kthreads = 59, .truncated = 2 };
	char why[200];

	memset(&d, 0, sizeof(d));
	p15_snap_books_fill(&d, &b);
	d.entries = 68;
	EXPECT(p15_snap_books_close(&d, why, sizeof(why)) == 0, "closing books");
	EXPECT(d.kthreads == 59 && d.truncated == 2 && d.threads == 22, "books copied");
	d.tasks = 91;
	EXPECT(p15_snap_books_close(&d, why, sizeof(why)) && strstr(why, "tasks 91"), "a task the books don't explain");
	d.tasks = 90;
	d.entries = 67;
	EXPECT(p15_snap_books_close(&d, why, sizeof(why)) && strstr(why, "emitted 68"), "a record p15d didn't account for");
	d.entries = 66;
	d.invalid = 2;
	EXPECT(p15_snap_books_close(&d, why, sizeof(why)) && strstr(why, "2 invalid"), "closing books with invalid ones still fail");
	d.invalid = 0;
	d.entries = 68;
	d.error = -EIO;
	EXPECT(p15_snap_books_close(&d, why, sizeof(why)) && strstr(why, "failed"), "a read error fails the snapshot");
	d.error = 0;
	d.tasks = 91;
	d.write_failed = 1;
	EXPECT(p15_snap_books_close(&d, why, sizeof(why)) && strstr(why, "1 not written"), "a write the program lost");
}

static void test_records(void)
{
	static unsigned char rec[2048];
	unsigned len = mk_proc(rec, 60, "/usr/bin/x", "x\0-y\0", 5);
	struct p15_proc *r = (void *)rec;
	const char *why;
	char line[1700];

	EXPECT(p15_rec_check(rec, len, &why) == 0, "a PROC record checks");
	p15_rec_format(rec, line, sizeof(line));
	EXPECT(strstr(line, "path=\"/usr/bin/x\"") && strstr(line, "argv=\"x -y \"") && strstr(line, "snap=7/opening"),
	       "PROC formats its path, argv and snapshot");
	rec[len - 1] = 1;
	EXPECT(p15_rec_check(rec, len, &why) != 0, "a non-zero pad byte is refused");
	rec[len - 1] = 0;
	r->kind = 3;
	EXPECT(p15_rec_check(rec, len, &why) != 0, "an unknown kind is refused");
	r->kind = 1;
	r->pflags = 4;
	EXPECT(p15_rec_check(rec, len, &why) != 0, "unknown pflags are refused");
	r->pflags = 0;
	r->h.len = (__u16)(len + 8);
	EXPECT(p15_rec_check(rec, len + 8, &why) != 0, "len larger than the fields need is refused");
	r->h.len = (__u16)len;
	r->argv_len = 2000;
	EXPECT(p15_rec_check(rec, len, &why) != 0, "argv_len beyond its maximum is refused");
	/* above the maximum, though len, tiling and padding would all agree */
	r->exe_path_len = 0;
	r->argv_len = P15_PROC_V1_ARGV_MAX + 1;
	r->h.len = (__u16)((sizeof(*r) + r->argv_len + 7) & ~7u);
	memset(rec + sizeof(*r), 'a', r->argv_len);
	memset(rec + sizeof(*r) + r->argv_len, 0, r->h.len - sizeof(*r) - r->argv_len);
	EXPECT(p15_rec_check(rec, r->h.len, &why) != 0, "argv_len above its maximum refused even when it tiles exactly");
	r->exe_path_len = P15_PROC_V1_EXE_PATH_MAX + 1;
	r->argv_len = 0;
	r->h.len = (__u16)((sizeof(*r) + r->exe_path_len + 7) & ~7u);
	memset(rec + sizeof(*r) + r->exe_path_len, 0, r->h.len - sizeof(*r) - r->exe_path_len);
	EXPECT(p15_rec_check(rec, r->h.len, &why) != 0, "exe_path_len above its maximum refused even when it tiles exactly");
}

int main(void)
{
	test_split_reads();
	test_invalid_and_foreign();
	test_refused();
	test_framing_lost();
	test_cut_short();
	test_books();
	test_records();
	printf("%s: %d failures\n", __FILE__, failures);
	return failures != 0;
}
