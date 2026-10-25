// SPDX-License-Identifier: MIT
/*
 * Unit tests for the P15W writer, batch builder, scanner and recovery
 * (docs/formats/p15w-v1.md). No root. Time comes from a fake clock, so
 * rotation and syncing are tested exactly. Run: make test-c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crc32c.h"
#include "wal.h"

static int failures;

#define EXPECT(cond, msg) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

/* ---- fake clock: every clock reads the same settable value ---- */

static unsigned long long fake_ns = 1000000000000ull;

static int fake_clock(clockid_t id, struct timespec *ts)
{
	(void)id;
	ts->tv_sec = fake_ns / 1000000000ull;
	ts->tv_nsec = fake_ns % 1000000000ull;
	return 0;
}

/* ---- helpers ---- */

static char *tmpdir(void)
{
	char tmpl[] = "/tmp/p15w-test-XXXXXX";
	char *d = mkdtemp(tmpl);

	return d ? strdup(d) : NULL;
}

static void rmtree(const char *d)
{
	char cmd[512];

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", d);
	if (system(cmd))
		printf("warn: could not remove %s\n", d);
}

/* One synthetic ADR-0008 record of `len` bytes; the bytes after the header carry `tag`. */
static void mkrec(unsigned char *p, unsigned len, unsigned char tag)
{
	memset(p, tag, len);
	p[0] = 1; p[1] = 0;                  /* type 1 */
	p[2] = 1; p[3] = 0;                  /* version 1 */
	p[4] = len & 0xFF; p[5] = len >> 8;  /* len */
}

static unsigned char *slurp(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	unsigned char *buf;
	long sz;

	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	rewind(f);
	buf = malloc(sz ? sz : 1);
	if (fread(buf, 1, sz, f) != (size_t)sz) {
		free(buf);
		buf = NULL;
	}
	fclose(f);
	*n = sz;
	return buf;
}

static void spit(const char *path, const unsigned char *b, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f || fwrite(b, 1, n, f) != n)
		printf("warn: write %s\n", path);
	if (f)
		fclose(f);
}

static char *segpath(const char *dir, unsigned i)
{
	static char p[512];

	snprintf(p, sizeof(p), "%s/seg-%08u.p15w", dir, i);
	return p;
}

static const struct p15w_kv META[] = { { "run.id", "test-run" }, { "boot-id", "0123-abcd" } };

static struct p15w *open_w(const char *dir, unsigned long long max_bytes, unsigned long long max_ns,
			   unsigned long long sync_ns, p15w_open_fn on_open)
{
	struct p15w_opts o = { .dir = dir, .max_bytes = max_bytes, .max_ns = max_ns, .sync_ns = sync_ns,
			       .meta = META, .nmeta = 2, .on_open = on_open, .clock = fake_clock };
	struct p15w *w;
	int rc = p15w_open(&w, &o);

	EXPECT(rc == 0 && w, "p15w_open");
	return w;
}

/* Append `n` records of `len` bytes as one batch. */
static int put(struct p15w *w, unsigned ring, unsigned n, unsigned len, unsigned char tag)
{
	unsigned char buf[8192];

	for (unsigned i = 0; i < n; i++)
		mkrec(buf + i * len, len, tag);
	return p15w_append(w, ring, n, buf, n * len);
}

static unsigned header_len_with_fake_clock(void)
{
	char *d = tmpdir();
	struct p15w *w = open_w(d, 0, 0, 0, NULL);
	unsigned hl = p15w_stats(w)->file_bytes;

	p15w_close(w);
	rmtree(d);
	free(d);
	return hl;
}

/* ---- tests ---- */

static void test_crc32c(void)
{
	unsigned char z[32] = { 0 }, f[32], inc[32];

	memset(f, 0xFF, sizeof(f));
	for (int i = 0; i < 32; i++)
		inc[i] = i;
	EXPECT(p15_crc32c(0, "123456789", 9) == 0xE3069283, "CRC32C check value");
	EXPECT(p15_crc32c(0, "", 0) == 0, "CRC32C of nothing");
	/* RFC 3720 B.4 */
	EXPECT(p15_crc32c(0, z, 32) == 0x8A9136AA, "RFC 3720: 32 zero bytes");
	EXPECT(p15_crc32c(0, f, 32) == 0x62A8AB43, "RFC 3720: 32 0xFF bytes");
	EXPECT(p15_crc32c(0, inc, 32) == 0x46DD794E, "RFC 3720: 0..31");
	EXPECT(p15_crc32c(p15_crc32c(0, "1234", 4), "56789", 5) == 0xE3069283, "CRC32C in pieces");
}

/* Writes the reference segment used by several tests; returns the offset of its last batch. */
static size_t write_reference(const char *dir)
{
	struct p15w *w = open_w(dir, 0, 0, 0, NULL);
	const struct p15w_stats *st = p15w_stats(w);
	size_t last;

	EXPECT(put(w, P15W_RING_SPINE, 2, 64, 0xA1) == 0, "spine batch");
	EXPECT(put(w, P15W_RING_BULK, 1, 40, 0xB1) == 0, "bulk batch");
	EXPECT(put(w, P15W_RING_DAEMON, 1, 32, 0xD1) == 0, "daemon batch");
	last = st->file_bytes;
	EXPECT(put(w, P15W_RING_SPINE, 3, 48, 0xA2) == 0, "second spine batch");
	EXPECT(st->batches == 4 && st->records == 7, "stats: batches and records");
	EXPECT(st->next_seq[0] == 5 && st->next_seq[1] == 1 && st->next_seq[2] == 1, "stats: sequences");
	EXPECT(p15w_close(w) == 0, "close");
	return last;
}

static void test_round_trip(void)
{
	char *d = tmpdir(), v[64];
	size_t n, last = write_reference(d);
	unsigned char *b = slurp(segpath(d, 0), &n);
	struct p15w_scan s;

	EXPECT(b != NULL, "segment 0 exists");
	EXPECT(p15w_scan_buf(b, n, &s) == 0, "scan header");
	EXPECT(s.stop == NULL && s.good_end == n, "valid to the end");
	EXPECT(s.batches == 4 && s.records == 7 && s.segment_index == 0, "scan counts");
	EXPECT(s.next_seq[0] == 5 && s.next_seq[1] == 1 && s.next_seq[2] == 1, "scan sequences");
	EXPECT(p15w_header_get(b, n, "run.id", v, sizeof(v)) == 0 && !strcmp(v, "test-run"), "caller metadata");
	EXPECT(p15w_header_get(b, n, "boot-id", v, sizeof(v)) == 0 && !strcmp(v, "0123-abcd"), "caller metadata 2");
	EXPECT(p15w_header_get(b, n, "seq.next.spine", v, sizeof(v)) == 0 && !strcmp(v, "0"), "seq.next in header");
	EXPECT(p15w_header_get(b, n, "clock.boottime_ns", v, sizeof(v)) == 0 && !strcmp(v, "1000000000000"), "clock anchor");
	EXPECT(p15w_header_get(b, n, "clock.read_spread_ns", v, sizeof(v)) == 0 && !strcmp(v, "0"), "clock spread");
	EXPECT(p15w_header_get(b, n, "rotate.max_bytes", v, sizeof(v)) == 0 && !strcmp(v, "67108864"), "default size");
	EXPECT(p15w_header_get(b, n, "rotate.max_ms", v, sizeof(v)) == 0 && !strcmp(v, "60000"), "default age");
	EXPECT(p15w_header_get(b, n, "sync.interval_ms", v, sizeof(v)) == 0 && !strcmp(v, "1000"), "default sync");
	EXPECT(p15w_header_get(b, n, "nope", v, sizeof(v)) == -ENOENT, "missing key");
	EXPECT(p15w_header_get(b, n, "run.id", v, 4) == -ENOSPC, "value too long for buffer");
	/* the last batch: header fields and the records' bytes as given */
	EXPECT(!memcmp(b + last, "P15B", 4) && b[last + 4] == 0 && b[last + 8] == 3, "last batch: ring 0, count 3");
	EXPECT(b[last + 16] == 2, "last batch: first_seq 2");
	EXPECT(b[last + 40 + 4] == 48 && b[last + 40 + 8] == 0xA2 && b[last + 40 + 143] == 0xA2, "payload bytes");
	EXPECT(last + 40 + 144 == n, "last batch ends the file");
	free(b);
	rmtree(d);
	free(d);
}

static void test_torn_tail_at_every_offset(void)
{
	char *d = tmpdir(), path[600];
	size_t n, last = write_reference(d), m;
	unsigned char *b = slurp(segpath(d, 0), &n), *c;
	struct p15w_scan s;
	int bad_scan = 0, bad_recover = 0;

	snprintf(path, sizeof(path), "%s/cut.p15w", d);
	for (size_t cut = last; cut <= n; cut++) {
		uint64_t gone;
		const char *why;

		p15w_scan_buf(b, cut, &s);
		if (cut == last || cut == n)
			bad_scan += !(s.stop == NULL && s.good_end == cut);
		else
			bad_scan += !(s.stop && s.torn && s.good_end == last);
		spit(path, b, cut);
		if (p15w_recover(path, &gone, &why) != 0) {
			bad_recover++;
			continue;
		}
		c = slurp(path, &m);
		bad_recover += !(m == (cut == n ? n : last) && gone == cut - m);
		p15w_scan_buf(c, m, &s);
		bad_recover += !(s.stop == NULL);
		free(c);
	}
	EXPECT(bad_scan == 0, "every cut inside the last batch is a torn tail ending at the previous batch");
	EXPECT(bad_recover == 0, "recovery truncates exactly the torn bytes and leaves a clean segment");
	free(b);
	rmtree(d);
	free(d);
}

static void forge_hdr_crc(unsigned char *h)
{
	uint32_t c = p15_crc32c(0, h, 32);

	memcpy(h + 32, &c, 4);
}

static void forge_payload_crc(unsigned char *h)
{
	uint32_t len, c;

	memcpy(&len, h + 12, 4);
	c = p15_crc32c(0, h + 40, len);
	memcpy(h + 24, &c, 4);
	forge_hdr_crc(h);
}

static void test_corruption_is_not_a_torn_tail(void)
{
	char *d = tmpdir(), path[600];
	size_t n;
	unsigned char *b, *c;
	struct p15w_scan s;
	uint64_t gone;
	const char *why;
	unsigned hl;

	write_reference(d);
	b = slurp(segpath(d, 0), &n);
	p15w_scan_buf(b, n, &s);
	hl = s.header_len;
	snprintf(path, sizeof(path), "%s/bad.p15w", d);

	c = malloc(n + 4096);
	memcpy(c, b, n);
	c[hl + 40 + 10] ^= 1;                       /* first batch's payload */
	p15w_scan_buf(c, n, &s);
	EXPECT(s.stop && !strcmp(s.stop, "payload crc") && !s.torn && s.good_end == hl, "payload flip: corruption");
	spit(path, c, n);
	EXPECT(p15w_recover(path, &gone, &why) == -EUCLEAN && gone == 0, "corruption is never truncated");
	free(c);
	c = slurp(path, &n);
	EXPECT(n == s.file_size, "file untouched after refused recovery");
	free(c);

	c = malloc(n + 4096);
	memcpy(c, b, n);
	c[hl + 8] ^= 1;                             /* first batch's header */
	p15w_scan_buf(c, n, &s);
	EXPECT(s.stop && !strcmp(s.stop, "batch header crc") && !s.torn, "batch header flip");

	memcpy(c, b, n);
	c[40] ^= 1;                                 /* segment header metadata */
	EXPECT(p15w_scan_buf(c, n, &s) == -EBADMSG && !strcmp(s.stop, "header crc"), "segment header flip");

	memcpy(c, b, n);
	c[hl + 40 + 4] = 40;                        /* a record len that does not tile, CRCs fixed up */
	forge_payload_crc(c + hl);
	p15w_scan_buf(c, n, &s);
	EXPECT(s.stop && !strcmp(s.stop, "records do not tile the payload") && !s.torn, "tiling");

	memcpy(c, b, n);
	{
		size_t second_spine = hl + 40 + 128 + 40 + 40 + 40 + 32;
		c[second_spine + 16] = 3;               /* first_seq 2 -> 3 */
		forge_hdr_crc(c + second_spine);
		p15w_scan_buf(c, n, &s);
		EXPECT(s.stop && !strcmp(s.stop, "sequence gap") && !s.torn && s.good_end == second_spine, "sequence gap");
	}

	memcpy(c, b, n);
	memset(c + n, 0, 4096);                     /* a zero-filled tail */
	p15w_scan_buf(c, n + 4096, &s);
	EXPECT(s.stop && !strcmp(s.stop, "batch magic") && s.torn && s.good_end == n, "zero tail is torn");
	spit(path, c, n + 4096);
	EXPECT(p15w_recover(path, &gone, &why) == 0 && gone == 4096, "zero tail cut");

	spit(path, b, 20);                          /* cut inside the segment header */
	EXPECT(p15w_recover(path, &gone, &why) == -EUCLEAN && !strcmp(why, "header incomplete"), "torn header refused");
	free(c);
	free(b);
	rmtree(d);
	free(d);
}

static void test_rotation_by_size(void)
{
	unsigned hl = header_len_with_fake_clock();
	char *d = tmpdir();
	struct p15w *w = open_w(d, hl + 3 * 136, 0, 0, NULL);
	const struct p15w_stats *st = p15w_stats(w);
	unsigned long long seq = 0;
	int bad = 0;

	for (int i = 0; i < 30; i++)
		EXPECT(put(w, P15W_RING_SPINE, 1, 96, i) == 0, "append");
	EXPECT(st->segments == 10 && st->rotations_size == 9 && st->oversize_batches == 0, "3 batches per segment");
	EXPECT(p15w_close(w) == 0, "close");
	for (unsigned i = 0; i < 10; i++) {
		size_t n;
		unsigned char *b = slurp(segpath(d, i), &n);
		struct p15w_scan s;
		char v[32];

		if (!b) {
			bad++;
			continue;
		}
		p15w_scan_buf(b, n, &s);
		p15w_header_get(b, n, "seq.next.spine", v, sizeof(v));
		bad += !(s.stop == NULL && s.segment_index == i && s.batches == 3 && n <= hl + 3 * 136);
		bad += strtoull(v, NULL, 10) != seq;
		seq += s.records;
		free(b);
	}
	EXPECT(bad == 0, "every segment clean, numbered, within size, sequences continue across segments");
	EXPECT(access(segpath(d, 10), F_OK) != 0, "no eleventh segment");
	rmtree(d);
	free(d);
}

static void test_oversize_batch(void)
{
	unsigned hl = header_len_with_fake_clock();
	char *d = tmpdir();
	struct p15w *w = open_w(d, hl + 100, 0, 0, NULL);
	const struct p15w_stats *st = p15w_stats(w);

	EXPECT(put(w, P15W_RING_BULK, 8, 64, 1) == 0, "oversize batch accepted");
	EXPECT(st->segments == 1 && st->oversize_batches == 1, "alone in segment 0, counted");
	EXPECT(put(w, P15W_RING_BULK, 1, 32, 2) == 0, "next batch");
	EXPECT(st->segments == 2 && st->rotations_size == 1, "next batch rotates");
	p15w_close(w);
	rmtree(d);
	free(d);
}

static void test_rotation_by_time_and_sync(void)
{
	char *d = tmpdir();
	unsigned long long t0 = fake_ns;
	struct p15w *w = open_w(d, 0, 10000000000ull, 1000000000ull, NULL);
	const struct p15w_stats *st = p15w_stats(w);

	fake_ns = t0 + 500000000ull;
	p15w_tick(w);
	EXPECT(st->fsyncs == 0, "no sync before the interval");
	fake_ns = t0 + 1000000000ull;
	p15w_tick(w);
	EXPECT(st->fsyncs == 1, "sync at the interval (header written)");
	fake_ns = t0 + 3000000000ull;
	p15w_tick(w);
	EXPECT(st->fsyncs == 1, "no sync when nothing was written");
	put(w, P15W_RING_SPINE, 1, 32, 1);
	fake_ns = t0 + 3500000000ull;
	p15w_tick(w);
	EXPECT(st->fsyncs == 2, "sync after a write, interval passed");
	put(w, P15W_RING_SPINE, 1, 32, 2);
	fake_ns = t0 + 4000000000ull;
	p15w_tick(w);
	EXPECT(st->fsyncs == 2, "the interval counts from the last sync");
	fake_ns = t0 + 9999999999ull;
	p15w_tick(w);
	EXPECT(st->segments == 1, "no rotation before the age");
	EXPECT(st->fsyncs == 3, "the write at +4 s is synced by that tick");
	fake_ns = t0 + 10000000000ull;
	p15w_tick(w);
	EXPECT(st->segments == 2 && st->rotations_time == 1 && st->fsyncs == 4, "rotation by age syncs the old one");
	fake_ns = t0 + 40000000000ull;
	p15w_tick(w);
	EXPECT(st->segments == 2, "an empty segment is not rotated by age");
	EXPECT(p15w_segment_index(w) == 1, "writing segment 1");
	EXPECT(p15w_close(w) == 0, "close");
	fake_ns = t0;
	rmtree(d);
	free(d);
}

static int snapshot_calls;

static int fake_snapshot(struct p15w *w, void *ctx)
{
	(void)ctx;
	snapshot_calls++;
	return put(w, P15W_RING_DAEMON, 2, 64, 0x55);
}

static int fake_snapshot_two(struct p15w *w, void *ctx)
{
	(void)ctx;
	return put(w, P15W_RING_DAEMON, 2, 64, 0x55) || put(w, P15W_RING_DAEMON, 2, 64, 0x56);
}

static void test_on_open_writes_first(void)
{
	unsigned hl = header_len_with_fake_clock();
	char *d = tmpdir();
	struct p15w *w;
	int bad = 0;

	snapshot_calls = 0;
	w = open_w(d, hl + 168 + 40 + 64, 0, 0, fake_snapshot);
	for (int i = 0; i < 4; i++)
		put(w, P15W_RING_SPINE, 1, 64, i);
	p15w_close(w);
	EXPECT(snapshot_calls == 4, "the callback runs once per segment");
	for (unsigned i = 0; i < 4; i++) {
		size_t n;
		unsigned char *b = slurp(segpath(d, i), &n);
		struct p15w_scan s;

		p15w_scan_buf(b, n, &s);
		bad += !(s.stop == NULL && b[s.header_len + 4] == P15W_RING_DAEMON && s.batches == 2);
		free(b);
	}
	EXPECT(bad == 0, "each segment starts with the callback's batch");

	/* a snapshot larger than max_bytes stays in its segment instead of rotating forever */
	{
		char *e = tmpdir();
		struct p15w *x = open_w(e, hl + 10, 0, 0, fake_snapshot_two);

		EXPECT(x && p15w_stats(x)->segments == 1 && p15w_stats(x)->oversize_batches == 2, "no rotation inside on_open");
		p15w_close(x);
		rmtree(e);
		free(e);
	}
	rmtree(d);
	free(d);
}

static void test_io_error_fails_the_writer(void)
{
	char *d = tmpdir();
	struct p15w *w = open_w(d, 0, 0, 0, NULL);
	int full = open("/dev/full", O_WRONLY);

	if (full < 0) {
		printf("skip: no /dev/full\n");
	} else {
		dup2(full, p15w_fd(w));
		close(full);
		EXPECT(put(w, P15W_RING_SPINE, 1, 32, 1) == -ENOSPC, "write error returned");
		EXPECT(p15w_stats(w)->errors == 1 && p15w_stats(w)->batches == 0, "counted, not written");
		EXPECT(put(w, P15W_RING_SPINE, 1, 32, 1) == -EIO, "failed writer refuses appends");
		EXPECT(p15w_tick(w) == -EIO, "and ticks");
		EXPECT(p15w_stats(w)->next_seq[0] == 0, "no sequence numbers spent");
	}
	EXPECT(p15w_close(w) == (full < 0 ? 0 : -ENOSPC), "close reports the first error");
	rmtree(d);
	free(d);
}

/* Write at most 7 bytes per call, and fail the very first call with EINTR. */
static int writev_calls;

static ssize_t trickle_writev(int fd, const struct iovec *iov, int n)
{
	struct iovec one;

	(void)n;
	if (writev_calls++ == 0) {
		errno = EINTR;
		return -1;
	}
	one.iov_base = iov[0].iov_base;
	one.iov_len = iov[0].iov_len < 7 ? iov[0].iov_len : 7;
	return writev(fd, &one, 1);
}

static void test_short_writes_and_eintr(void)
{
	char *d = tmpdir();
	struct p15w_opts o = { .dir = d, .clock = fake_clock, .writev = trickle_writev };
	struct p15w *w;
	size_t n;
	unsigned char *b;
	struct p15w_scan s;

	writev_calls = 0;
	EXPECT(p15w_open(&w, &o) == 0, "open through a trickling writev");
	EXPECT(put(w, P15W_RING_SPINE, 3, 64, 7) == 0, "append through a trickling writev");
	EXPECT(p15w_stats(w)->short_writes > 30 && p15w_stats(w)->errors == 0, "short writes counted, not errors");
	p15w_close(w);
	b = slurp(segpath(d, 0), &n);
	p15w_scan_buf(b, n, &s);
	EXPECT(s.stop == NULL && s.records == 3 && b[n - 1] == 7, "the segment is intact");
	free(b);
	rmtree(d);
	free(d);
}

static void test_bad_batches_rejected(void)
{
	char *d = tmpdir();
	struct p15w *w = open_w(d, 0, 0, 0, NULL);
	unsigned char r[128];

	mkrec(r, 64, 1);
	EXPECT(p15w_append(w, 3, 1, r, 64) == -EINVAL, "unknown ring");
	EXPECT(p15w_append(w, 0, 0, r, 64) == -EINVAL, "zero records");
	EXPECT(p15w_append(w, 0, 2, r, 64) == -EINVAL, "count does not match the records");
	EXPECT(p15w_append(w, 0, 1, r, 60) == -EINVAL, "length not a multiple of 8");
	EXPECT(p15w_append(w, 0, 1, r, 56) == -EINVAL, "record longer than the payload");
	EXPECT(p15w_append(w, 0, 1, NULL, 64) == -EINVAL, "no payload");
	mkrec(r, 36, 1);
	mkrec(r + 36, 36, 1);
	EXPECT(p15w_append(w, 0, 2, r, 72) == -EINVAL, "record lengths not multiples of 8, though the total is");
	EXPECT(p15w_stats(w)->rejected_batches == 7 && p15w_stats(w)->batches == 0, "all counted, none written");
	mkrec(r, 64, 1);
	EXPECT(p15w_append(w, 0, 1, r, 64) == 0, "the good one");
	p15w_close(w);
	rmtree(d);
	free(d);
}

static void test_batch_builder(void)
{
	char *d = tmpdir();
	struct p15w *w = open_w(d, 0, 0, 0, NULL);
	struct p15w_batch b;
	unsigned char r[1344];

	EXPECT(p15w_batch_init(&b, P15W_RING_SPINE, 128) == 0, "init");
	mkrec(r, 64, 1);
	EXPECT(p15w_batch_add(&b, r, sizeof(r)) == 0 && b.len == 64, "copied at its own len, not the reserved size");
	EXPECT(p15w_batch_add(&b, r, 64) == 0 && b.count == 2, "second");
	mkrec(r, 32, 2);
	EXPECT(p15w_batch_add(&b, r, 32) == -ENOSPC && b.count == 2, "full");
	r[4] = 33;
	EXPECT(p15w_batch_add(&b, r, 64) == -EINVAL, "len not a multiple of 8");
	r[4] = 16;
	EXPECT(p15w_batch_add(&b, r, 64) == -EINVAL, "len below a header");
	r[4] = 64;
	EXPECT(p15w_batch_add(&b, r, 40) == -EINVAL, "len past the bytes given");
	EXPECT(p15w_batch_add(&b, r, 16) == -EINVAL, "fewer bytes than a header");
	EXPECT(b.rejected == 4, "every refusal counted");
	EXPECT(p15w_batch_flush(w, &b) == 0 && b.count == 0 && b.len == 0, "flush empties");
	EXPECT(p15w_stats(w)->batches == 1 && p15w_stats(w)->records == 2, "one batch of two");
	EXPECT(p15w_batch_flush(w, &b) == 0 && p15w_stats(w)->batches == 1, "empty flush writes nothing");
	p15w_batch_free(&b);
	EXPECT(p15w_batch_init(&b, 7, 128) == -EINVAL && !b.buf, "bad ring");
	p15w_close(w);
	rmtree(d);
	free(d);
}

static void test_open_checks(void)
{
	char *d = tmpdir();
	struct p15w *w, *w2;
	struct p15w_kv dup[] = { { "a", "1" }, { "a", "2" } }, res[] = { { "clock.x", "1" } }, bad[] = { { "Run", "1" } };
	struct p15w_opts o = { .dir = d, .clock = fake_clock };

	o.meta = dup; o.nmeta = 2;
	EXPECT(p15w_open(&w, &o) == -EINVAL && !w, "duplicate key");
	o.meta = res; o.nmeta = 1;
	EXPECT(p15w_open(&w, &o) == -EINVAL, "writer's own key namespace");
	o.meta = bad; o.nmeta = 1;
	EXPECT(p15w_open(&w, &o) == -EINVAL, "key characters");
	o.meta = NULL; o.nmeta = 0;
	EXPECT(p15w_open(&w, &o) == 0, "open");
	EXPECT(p15w_open(&w2, &o) == -EEXIST, "never overwrites a segment");
	p15w_close(w);
	o.dir = "/nonexistent/p15w";
	EXPECT(p15w_open(&w, &o) == -ENOENT, "missing directory");
	rmtree(d);
	free(d);
}

int main(void)
{
	test_crc32c();
	test_round_trip();
	test_torn_tail_at_every_offset();
	test_corruption_is_not_a_torn_tail();
	test_rotation_by_size();
	test_oversize_batch();
	test_rotation_by_time_and_sync();
	test_on_open_writes_first();
	test_io_error_fails_the_writer();
	test_short_writes_and_eintr();
	test_bad_batches_rejected();
	test_batch_builder();
	test_open_checks();
	printf("%s: %d failures\n", __FILE__, failures);
	return failures != 0;
}
