// SPDX-License-Identifier: MIT
/* P15W v1.0 writer, batch builder and scanner. Format: docs/formats/p15w-v1.md. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "crc32c.h"
#include "wal.h"

#define DEF_MAX_BYTES (64ull << 20)
#define DEF_MAX_NS    (60ull * 1000000000ull)
#define DEF_SYNC_NS   1000000000ull
#define KEY_MAX       255u
#define VALUE_MAX     65536u

static const char *const ring_key[P15W_NRINGS] = { "seq.next.spine", "seq.next.bulk", "seq.next.daemon" };

struct p15w {
	struct p15w_opts o;
	int dirfd, fd;
	unsigned seg;
	uint64_t seg_bytes, seg_batches, opened_ns, last_sync_ns;
	int dirty, in_open, failed;      /* failed: the first error, as -errno */
	struct p15w_stats st;
};

/* ---- little-endian helpers ---- */

static void put16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = v >> (8 * i); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = v >> (8 * i); }
static uint16_t get16(const uint8_t *p) { return p[0] | p[1] << 8; }
static uint32_t get32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t get64(const uint8_t *p) { return get32(p) | (uint64_t)get32(p + 4) << 32; }
static uint32_t pad8(uint32_t n) { return (n + 7) & ~7u; }

/* ---- shared checks ---- */

static int key_ok(const char *k, size_t n)
{
	if (n == 0 || n > KEY_MAX)
		return 0;
	for (size_t i = 0; i < n; i++)
		if (!((k[i] >= 'a' && k[i] <= 'z') || (k[i] >= '0' && k[i] <= '9') || k[i] == '.' || k[i] == '_' ||
		      k[i] == '-'))
			return 0;
	return 1;
}

/* Records tile [p, p+len) exactly and number `count` (§3.1). */
static int tiles(const uint8_t *p, uint32_t len, uint32_t count)
{
	uint32_t off = 0, n = 0;

	while (off < len) {
		uint32_t rl;

		if (len - off < P15W_REC_MIN)
			return 0;
		rl = get16(p + off + 4);
		if (rl < P15W_REC_MIN || rl % 8 || rl > len - off)
			return 0;
		off += rl;
		n++;
	}
	return n == count;
}

/* ---- writer ---- */

static int fail(struct p15w *w, int err)
{
	w->st.errors++;
	if (!w->failed)
		w->failed = -err;
	return -err;
}

static int now(struct p15w *w, clockid_t id, uint64_t *ns)
{
	struct timespec ts;

	if (w->o.clock(id, &ts))
		return fail(w, errno ? errno : EINVAL);
	*ns = (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
	return 0;
}

static int write_all(struct p15w *w, struct iovec *iov, int n)
{
	while (n > 0) {
		ssize_t r = w->o.writev(w->fd, iov, n);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			return fail(w, errno);
		}
		while (n > 0 && (size_t)r >= iov->iov_len) {
			r -= iov->iov_len;
			iov++;
			n--;
		}
		if (n > 0) {             /* partial: finish the rest; still one batch on disk */
			w->st.short_writes++;
			iov->iov_base = (uint8_t *)iov->iov_base + r;
			iov->iov_len -= r;
		}
	}
	return 0;
}

static int write_header(struct p15w *w)
{
	char vals[10][32];
	struct p15w_kv own[10];
	uint64_t bt0, mono, real, bt1;
	size_t nown = 0, total = P15W_PREFIX_LEN;
	uint8_t *h, *p;
	int rc;
	struct iovec iov;

	if ((rc = now(w, CLOCK_BOOTTIME, &bt0)) || (rc = now(w, CLOCK_MONOTONIC, &mono)) ||
	    (rc = now(w, CLOCK_REALTIME, &real)) || (rc = now(w, CLOCK_BOOTTIME, &bt1)))
		return rc;
#define OWN(k, fmt, v) do { snprintf(vals[nown], sizeof(vals[nown]), fmt, v); \
			    own[nown].key = (k); own[nown].value = vals[nown]; nown++; } while (0)
	OWN("clock.boottime_ns", "%llu", (unsigned long long)bt0);
	OWN("clock.monotonic_ns", "%llu", (unsigned long long)mono);
	OWN("clock.realtime_ns", "%llu", (unsigned long long)real);
	OWN("clock.read_spread_ns", "%llu", (unsigned long long)(bt1 - bt0));
	for (int r = 0; r < P15W_NRINGS; r++)
		OWN(ring_key[r], "%llu", (unsigned long long)w->st.next_seq[r]);
	OWN("rotate.max_bytes", "%llu", (unsigned long long)w->o.max_bytes);
	OWN("rotate.max_ms", "%llu", (unsigned long long)(w->o.max_ns / 1000000));
	OWN("sync.interval_ms", "%llu", (unsigned long long)(w->o.sync_ns / 1000000));
#undef OWN
	for (size_t i = 0; i < nown + w->o.nmeta; i++) {
		const struct p15w_kv *kv = i < nown ? &own[i] : &w->o.meta[i - nown];

		total += pad8(8 + strlen(kv->key) + strlen(kv->value));
	}
	if (!(h = calloc(1, total)))
		return fail(w, ENOMEM);
	memcpy(h, "P15W", 4);
	put16(h + 4, 1);
	put16(h + 6, 0);
	put32(h + 8, 0x01020304);
	put32(h + 12, total);
	put32(h + 20, w->seg);
	put32(h + 24, nown + w->o.nmeta);
	p = h + P15W_PREFIX_LEN;
	for (size_t i = 0; i < nown + w->o.nmeta; i++) {
		const struct p15w_kv *kv = i < nown ? &own[i] : &w->o.meta[i - nown];
		size_t kl = strlen(kv->key), vl = strlen(kv->value);

		put16(p, kl);
		put32(p + 4, vl);
		memcpy(p + 8, kv->key, kl);
		memcpy(p + 8 + kl, kv->value, vl);
		p += pad8(8 + kl + vl);
	}
	put32(h + 16, p15_crc32c(0, h, total));
	iov.iov_base = h;
	iov.iov_len = total;
	rc = write_all(w, &iov, 1);
	free(h);
	if (rc)
		return rc;
	w->seg_bytes = total;
	w->st.file_bytes += total;
	w->opened_ns = w->last_sync_ns = mono;
	w->dirty = 1;
	return 0;
}

static int open_segment(struct p15w *w)
{
	char name[32];
	int rc;

	snprintf(name, sizeof(name), "seg-%08u.p15w", w->seg);
	w->fd = openat(w->dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0640);
	if (w->fd < 0)
		return fail(w, errno);
	if (fsync(w->dirfd))              /* the new name is durable too (§5) */
		return fail(w, errno);
	w->st.dir_fsyncs++;
	w->st.segments++;
	w->seg_batches = 0;
	if ((rc = write_header(w)))
		return rc;
	if (w->o.on_open) {
		w->in_open = 1;           /* the snapshot stays in its segment: no size rotation inside it */
		rc = w->o.on_open(w, w->o.on_open_ctx);
		w->in_open = 0;
		if (rc)
			return w->failed ? w->failed : fail(w, rc < 0 ? -rc : EINVAL);
	}
	return 0;
}

static int close_segment(struct p15w *w)
{
	int rc = 0;

	if (w->fd < 0)
		return 0;
	if (fdatasync(w->fd))
		rc = fail(w, errno);
	else
		w->st.fsyncs++;
	if (close(w->fd) && !rc)
		rc = fail(w, errno);
	w->fd = -1;
	w->dirty = 0;
	return rc;
}

static int rotate(struct p15w *w, uint64_t *counter)
{
	int rc = close_segment(w);

	if (rc)
		return rc;
	(*counter)++;
	w->seg++;
	return open_segment(w);
}

static int default_clock(clockid_t id, struct timespec *ts)
{
	return clock_gettime(id, ts);
}

int p15w_open(struct p15w **out, const struct p15w_opts *opts)
{
	struct p15w *w;
	int rc;

	*out = NULL;
	if (!opts || !opts->dir || (opts->nmeta && !opts->meta))
		return -EINVAL;
	for (size_t i = 0; i < opts->nmeta; i++) {
		const char *k = opts->meta[i].key, *v = opts->meta[i].value;

		if (!k || !v || !key_ok(k, strlen(k)) || strlen(v) > VALUE_MAX)
			return -EINVAL;
		/* the writer's own keys and the caller's must not collide; caller keys are unique */
		if (!strncmp(k, "clock.", 6) || !strncmp(k, "seq.next.", 9) || !strncmp(k, "rotate.", 7) ||
		    !strncmp(k, "sync.", 5))
			return -EINVAL;
		for (size_t j = 0; j < i; j++)
			if (!strcmp(k, opts->meta[j].key))
				return -EINVAL;
	}
	if (!(w = calloc(1, sizeof(*w))))
		return -ENOMEM;
	w->o = *opts;
	w->o.max_bytes = opts->max_bytes ? opts->max_bytes : DEF_MAX_BYTES;
	w->o.max_ns = opts->max_ns ? opts->max_ns : DEF_MAX_NS;
	w->o.sync_ns = opts->sync_ns ? opts->sync_ns : DEF_SYNC_NS;
	w->o.clock = opts->clock ? opts->clock : default_clock;
	w->o.writev = opts->writev ? opts->writev : writev;
	w->fd = -1;
	w->dirfd = open(opts->dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (w->dirfd < 0) {
		rc = -errno;
		free(w);
		return rc;
	}
	if ((rc = open_segment(w))) {
		if (w->fd >= 0)
			close(w->fd);
		close(w->dirfd);
		free(w);
		return rc;
	}
	*out = w;
	return 0;
}

int p15w_append(struct p15w *w, unsigned ring, uint32_t count, const void *payload, uint32_t len)
{
	uint8_t h[P15W_BATCH_HDR_LEN] = { 0 };
	struct iovec iov[2];
	uint64_t total = P15W_BATCH_HDR_LEN + (uint64_t)len;
	int rc;

	if (w->failed)
		return -EIO;
	if (ring >= P15W_NRINGS || count == 0 || !payload || len % 8 || len > P15W_MAX_PAYLOAD ||
	    (uint64_t)len < (uint64_t)count * P15W_REC_MIN || !tiles(payload, len, count)) {
		w->st.rejected_batches++;
		return -EINVAL;
	}
	if (!w->in_open && w->seg_batches > 0 && w->seg_bytes + total > w->o.max_bytes &&
	    (rc = rotate(w, &w->st.rotations_size)))
		return rc;
	if (w->seg_bytes + total > w->o.max_bytes)
		w->st.oversize_batches++;
	memcpy(h, "P15B", 4);
	put16(h + 4, ring);
	put32(h + 8, count);
	put32(h + 12, len);
	put64(h + 16, w->st.next_seq[ring]);
	put32(h + 24, p15_crc32c(0, payload, len));
	put32(h + 32, p15_crc32c(0, h, 32));
	iov[0].iov_base = h;
	iov[0].iov_len = sizeof(h);
	iov[1].iov_base = (void *)payload;
	iov[1].iov_len = len;
	if ((rc = write_all(w, iov, 2)))
		return rc;
	w->st.next_seq[ring] += count;
	w->seg_bytes += total;
	w->seg_batches++;
	w->st.batches++;
	w->st.records += count;
	w->st.payload_bytes += len;
	w->st.file_bytes += total;
	w->dirty = 1;
	return 0;
}

int p15w_tick(struct p15w *w)
{
	uint64_t t;
	int rc;

	if (w->failed)
		return -EIO;
	if ((rc = now(w, CLOCK_MONOTONIC, &t)))
		return rc;
	if (w->seg_batches > 0 && t - w->opened_ns >= w->o.max_ns)
		return rotate(w, &w->st.rotations_time);
	if (w->dirty && t - w->last_sync_ns >= w->o.sync_ns) {
		if (fdatasync(w->fd))
			return fail(w, errno);
		w->st.fsyncs++;
		w->last_sync_ns = t;
		w->dirty = 0;
	}
	return 0;
}

int p15w_close(struct p15w *w)
{
	int rc;

	if (!w)
		return 0;
	close_segment(w);
	close(w->dirfd);
	rc = w->failed;
	free(w);
	return rc;
}

const struct p15w_stats *p15w_stats(const struct p15w *w) { return &w->st; }
unsigned p15w_segment_index(const struct p15w *w) { return w->seg; }
int p15w_fd(const struct p15w *w) { return w->fd; }

/* ---- batch builder ---- */

int p15w_batch_init(struct p15w_batch *b, unsigned ring, uint32_t cap)
{
	memset(b, 0, sizeof(*b));
	if (ring >= P15W_NRINGS || cap < P15W_REC_MIN || cap > P15W_MAX_PAYLOAD)
		return -EINVAL;
	if (!(b->buf = malloc(cap)))
		return -ENOMEM;
	b->ring = ring;
	b->cap = cap;
	return 0;
}

void p15w_batch_free(struct p15w_batch *b)
{
	free(b->buf);
	b->buf = NULL;
}

int p15w_batch_add(struct p15w_batch *b, const void *rec, size_t size)
{
	uint32_t len;

	if (size < P15W_REC_MIN)
		goto bad;
	len = get16((const uint8_t *)rec + 4);
	if (len < P15W_REC_MIN || len % 8 || len > size || len > b->cap)
		goto bad;
	if (b->len + len > b->cap)
		return -ENOSPC;
	memcpy(b->buf + b->len, rec, len);
	b->len += len;
	b->count++;
	return 0;
bad:
	b->rejected++;
	return -EINVAL;
}

int p15w_batch_flush(struct p15w *w, struct p15w_batch *b)
{
	int rc;

	if (b->count == 0)
		return 0;
	rc = p15w_append(w, b->ring, b->count, b->buf, b->len);
	b->count = b->len = 0;   /* on error the caller counts the batch's records as lost */
	return rc;
}

/* ---- scanner ---- */

/* Check the header (§2). On success *hlen is set; if `find` is given, *val and *vlen locate its value. */
static int check_header(const uint8_t *b, size_t n, uint32_t *hlen, const char **why, const char *find,
			const uint8_t **val, uint32_t *vlen)
{
	uint32_t len, cnt, off, crc;
	static const uint8_t zero4[4];

	if (n < P15W_PREFIX_LEN)
		return *why = "header incomplete", -EBADMSG;
	if (memcmp(b, "P15W", 4))
		return *why = "segment magic", -EBADMSG;
	if (get16(b + 4) != 1 || get16(b + 6) != 0)
		return *why = "format version", -EBADMSG;
	if (get32(b + 8) != 0x01020304 || get32(b + 28) != 0)
		return *why = "byte order or reserved field", -EBADMSG;
	len = get32(b + 12);
	if (len < P15W_PREFIX_LEN || len % 8)
		return *why = "header length", -EBADMSG;
	if (len > n)
		return *why = "header incomplete", -EBADMSG;
	crc = p15_crc32c(0, b, 16);
	crc = p15_crc32c(crc, zero4, 4);
	crc = p15_crc32c(crc, b + 20, len - 20);
	if (crc != get32(b + 16))
		return *why = "header crc", -EBADMSG;
	cnt = get32(b + 24);
	off = P15W_PREFIX_LEN;
	for (uint32_t i = 0; i < cnt; i++) {
		uint32_t kl, vl;

		if (len - off < 8)
			return *why = "metadata entry", -EBADMSG;
		kl = get16(b + off);
		vl = get32(b + off + 4);
		if (get16(b + off + 2) || vl > VALUE_MAX || (uint64_t)pad8(8 + kl + vl) > len - off ||
		    !key_ok((const char *)b + off + 8, kl))
			return *why = "metadata entry", -EBADMSG;
		for (uint32_t j = 8 + kl + vl; j < pad8(8 + kl + vl); j++)
			if (b[off + j])
				return *why = "metadata padding", -EBADMSG;
		for (uint32_t prev = P15W_PREFIX_LEN; prev < off; prev += pad8(8 + get16(b + prev) + get32(b + prev + 4)))
			if (get16(b + prev) == kl && !memcmp(b + prev + 8, b + off + 8, kl))
				return *why = "duplicate metadata key", -EBADMSG;
		if (find && strlen(find) == kl && !memcmp(find, b + off + 8, kl)) {
			*val = b + off + 8 + kl;
			*vlen = vl;
		}
		off += pad8(8 + kl + vl);
	}
	if (off != len)
		return *why = "metadata does not end at header_len", -EBADMSG;
	*hlen = len;
	return 0;
}

static int all_zero(const uint8_t *p, size_t n)
{
	while (n--)
		if (*p++)
			return 0;
	return 1;
}

int p15w_header_get(const uint8_t *buf, size_t n, const char *key, char *out, size_t outlen)
{
	const uint8_t *v = NULL;
	uint32_t hlen, vl = 0;
	const char *why;

	if (check_header(buf, n, &hlen, &why, key, &v, &vl))
		return -EBADMSG;
	if (!v)
		return -ENOENT;
	if (vl + 1 > outlen)
		return -ENOSPC;
	memcpy(out, v, vl);
	out[vl] = 0;
	return 0;
}

int p15w_scan_buf(const uint8_t *buf, size_t n, struct p15w_scan *s)
{
	uint64_t off;

	memset(s, 0, sizeof(*s));
	s->file_size = n;
	if (check_header(buf, n, &s->header_len, &s->stop, NULL, NULL, NULL))
		return -EBADMSG;
	s->segment_index = get32(buf + 20);
	for (int r = 0; r < P15W_NRINGS; r++) {
		char v[24], *end;

		if (p15w_header_get(buf, n, ring_key[r], v, sizeof(v)) || !v[0])
			return s->stop = "missing seq.next in header", -EBADMSG;
		errno = 0;
		s->next_seq[r] = strtoull(v, &end, 10);
		if (*end || errno)
			return s->stop = "bad seq.next in header", -EBADMSG;
	}
	off = s->good_end = s->header_len;
	while (off < n) {
		const uint8_t *h = buf + off;
		uint64_t rem = n - off;
		uint32_t ring, count, plen;

		if (rem < P15W_BATCH_HDR_LEN) {
			s->stop = "short batch header";
			s->torn = 1;
			break;
		}
		ring = get16(h + 4);
		count = get32(h + 8);
		plen = get32(h + 12);
		if (memcmp(h, "P15B", 4))
			s->stop = "batch magic";
		else if (p15_crc32c(0, h, 32) != get32(h + 32))
			s->stop = "batch header crc";
		else if (get16(h + 6) || get32(h + 28) || get32(h + 36) || ring >= P15W_NRINGS)
			s->stop = "batch reserved field or ring";
		else if (count == 0 || plen % 8 || plen > P15W_MAX_PAYLOAD || (uint64_t)plen < (uint64_t)count * P15W_REC_MIN)
			s->stop = "batch count or length";
		else if (plen > rem - P15W_BATCH_HDR_LEN) {
			s->stop = "batch payload past end of file";
			s->torn = 1;
		} else if (p15_crc32c(0, h + P15W_BATCH_HDR_LEN, plen) != get32(h + 24)) {
			s->stop = "payload crc";
			s->torn = (off + P15W_BATCH_HDR_LEN + plen == n);
		} else if (!tiles(h + P15W_BATCH_HDR_LEN, plen, count))
			s->stop = "records do not tile the payload";
		else if (get64(h + 16) != s->next_seq[ring])
			s->stop = "sequence gap";
		if (s->stop) {
			if (all_zero(h, rem))    /* a zero-filled tail after a crash (§4) */
				s->torn = 1;
			break;
		}
		s->next_seq[ring] += count;
		s->batches++;
		s->records += count;
		off += P15W_BATCH_HDR_LEN + plen;
		s->good_end = off;
	}
	return 0;
}

int p15w_recover(const char *path, uint64_t *cut, const char **why)
{
	struct p15w_scan s;
	struct stat st;
	uint8_t *buf = NULL;
	ssize_t got = 0;
	int fd, rc = 0;

	*cut = 0;
	*why = NULL;
	if ((fd = open(path, O_RDWR | O_CLOEXEC)) < 0)
		return -errno;
	if (fstat(fd, &st)) {
		rc = -errno;
		goto out;
	}
	if (st.st_size && !(buf = malloc(st.st_size))) {
		rc = -ENOMEM;
		goto out;
	}
	while (got < st.st_size) {
		ssize_t r = pread(fd, buf + got, st.st_size - got, got);

		if (r <= 0) {
			rc = r < 0 ? -errno : -EIO;
			goto out;
		}
		got += r;
	}
	if (p15w_scan_buf(buf, st.st_size, &s)) {
		*why = s.stop;             /* a bad header is never truncated */
		rc = -EUCLEAN;
	} else if (s.stop && !s.torn) {
		*why = s.stop;
		rc = -EUCLEAN;
	} else if (s.stop) {
		*why = s.stop;
		if (ftruncate(fd, s.good_end) || fdatasync(fd))
			rc = -errno;
		else
			*cut = st.st_size - s.good_end;
	}
out:
	free(buf);
	close(fd);
	return rc;
}
