/* SPDX-License-Identifier: MIT */
/*
 * P15W v1.0 write-ahead log: writer, batch builder and scanner (ADR-0007).
 * The format is specified in docs/formats/p15w-v1.md; this code follows it.
 *
 * Time never comes from a hidden source: every function that needs the clock
 * reads it through opts.clock, so tests drive rotation and syncing exactly.
 * Likewise every write goes through opts.writev, so tests can force short writes.
 */
#ifndef P15_WAL_H
#define P15_WAL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include "compiler.h"

#define P15W_PREFIX_LEN    32u
#define P15W_BATCH_HDR_LEN 40u
#define P15W_MAX_PAYLOAD   (16u << 20)
#define P15W_REC_MIN       32u      /* an ADR-0008 record header */

enum { P15W_RING_SPINE = 0, P15W_RING_BULK = 1, P15W_RING_DAEMON = 2, P15W_NRINGS = 3 };

struct p15w;

struct p15w_kv {
	const char *key;      /* [a-z0-9._-], 1-255 bytes, unique */
	const char *value;    /* UTF-8 text, <= 65,536 bytes */
};

typedef int (*p15w_clock_fn)(clockid_t id, struct timespec *ts);
typedef ssize_t (*p15w_writev_fn)(int fd, const struct iovec *iov, int n);
/* Called right after each segment's header is written, before any other batch (the snapshot, step 4c). */
typedef int (*p15w_open_fn)(struct p15w *w, void *ctx);

struct p15w_opts {
	const char *dir;                 /* existing run directory, empty of segments */
	uint64_t max_bytes;              /* rotate before passing this size; 0 = 64 MiB */
	uint64_t max_ns;                 /* rotate after this age; 0 = 60 s */
	uint64_t sync_ns;                /* fdatasync when this much time has passed; 0 = 1 s */
	const struct p15w_kv *meta;      /* repeated in every segment header */
	size_t nmeta;
	p15w_open_fn on_open;
	void *on_open_ctx;
	p15w_clock_fn clock;             /* NULL = clock_gettime */
	p15w_writev_fn writev;           /* NULL = writev; tests inject short writes and EINTR */
};

/* Every early return, rotation and failure is counted (CLAUDE.md: no silent paths). */
struct p15w_stats {
	uint64_t segments;               /* opened */
	uint64_t rotations_size, rotations_time;
	uint64_t batches, records, payload_bytes, file_bytes;
	uint64_t fsyncs, dir_fsyncs;
	uint64_t short_writes;           /* writev returned less than asked; the rest was written after */
	uint64_t oversize_batches;       /* larger than max_bytes: written alone in a segment */
	uint64_t rejected_batches;       /* refused by p15w_append's checks (bad arguments, not I/O) */
	uint64_t errors;                 /* write, sync, open or clock failures; the writer is then failed */
	uint64_t next_seq[P15W_NRINGS];
};

/* Create segment 0 in opts->dir. Returns 0 or -errno; *out is NULL on failure. */
P15_MUST_CHECK int p15w_open(struct p15w **out, const struct p15w_opts *opts);

/*
 * Append one batch: `count` records, `len` bytes, all from `ring`. The records must
 * tile the payload (docs/formats/p15w-v1.md §3.1). Assigns the ring's next sequence
 * numbers. Returns 0, -EINVAL (bad batch, counted, nothing written) or -errno from I/O.
 * After an I/O error every call returns -EIO: the run is invalid (ADR-0006 rule 6).
 */
P15_MUST_CHECK int p15w_append(struct p15w *w, unsigned ring, uint32_t count, const void *payload, uint32_t len);

/* Rotate by age and fdatasync by interval, if due. Call it from the drain loop. */
P15_MUST_CHECK int p15w_tick(struct p15w *w);

/* fdatasync and close. Returns the first error the writer saw, or 0. Frees w. */
P15_MUST_CHECK int p15w_close(struct p15w *w);

const struct p15w_stats *p15w_stats(const struct p15w *w);
unsigned p15w_segment_index(const struct p15w *w);
int p15w_fd(const struct p15w *w);       /* diagnostics and tests only */

/* ---- batch builder: records are copied at their own len, not the ring's reserved size ---- */

struct p15w_batch {
	unsigned ring;
	uint32_t count, len, cap;
	uint8_t *buf;
	uint64_t rejected;               /* records refused by p15w_batch_add for a bad len */
};

P15_MUST_CHECK int p15w_batch_init(struct p15w_batch *b, unsigned ring, uint32_t cap);
void p15w_batch_free(struct p15w_batch *b);
/*
 * Copy one record. `size` is the bytes available at `rec`; the record's own len
 * (u16 at offset 4) is what is copied. Returns 0, -ENOSPC if it does not fit
 * (flush, then add again), or -EINVAL if len < 32, len % 8, or len > size (counted).
 */
P15_MUST_CHECK int p15w_batch_add(struct p15w_batch *b, const void *rec, size_t size);
/* Append the batch if it holds records, then empty it. Returns p15w_append's result. */
P15_MUST_CHECK int p15w_batch_flush(struct p15w *w, struct p15w_batch *b);

/* ---- scanner: the reader's rules of §4, used for recovery and by tests ---- */

struct p15w_scan {
	uint32_t segment_index;
	uint32_t header_len;
	uint64_t file_size;
	uint64_t good_end;               /* bytes from the start that are valid */
	uint64_t batches, records;
	uint64_t next_seq[P15W_NRINGS];  /* after the last valid batch */
	const char *stop;                /* NULL if valid to the end of the file, else the §4 cause */
	int torn;                        /* the stop is a torn tail (§4), not corruption */
};

/*
 * Scan a segment held in memory. Returns 0 (see s->stop), or -EBADMSG if the
 * header itself fails its checks (s->stop says which).
 */
P15_MUST_CHECK int p15w_scan_buf(const uint8_t *buf, size_t n, struct p15w_scan *s);

/* Copy the value of `key` from a valid header into out (NUL-terminated). 0, -ENOENT or -ENOSPC. */
P15_MUST_CHECK int p15w_header_get(const uint8_t *buf, size_t n, const char *key, char *out, size_t outlen);

/*
 * Recovery: scan the segment at path; if it ends in a torn tail, truncate it at the
 * last valid batch and set *cut to the bytes removed. Corruption is never truncated:
 * returns -EUCLEAN with *why set. Returns 0 when the file is clean or was cut.
 */
P15_MUST_CHECK int p15w_recover(const char *path, uint64_t *cut, const char **why);

#endif
