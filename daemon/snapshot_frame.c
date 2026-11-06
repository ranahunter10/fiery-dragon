// SPDX-License-Identifier: MIT
/* Framing and checking a process snapshot's output (ADR-0007 rule 3). See snapshot.h. */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "records.h"
#include "snapshot.h"

void p15_snap_frame_init(struct p15_snap_frame *f, uint32_t snap_id, uint16_t kind, struct p15_snap_done_v1 *done,
			 p15_snap_put_fn put, void *ctx)
{
	f->snap_id = snap_id;
	f->kind = kind;
	f->have = 0;
	f->lost = 0;
	f->done = done;
	f->put = put;
	f->put_ctx = ctx;
}

/* A len that could be a PROC record: framing holds while it does. */
static int plausible_len(uint16_t len)
{
	return len >= sizeof(struct p15_proc) && len <= P15_PROC_MAX_SIZE && len % 8 == 0;
}

static void one(struct p15_snap_frame *f, const uint8_t *rec, uint16_t len)
{
	const struct p15_proc *p = (const void *)rec;
	const char *why;

	if (p15_rec_check(rec, len, &why) || p->h.type != P15_T_PROC || p->h.version != P15_PROC_VERSION || p->snap_id != f->snap_id ||
	    p->kind != f->kind) {
		f->done->invalid++;
		return;
	}
	if (f->put(f->put_ctx, rec, len))
		f->done->unwritten++;
	else
		f->done->entries++;
}

void p15_snap_frame_feed(struct p15_snap_frame *f, size_t n)
{
	uint32_t off = 0;

	f->have += (uint32_t)n;
	if (f->lost) {
		f->have = 0;
		return;
	}
	while (f->have - off >= sizeof(struct p15_hdr)) {
		uint16_t len;

		memcpy(&len, f->buf + off + offsetof(struct p15_hdr, len), sizeof(len));
		if (!plausible_len(len)) {
			/* nothing tells where the next record starts: count one, stop reading, fail the snapshot */
			f->done->invalid++;
			f->done->error = -EPROTO;
			f->lost = 1;
			f->have = 0;
			return;
		}
		if (f->have - off < len)
			break;
		one(f, f->buf + off, len);
		off += len;
	}
	memmove(f->buf, f->buf + off, f->have - off);
	f->have -= off;
}

void p15_snap_frame_end(struct p15_snap_frame *f)
{
	if (f->have && !f->lost) {
		f->done->invalid++;           /* a record cut short: the output ended inside it */
		if (!f->done->error)
			f->done->error = -EPROTO;
	}
	f->have = 0;
}

void p15_snap_books_fill(struct p15_snap_done_v1 *d, const struct p15_snap_books *b)
{
	d->tasks = b->tasks;
	d->threads = b->threads;
	d->emitted = b->emitted;
	d->write_failed = b->write_failed;
	d->kthreads = b->kthreads;
	d->exiting = b->exiting;
	d->argv_failed = b->argv_failed;
	d->path_unlocked = b->path_unlocked;
	d->path_not_found = b->path_not_found;
	d->path_failed = b->path_failed;
	d->truncated = b->truncated;
}

int p15_snap_books_close(const struct p15_snap_done_v1 *d, char *why, size_t n)
{
	if (d->error) {
		snprintf(why, n, "snapshot %u: reading the iterator failed (%d)", d->snap_id, d->error);
		return -1;
	}
	if (d->tasks != d->threads + d->emitted + d->write_failed) {
		snprintf(why, n, "snapshot %u: tasks %llu != threads %llu + emitted %llu + write_failed %llu", d->snap_id,
			 (unsigned long long)d->tasks, (unsigned long long)d->threads, (unsigned long long)d->emitted,
			 (unsigned long long)d->write_failed);
		return -1;
	}
	if (d->emitted != d->entries + d->invalid + d->unwritten) {
		snprintf(why, n, "snapshot %u: emitted %llu != entries %llu + invalid %llu + unwritten %llu", d->snap_id,
			 (unsigned long long)d->emitted, (unsigned long long)d->entries, (unsigned long long)d->invalid,
			 (unsigned long long)d->unwritten);
		return -1;
	}
	if (d->write_failed || d->invalid || d->unwritten) {
		snprintf(why, n, "snapshot %u: %llu not written by the program, %llu invalid, %llu refused by the WAL",
			 d->snap_id, (unsigned long long)d->write_failed, (unsigned long long)d->invalid,
			 (unsigned long long)d->unwritten);
		return -1;
	}
	return 0;
}
