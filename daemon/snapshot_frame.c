// SPDX-License-Identifier: MIT
/* Framing and checking a process snapshot's output (ADR-0007 rule 3). See snapshot.h. */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "records.h"
#include "snapshot.h"

static void init(struct p15_snap_frame *f, uint16_t type, uint32_t snap_id, uint16_t kind, p15_snap_put_fn put,
		 void *ctx)
{
	f->type = type;
	f->snap_id = snap_id;
	f->kind = kind;
	f->have = 0;
	f->lost = 0;
	f->put = put;
	f->put_ctx = ctx;
}

void p15_snap_frame_init(struct p15_snap_frame *f, uint32_t snap_id, uint16_t kind, struct p15_snap_done_v2 *done,
			 p15_snap_put_fn put, void *ctx)
{
	init(f, P15_T_PROC, snap_id, kind, put, ctx);
	f->entries = &done->entries;
	f->invalid = &done->invalid;
	f->unwritten = &done->unwritten;
	f->error = &done->error;
}

void p15_snap_frame_init_fd(struct p15_snap_frame *f, uint32_t snap_id, struct p15_snap_done_v2 *done,
			    p15_snap_put_fn put, void *ctx)
{
	init(f, P15_T_FD, snap_id, 0, put, ctx);
	f->entries = &done->fd_entries;
	f->invalid = &done->fd_invalid;
	f->unwritten = &done->fd_unwritten;
	f->error = &done->fd_error;
}

/* A len that could be a record of the pass's type: framing holds while it does. */
static int plausible_len(const struct p15_snap_frame *f, uint16_t len)
{
	if (f->type == P15_T_FD)
		return len >= sizeof(struct p15_fd) && len <= P15_FD_MAX_SIZE && len % 8 == 0;
	return len >= sizeof(struct p15_proc) && len <= P15_PROC_MAX_SIZE && len % 8 == 0;
}

/* Of the pass's type and version, and of this snapshot. */
static int ours(const struct p15_snap_frame *f, const uint8_t *rec)
{
	const struct p15_hdr *h = (const void *)rec;

	if (h->type != f->type)
		return 0;
	if (f->type == P15_T_FD)
		return h->version == P15_FD_VERSION && ((const struct p15_fd *)rec)->snap_id == f->snap_id;
	return h->version == P15_PROC_VERSION && ((const struct p15_proc *)rec)->snap_id == f->snap_id &&
	       ((const struct p15_proc *)rec)->kind == f->kind;
}

static void one(struct p15_snap_frame *f, const uint8_t *rec, uint16_t len)
{
	const char *why;

	if (p15_rec_check(rec, len, &why) || !ours(f, rec)) {
		(*f->invalid)++;
		return;
	}
	if (f->put(f->put_ctx, rec, len))
		(*f->unwritten)++;
	else
		(*f->entries)++;
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
		if (!plausible_len(f, len)) {
			/* nothing tells where the next record starts: count one, stop reading, fail the snapshot */
			(*f->invalid)++;
			*f->error = -EPROTO;
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
		(*f->invalid)++;              /* a record cut short: the output ended inside it */
		if (!*f->error)
			*f->error = -EPROTO;
	}
	f->have = 0;
}

void p15_snap_books_fill(struct p15_snap_done_v2 *d, const struct p15_snap_books *b)
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

void p15_snap_fd_books_fill(struct p15_snap_done_v2 *d, const struct p15_fd_books *b)
{
	d->fd_pass = 1;
	d->fd_files = b->files;
	d->fd_no_inode = b->no_inode;
	d->fd_emitted = b->emitted;
	d->fd_write_failed = b->write_failed;
	d->fd_known = b->known;
	d->fd_registered = b->registered;
	d->fd_map_full = b->map_full;
	d->fd_path_error = b->path_error;
	d->fd_truncated = b->truncated;
}

/* The FD pass's books (bpf/include/p15_snap.h, SNAP_DONE v2 doc); 0 when they close. */
static int fd_books_close(const struct p15_snap_done_v2 *d, char *why, size_t n)
{
	if (!d->fd_pass)
		return 0;
	if (d->fd_error) {
		snprintf(why, n, "snapshot %u: reading the FD iterator failed (%d)", d->snap_id, d->fd_error);
		return -1;
	}
	if (d->fd_files != d->fd_no_inode + d->fd_emitted + d->fd_write_failed) {
		snprintf(why, n, "snapshot %u: fd_files %llu != fd_no_inode %llu + fd_emitted %llu + fd_write_failed %llu",
			 d->snap_id, (unsigned long long)d->fd_files, (unsigned long long)d->fd_no_inode,
			 (unsigned long long)d->fd_emitted, (unsigned long long)d->fd_write_failed);
		return -1;
	}
	if (d->fd_emitted != d->fd_entries + d->fd_invalid + d->fd_unwritten) {
		snprintf(why, n, "snapshot %u: fd_emitted %llu != fd_entries %llu + fd_invalid %llu + fd_unwritten %llu",
			 d->snap_id, (unsigned long long)d->fd_emitted, (unsigned long long)d->fd_entries,
			 (unsigned long long)d->fd_invalid, (unsigned long long)d->fd_unwritten);
		return -1;
	}
	if (d->fd_emitted != d->fd_known + d->fd_registered + d->fd_map_full) {
		snprintf(why, n, "snapshot %u: fd_emitted %llu != fd_known %llu + fd_registered %llu + fd_map_full %llu",
			 d->snap_id, (unsigned long long)d->fd_emitted, (unsigned long long)d->fd_known,
			 (unsigned long long)d->fd_registered, (unsigned long long)d->fd_map_full);
		return -1;
	}
	if (d->fd_write_failed || d->fd_invalid || d->fd_unwritten) {
		snprintf(why, n, "snapshot %u: FD rows: %llu not written by the program, %llu invalid, %llu refused by the WAL",
			 d->snap_id, (unsigned long long)d->fd_write_failed, (unsigned long long)d->fd_invalid,
			 (unsigned long long)d->fd_unwritten);
		return -1;
	}
	return 0;
}

int p15_snap_books_close(const struct p15_snap_done_v2 *d, char *why, size_t n)
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
	return fd_books_close(d, why, n);
}
