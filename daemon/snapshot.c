// SPDX-License-Identifier: MIT
/* Taking a process snapshot: the iterator, the read loop, the WAL (ADR-0007 rule 3). See snapshot.h. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "drain.h"
#include "exitcodes.h"
#include "snapshot.h"
#include "snap.skel.h"

#define SNAP_BATCH_CAP (256u << 10)

int p15_snapshot_init(struct p15_snapshot *s, struct p15_run *run, char *err, size_t errlen)
{
	memset(s, 0, sizeof(*s));
	s->run = run;
	if (p15w_batch_init(&s->batch, P15W_RING_DAEMON, SNAP_BATCH_CAP)) {
		snprintf(err, errlen, "snapshot: cannot allocate its batch");
		return P15_EXIT_OSERR;
	}
	s->skel = snap_bpf__open_and_load();
	if (!s->skel) {
		snprintf(err, errlen, "snapshot: load failed: %s", strerror(errno));
		return P15_EXIT_LOAD;
	}
	s->link = bpf_program__attach_iter(s->skel->progs.snap_task, NULL);
	if (!s->link) {
		snprintf(err, errlen, "snapshot: attaching the task iterator failed: %s", strerror(errno));
		return P15_EXIT_LOAD;
	}
	return 0;
}

void p15_snapshot_free(struct p15_snapshot *s)
{
	bpf_link__destroy(s->link);
	snap_bpf__destroy(s->skel);
	p15w_batch_free(&s->batch);
	s->link = NULL;
	s->skel = NULL;
}

struct sink {
	struct p15_snapshot *s;
	struct p15w *w;
	int wal_rc;                   /* the first WAL error */
};

/* The batch's records are entries only once appended: a failed flush turns them into unwritten. */
static int flush(struct sink *k)
{
	uint32_t count = k->s->batch.count;
	int rc = p15w_batch_flush(k->w, &k->s->batch);

	if (rc) {
		k->s->frame.done->entries -= count;
		k->s->frame.done->unwritten += count;
		if (!k->wal_rc)
			k->wal_rc = rc;
	}
	return rc;
}

static int put(void *ctx, const void *rec, uint32_t len)
{
	struct sink *k = ctx;
	int rc = p15w_batch_add(&k->s->batch, rec, len);

	if (rc == -ENOSPC) {
		if (flush(k))
			return k->wal_rc;
		rc = p15w_batch_add(&k->s->batch, rec, len);
	}
	return rc;
}

/* Read the iterator's output to its end in chunks of P15_SNAP_READ_CHUNK (p15_snap.h: the
 * kernel then never shows a task twice). Returns 0 or -errno. */
static int read_all(int fd, struct p15_snap_frame *f)
{
	for (;;) {
		ssize_t n = read(fd, f->buf + f->have, P15_SNAP_READ_CHUNK);

		if (n < 0 && (errno == EINTR || errno == EAGAIN))
			continue;     /* EAGAIN: a million tasks without output in one read (bpf_iter.c line 175) */
		if (n < 0)
			return -errno;
		if (n == 0)
			return 0;
		p15_snap_frame_feed(f, (size_t)n);
	}
}

int p15_snapshot_take(struct p15_snapshot *s, unsigned kind, struct p15w *w)
{
	struct p15_snap_done_v1 *d = &s->last;
	struct sink k = { .s = s, .w = w, .wal_rc = 0 };
	uint64_t t0;
	char why[200];
	int fd, rc;

	memset(d, 0, sizeof(*d));
	d->snap_id = s->next_id++;
	d->kind = (uint16_t)kind;
	memset(&s->skel->bss->books, 0, sizeof(s->skel->bss->books));
	s->skel->bss->snap_id = d->snap_id;
	s->skel->bss->snap_kind = kind;
	p15_snap_frame_init(&s->frame, d->snap_id, (uint16_t)kind, d, put, &k);

	t0 = p15_boot_ns();
	fd = bpf_iter_create(bpf_link__fd(s->link));
	if (fd < 0) {
		d->error = fd;
	} else {
		rc = read_all(fd, &s->frame);
		if (rc && !d->error)
			d->error = rc;
		close(fd);
	}
	p15_snap_frame_end(&s->frame);
	d->duration_ns = p15_boot_ns() - t0;
	flush(&k);
	p15_snap_books_fill(d, &s->skel->bss->books);

	p15_daemon_hdr(s->run, d, P15_T_SNAP_DONE, P15_SNAP_DONE_VERSION, sizeof(*d));
	rc = p15w_append(w, P15W_RING_DAEMON, 1, d, sizeof(*d));
	if (rc && !k.wal_rc)
		k.wal_rc = rc;
	if (k.wal_rc)
		return k.wal_rc;
	if (p15_snap_books_close(d, why, sizeof(why))) {
		p15_run_set_state(s->run, P15_RUN_INVALID, why);
		return P15_SNAP_INCOMPLETE;
	}
	return 0;
}

int p15_snapshot_on_open(struct p15w *w, void *ctx)
{
	struct p15_snapshot *s = ctx;
	int rc = p15_snapshot_take(s, P15_SNAP_OPENING, w);

	/* an incomplete snapshot has made the run INVALID with its reason; only a WAL failure stops the WAL */
	return rc == P15_SNAP_INCOMPLETE ? 0 : rc;
}
