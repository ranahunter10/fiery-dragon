/* SPDX-License-Identifier: MIT */
/*
 * The drain (ADR-0006 rule 4, ADR-0017 layers 2-4): polls the BPF rings, checks every record,
 * copies it at its own len into a queue batch, and publishes batches to the writer. It never
 * touches the disk. After every poll it reads the BPF loss counters (through their mapping, never a
 * map syscall: ADR-0026) and the kernel's per-program
 * skip counters (recursion_misses, ADR-0020 rule 3); if spine records were lost or skipped since
 * the previous read it emits a GAP record that brackets the loss in time. Records don't wake it
 * below the rings' high-water mark (ADR-0020 rule 2), so every poll ends with a consume.
 * Runs on p15d's main thread; owns the producer side of run->q.
 */
#ifndef P15_DRAIN_H
#define P15_DRAIN_H

#include <stdint.h>

#include "compiler.h"
#include "counters.h"
#include "run.h"

struct ring_buffer;
struct ring;

struct p15_drain {
	struct p15_run *run;
	struct ring_buffer *rb;
	struct ring *spine, *bulk;
	struct p15_counters ctr, bulk_ctr; /* mapped counter rows (ADR-0026); bulk_ctr unmapped without network */
	struct p15_counters file_ctr;     /* the file-identity counters; unmapped without them */
	int ncpu;
	struct p15q_slot *open;          /* the batch being filled, or NULL */
	uint64_t prev_ctr[P15_CTR_MAX], prev_bulk[P15_CTR_MAX];
	uint64_t prev_missed[P15_SPINE_TYPES], prev_net_missed;
	uint64_t prev_file[P15_CTR_MAX], prev_file_kprobe_missed;
	uint64_t prev_read_ns, last_poll_ns;
	int queue_full_now;              /* the last poll left records in a ring for want of a batch */
};

/* bulk_rb_fd is -1 without network capture and file identity; bulk_ctr_fd (NET) and file_ctr_fd are -1
 * without theirs. */
P15_MUST_CHECK int p15_drain_init(struct p15_drain *d, struct p15_run *run, int spine_rb_fd, int ctr_fd, int bulk_rb_fd,
				int bulk_ctr_fd, int file_ctr_fd);
void p15_drain_free(struct p15_drain *d);
/* One poll of up to timeout_ms, then publish, then the counter read and GAP check. 0 or -errno. */
P15_MUST_CHECK int p15_drain_poll(struct p15_drain *d, int timeout_ms);
/* After the programs are detached: empty the rings, publish, final counter read. 0 or -errno. */
P15_MUST_CHECK int p15_drain_finish(struct p15_drain *d);
/* Did spine records get lost since the previous read: a ring or build failure, or an event the
 * kernel skipped (recursion_misses, ADR-0020 rule 3)? Then the drain emits a GAP. */
int p15_spine_loss_changed(const uint64_t *prev_ctr, const uint64_t *now_ctr, const uint64_t *prev_missed,
			   const uint64_t *now_missed);
/* Fill a daemon record's common header (ADR-0008): ts now (boot clock), the daemon's identity. */
void p15_daemon_hdr(const struct p15_run *r, void *rec, unsigned type, unsigned version, unsigned len);

#endif
