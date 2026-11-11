/* SPDX-License-Identifier: MIT */
/*
 * Bounded single-producer/single-consumer queue of batches between the drain thread
 * and the WAL writer thread (ADR-0017 layer 2). Preallocated at start; no locks and
 * no allocation on the hot path.
 *
 * Contract:
 *   producer (drain) only:  p15q_acquire, p15q_publish
 *   consumer (writer) only: p15q_peek, p15q_release, p15q_wait
 *   either thread:          p15q_depth, p15q_kick
 * The producer fills the slot p15q_acquire returned and publishes it; until then the
 * consumer can't see it. If every slot is full, p15q_acquire returns NULL and counts it
 * (q->full): the drain then reads nothing more from that BPF ring, which absorbs the backlog.
 */
#ifndef P15_QUEUE_H
#define P15_QUEUE_H

#include <stdatomic.h>
#include <stdint.h>

#include "compiler.h"

struct p15q_slot {
	unsigned ring;          /* WAL ring of every record in it (P15W_RING_*) */
	uint32_t count, len, cap;
	uint8_t *buf;
};

struct p15q {
	uint32_t n;             /* slots */
	struct p15q_slot *slots;
	_Atomic uint64_t head;  /* next slot the producer publishes; written by the producer only */
	_Atomic uint64_t tail;  /* next slot the consumer releases; written by the consumer only */
	int efd;                /* eventfd: the producer kicks it after publishing */
	_Atomic uint64_t full;  /* p15q_acquire found no free slot */
	_Atomic uint32_t depth_max;
};

/* n slots of cap bytes each. Returns 0 or -errno. */
P15_MUST_CHECK int p15q_init(struct p15q *q, uint32_t n, uint32_t cap);
void p15q_free(struct p15q *q);

/* Producer: the slot to fill next (emptied, ring set), or NULL if all are taken (counted). */
struct p15q_slot *p15q_acquire(struct p15q *q, unsigned ring);
/* Producer: make the acquired slot visible to the consumer and wake it. */
void p15q_publish(struct p15q *q);

/* Consumer: the oldest published slot, or NULL. */
struct p15q_slot *p15q_peek(struct p15q *q);
/* Consumer: give the peeked slot back. */
void p15q_release(struct p15q *q);
/* Consumer: wait up to timeout_ms for a publish or a kick. Returns 0, or -errno. */
P15_MUST_CHECK int p15q_wait(struct p15q *q, int timeout_ms);

/* Published slots not yet released. */
uint32_t p15q_depth(struct p15q *q);
/* Wake the consumer without publishing (e.g. to make it see a stop request). */
void p15q_kick(struct p15q *q);

#endif
