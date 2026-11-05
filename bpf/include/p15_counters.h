/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * Per-cause counters shared by the BPF programs and the daemon (ADR-0006,
 * accounting invariant). One per-CPU u64 per (record type, kind). For every
 * record type, at quiescence:
 *
 *     SEEN == EMITTED + RESERVE_FAILED + BUILD_FAILED
 *
 * READ_FAILED and TRUNCATED describe emitted records (each such record also
 * carries P15_F_READ_FAILED / P15_F_TRUNCATED in its header flags).
 */
#ifndef P15_COUNTERS_H
#define P15_COUNTERS_H

enum p15_ctr_kind {
	P15_CK_SEEN = 0,           /* the hook fired */
	P15_CK_EMITTED = 1,        /* a record was submitted to the ring */
	P15_CK_RESERVE_FAILED = 2, /* the ring was full: no record (spine: run invalid) */
	P15_CK_READ_FAILED = 3,    /* a memory read for an emitted record failed */
	P15_CK_TRUNCATED = 4,      /* a variable-length field of an emitted record was cut */
	P15_CK_BUILD_FAILED = 5,   /* no buffer to build the record in, or a dynptr write refused: no record */
	P15_CK__N = 8,
};

#define P15_CTR_TYPES 8                       /* record types 0..7 */
#define P15_CTR_MAX (P15_CTR_TYPES * P15_CK__N)
#define P15_CTR_INDEX(type, kind) ((type) * P15_CK__N + (kind))

#endif /* P15_COUNTERS_H */
