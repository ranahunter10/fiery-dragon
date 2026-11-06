/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * Per-cause counters shared by the BPF programs and the daemon (ADR-0006,
 * accounting invariant). One u64 per (record type, kind). For every
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
	P15_CK_EXCLUDED = 6,       /* not recorded by policy (ADR-0006 rule 6 excluded_by_policy), e.g. a failed accept */
	P15_CK__N = 8,
};

#define P15_CTR_TYPES 8                       /* record types 0..7 */
#define P15_CTR_MAX (P15_CTR_TYPES * P15_CK__N)
#define P15_CTR_INDEX(type, kind) ((type) * P15_CK__N + (kind))

/*
 * Storage (ADR-0026). One BPF_MAP_TYPE_ARRAY of u64 with BPF_F_MMAPABLE, which p15d reads through
 * mmap, never through a bpf() map call: on 7.0 a map lookup or update from userspace holds
 * bpf_prog_active while preemptible (bpf_disable_instrumentation, include/linux/bpf.h), and kprobe
 * and classic-tracepoint programs of other tasks on that CPU are skipped meanwhile.
 *
 * Rows of P15_CTR_MAX counters (512 bytes, whole cache lines): row c for CPU c < ncpu, and one
 * last row, row ncpu, for any CPU at or above ncpu. ncpu is a rodata constant the loader sets with
 * the map's size (P15_CTR_ENTRIES). Left at its default 0, every count lands in row 0 and the map's
 * default size is that one row, so a loader that sets nothing still counts everything. A counter's
 * value is the sum of its slot over all rows. BPF adds atomically: fentry/fexit programs run
 * preemptible on 7.0, so two may interleave on one CPU (E-0097).
 */
#define P15_CTR_ENTRIES(ncpu) (((ncpu) + 1) * P15_CTR_MAX)
#define P15_CTR_SLOT(row, idx) ((row) * P15_CTR_MAX + (idx))

#endif /* P15_COUNTERS_H */
