/* SPDX-License-Identifier: MIT */
/*
 * The BPF loss counters, read without a bpf() map call (ADR-0026). The programs keep them in an
 * mmapable array of rows (bpf/include/p15_counters.h); p15d maps it read-only once and sums the
 * rows on every read. A map lookup from userspace would hold bpf_prog_active while preemptible
 * and make the kernel skip other tasks' kprobe and classic-tracepoint programs on that CPU.
 */
#ifndef P15_COUNTERS_DAEMON_H
#define P15_COUNTERS_DAEMON_H

#include <stddef.h>
#include <stdint.h>

#include "compiler.h"
#include "p15_counters.h"

struct bpf_map;

/* Before load: set the map's size and the program's row count together, for ncpu possible CPUs.
 * ncpu_rodata points into the skeleton's rodata (e.g. &skel->rodata->spine_counters_ncpu).
 * 0, or -EINVAL (ncpu out of range) or the libbpf error. */
P15_MUST_CHECK int p15_counters_configure(struct bpf_map *map, volatile uint32_t *ncpu_rodata, int ncpu);
/* After load: the map is the mmapable u64 array p15_counters_configure asked for. 0 or -EINVAL. */
P15_MUST_CHECK int p15_counters_verify(const struct bpf_map *map, int ncpu);

struct p15_counters {
	const uint64_t *rows;   /* P15_CTR_ENTRIES(ncpu) u64, read-only, shared with BPF */
	size_t map_len;         /* bytes mapped */
	int ncpu;
};

/* Map the counters of map_fd (P15_CTR_ENTRIES(ncpu) entries) read-only. 0 or -errno. */
P15_MUST_CHECK int p15_counters_map(struct p15_counters *c, int map_fd, int ncpu);
void p15_counters_unmap(struct p15_counters *c);
/* sum[k] = counter k over every row (each value read once, atomically). */
void p15_counters_sum(const struct p15_counters *c, uint64_t sum[P15_CTR_MAX]);
/* The same over a plain buffer of rows; for the unit tests. */
void p15_counters_sum_rows(const uint64_t *rows, int ncpu, uint64_t sum[P15_CTR_MAX]);

#endif
