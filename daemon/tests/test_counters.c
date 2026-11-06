// SPDX-License-Identifier: MIT
/*
 * Unit tests for the counter storage (ADR-0026): the row layout and its sum, and configure /
 * verify against the spine's real map definition (the skeleton is opened, never loaded, so no
 * root is needed). The mapping itself is exercised by p15d's end-to-end test.
 * Run: make test-c
 */
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>

#include "counters.h"
#include "spine.skel.h"

static int failures;

#define EXPECT(cond, msg) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

static void test_layout(void)
{
	EXPECT(P15_CTR_MAX * 8 % 64 == 0, "a row is a whole number of cache lines");
	EXPECT(P15_CTR_ENTRIES(0) == P15_CTR_MAX, "ncpu 0: one row (the default map size)");
	EXPECT(P15_CTR_ENTRIES(3) == 4 * P15_CTR_MAX, "ncpu 3: three CPU rows and the last row");
	EXPECT(P15_CTR_SLOT(1, 5) == P15_CTR_MAX + 5, "slot (row 1, counter 5)");
}

static void test_sum(void)
{
	enum { NCPU = 3 };
	uint64_t rows[P15_CTR_ENTRIES(NCPU)], sum[P15_CTR_MAX];
	int ok = 1;

	memset(rows, 0, sizeof(rows));
	for (int r = 0; r <= NCPU; r++)
		for (int k = 0; k < P15_CTR_MAX; k++)
			rows[P15_CTR_SLOT(r, k)] = (uint64_t)(r + 1) * 1000 + (uint64_t)k;   /* every row distinct */
	p15_counters_sum_rows(rows, NCPU, sum);
	for (int k = 0; k < P15_CTR_MAX; k++)
		ok &= sum[k] == (1000 + 2000 + 3000 + 4000) + 4ull * (uint64_t)k;
	EXPECT(ok, "each counter is its slot summed over the three CPU rows and the last row");

	memset(rows, 0, sizeof(rows));
	rows[P15_CTR_SLOT(NCPU, 7)] = 5;   /* a count from a CPU at or above ncpu */
	p15_counters_sum_rows(rows, NCPU, sum);
	EXPECT(sum[7] == 5 && sum[6] == 0 && sum[8] == 0, "a count in the last row is counted, and only in its slot");

	memset(rows, 0, sizeof(rows));
	rows[P15_CTR_SLOT(0, 0)] = 9;      /* an unconfigured program: everything in row 0 */
	p15_counters_sum_rows(rows, 0, sum);
	EXPECT(sum[0] == 9, "ncpu 0: row 0 alone is summed");
}

static void test_configure_verify(void)
{
	struct spine_bpf *s = spine_bpf__open();
	struct bpf_map *m;

	EXPECT(s != NULL, "the spine skeleton opens without root");
	if (!s)
		return;
	m = s->maps.spine_counters;
	EXPECT(bpf_map__type(m) == BPF_MAP_TYPE_ARRAY && (bpf_map__map_flags(m) & BPF_F_MMAPABLE) &&
	       bpf_map__value_size(m) == sizeof(uint64_t), "the BPF definition is an mmapable u64 array");
	EXPECT(bpf_map__max_entries(m) == P15_CTR_ENTRIES(0) && s->rodata->spine_counters_ncpu == 0,
	       "unconfigured: one row and ncpu 0, consistent with each other");
	EXPECT(p15_counters_verify(m, 3) != 0, "verify refuses the unconfigured map for 3 CPUs");
	EXPECT(p15_counters_configure(m, &s->rodata->spine_counters_ncpu, 0) != 0, "configure refuses ncpu 0");
	EXPECT(p15_counters_configure(m, &s->rodata->spine_counters_ncpu, 100000) != 0, "configure refuses an absurd ncpu");
	EXPECT(p15_counters_configure(m, &s->rodata->spine_counters_ncpu, 3) == 0, "configure for 3 CPUs");
	EXPECT(bpf_map__max_entries(m) == P15_CTR_ENTRIES(3) && s->rodata->spine_counters_ncpu == 3,
	       "  ... sets the size and the program's row count together");
	EXPECT(p15_counters_verify(m, 3) == 0, "  ... and verify accepts it");
	EXPECT(p15_counters_verify(m, 4) != 0, "verify refuses a different CPU count");
	EXPECT(p15_counters_verify(m, 0) != 0, "verify refuses ncpu 0");
	EXPECT(bpf_map__set_map_flags(m, 0) == 0 && p15_counters_verify(m, 3) != 0, "verify refuses a map that is not mmapable");
	EXPECT(bpf_map__set_map_flags(m, BPF_F_MMAPABLE) == 0 && p15_counters_verify(m, 3) == 0, "  ... and accepts it again");
	EXPECT(bpf_map__set_value_size(m, 4) == 0 && p15_counters_verify(m, 3) != 0, "verify refuses 4-byte values");
	EXPECT(bpf_map__set_value_size(m, 8) == 0 && bpf_map__set_type(m, BPF_MAP_TYPE_PERCPU_ARRAY) == 0 &&
	       p15_counters_verify(m, 3) != 0, "verify refuses a per-CPU array (it can't be mapped)");
	spine_bpf__destroy(s);
}

int main(void)
{
	test_layout();
	test_sum();
	test_configure_verify();
	printf("%s: %d failures\n", __FILE__, failures);
	return failures != 0;
}
