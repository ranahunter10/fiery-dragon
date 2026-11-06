// SPDX-License-Identifier: MIT
#include "counters.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#define P15_CTR_NCPU_MAX 8192   /* far above any machine this runs on; bounds the map's size */

int p15_counters_configure(struct bpf_map *map, volatile uint32_t *ncpu_rodata, int ncpu)
{
	int rc;

	if (ncpu <= 0 || ncpu > P15_CTR_NCPU_MAX)
		return -EINVAL;
	rc = bpf_map__set_max_entries(map, P15_CTR_ENTRIES((uint32_t)ncpu));
	if (rc)
		return rc;
	*ncpu_rodata = (uint32_t)ncpu;
	return 0;
}

int p15_counters_verify(const struct bpf_map *map, int ncpu)
{
	if (ncpu <= 0 || ncpu > P15_CTR_NCPU_MAX ||
	    bpf_map__type(map) != BPF_MAP_TYPE_ARRAY || !(bpf_map__map_flags(map) & BPF_F_MMAPABLE) ||
	    bpf_map__value_size(map) != sizeof(uint64_t) ||
	    bpf_map__max_entries(map) != P15_CTR_ENTRIES((uint32_t)ncpu))
		return -EINVAL;
	return 0;
}

int p15_counters_map(struct p15_counters *c, int map_fd, int ncpu)
{
	long page = sysconf(_SC_PAGESIZE);
	size_t bytes, len;
	void *p;

	memset(c, 0, sizeof(*c));
	if (ncpu <= 0 || ncpu > P15_CTR_NCPU_MAX || page <= 0)
		return -EINVAL;
	bytes = (size_t)P15_CTR_ENTRIES((uint32_t)ncpu) * sizeof(uint64_t);
	len = (bytes + (size_t)page - 1) & ~((size_t)page - 1);   /* the kernel maps whole pages */
	p = mmap(NULL, len, PROT_READ, MAP_SHARED, map_fd, 0);
	if (p == MAP_FAILED)
		return -errno;
	c->rows = p;
	c->map_len = len;
	c->ncpu = ncpu;
	return 0;
}

void p15_counters_unmap(struct p15_counters *c)
{
	if (c->rows)
		munmap((void *)c->rows, c->map_len);
	memset(c, 0, sizeof(*c));
}

void p15_counters_sum_rows(const uint64_t *rows, int ncpu, uint64_t sum[P15_CTR_MAX])
{
	for (int k = 0; k < P15_CTR_MAX; k++)
		sum[k] = 0;
	for (int r = 0; r <= ncpu; r++)   /* ncpu CPU rows, then the last row */
		for (int k = 0; k < P15_CTR_MAX; k++)
			sum[k] += __atomic_load_n(&rows[P15_CTR_SLOT(r, k)], __ATOMIC_RELAXED);
}

void p15_counters_sum(const struct p15_counters *c, uint64_t sum[P15_CTR_MAX])
{
	p15_counters_sum_rows(c->rows, c->ncpu, sum);
}
