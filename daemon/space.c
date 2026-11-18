// SPDX-License-Identifier: MIT
/* See space.h. */
#include <errno.h>
#include <string.h>
#include <sys/statvfs.h>

#include "space.h"
#include "wal.h"

static int real_statfs(int fd, uint64_t *avail, uint64_t *total)
{
	struct statvfs v;

	if (fstatvfs(fd, &v))
		return -errno;
	*avail = (uint64_t)v.f_bavail * v.f_frsize;
	*total = (uint64_t)v.f_blocks * v.f_frsize;
	return 0;
}

void p15_space_sizes(uint64_t total, uint32_t low_mb, uint32_t reserve_mb, uint64_t *low, uint64_t *reserve)
{
	uint64_t l = low_mb ? (uint64_t)low_mb << 20 : total / 100 * P15_SPACE_LOW_PCT;
	uint64_t r = reserve_mb ? (uint64_t)reserve_mb << 20 : total / 100 * P15_SPACE_RESERVE_PCT;

	if (!low_mb && l > P15_SPACE_LOW_MAX)
		l = P15_SPACE_LOW_MAX;
	if (!reserve_mb && r > P15_SPACE_RESERVE_MAX)
		r = P15_SPACE_RESERVE_MAX;
	if (r < P15_SPACE_RESERVE_MIN)
		r = P15_SPACE_RESERVE_MIN;
	if (l < 2 * r)
		l = 2 * r;              /* SHED_BULK must come before SHED_ALL, with room between them */
	*low = l;
	*reserve = r;
}

void p15_space_init(struct p15_space *s, int on, uint64_t low, uint64_t reserve)
{
	memset(s, 0, sizeof(*s));
	s->on = on;
	s->low = low;
	s->reserve = reserve;
	s->avail = UINT64_MAX;      /* unknown until the first refresh: nothing is shed on a guess */
}

/* The level for `avail`, given the current one: entering a level at its threshold, leaving it only
 * an eighth of the threshold above it. */
static int level_for(const struct p15_space *s, uint64_t avail)
{
	uint64_t up_low = s->low + s->low / 8, up_res = s->reserve + s->reserve / 8;
	int lv = s->level;

	if (avail < s->reserve)
		return P15_SPACE_SHED_ALL;
	if (lv == P15_SPACE_SHED_ALL && avail < up_res)
		return P15_SPACE_SHED_ALL;
	if (avail < s->low)
		return P15_SPACE_SHED_BULK;
	if (lv >= P15_SPACE_SHED_BULK && avail < up_low)
		return P15_SPACE_SHED_BULK;
	return P15_SPACE_OK;
}

static int set_level(struct p15_space *s, int lv)
{
	if (lv == s->level)
		return 0;
	s->level = lv;
	s->transitions++;
	return 1;
}

int p15_space_refresh(struct p15_space *s, int fd)
{
	uint64_t avail = 0, total = 0;
	int rc;

	if (!s->on)
		return 0;
	rc = (s->statfs ? s->statfs : real_statfs)(fd, &avail, &total);
	if (rc) {
		s->refresh_errors++;
		return rc;
	}
	s->refreshes++;
	s->avail = avail;
	s->total = total;
	return set_level(s, level_for(s, avail));
}

int p15_space_wrote(struct p15_space *s, uint64_t bytes)
{
	if (!s->on || s->avail == UINT64_MAX)
		return 0;
	s->avail = s->avail > bytes ? s->avail - bytes : 0;
	return set_level(s, level_for(s, s->avail));
}

void p15_space_full(struct p15_space *s)
{
	if (!s->on)
		return;
	s->avail = 0;
	set_level(s, P15_SPACE_SHED_ALL);
}

int p15_space_allows(const struct p15_space *s, unsigned ring)
{
	if (!s->on || ring == P15W_RING_DAEMON)
		return 1;               /* small, and it says what happened: written into the reserve */
	if (ring == P15W_RING_SPINE)
		return s->level < P15_SPACE_SHED_ALL;
	return s->level == P15_SPACE_OK;
}

const char *p15_space_level_name(int level)
{
	static const char *const names[] = { "ok", "shed_bulk", "shed_all" };

	return level >= 0 && level <= 2 ? names[level] : "?";
}
