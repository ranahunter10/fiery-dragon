// SPDX-License-Identifier: MIT
/*
 * The WAL's free-space guard (daemon/space.c, F-02), with an injected free-space reader: the sizes,
 * the levels and what each lets through, the hysteresis, the estimate between readings, a refused
 * batch, a failed reading, and the guard switched off.
 */
#include <errno.h>
#include <stdio.h>

#include "space.h"
#include "wal.h"

static int failures;

#define EXPECT(cond, msg) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

#define MiB (1ull << 20)
#define GiB (1ull << 30)

static uint64_t fake_avail, fake_total = 64 * GiB;
static int fake_err;

static int fake_statfs(int fd, uint64_t *avail, uint64_t *total)
{
	(void)fd;
	if (fake_err)
		return -fake_err;
	*avail = fake_avail;
	*total = fake_total;
	return 0;
}

static void test_sizes(void)
{
	uint64_t l, r;

	p15_space_sizes(64 * GiB, 0, 0, &l, &r);
	EXPECT(l == 512 * MiB && r == 64 * MiB, "a large filesystem: the fixed caps, 512 MiB and 64 MiB");
	p15_space_sizes(1 * GiB, 0, 0, &l, &r);
	EXPECT(l == GiB / 100 * 10 && r == GiB / 100 * 2, "1 GiB: 10 % and 2 %");
	p15_space_sizes(64 * MiB, 0, 0, &l, &r);
	EXPECT(r == 4 * MiB && l == 8 * MiB, "a tiny filesystem: the reserve's 4 MiB floor, low raised to twice it");
	p15_space_sizes(0, 0, 0, &l, &r);
	EXPECT(r == 4 * MiB && l == 8 * MiB, "size unknown: the floors");
	p15_space_sizes(64 * GiB, 20, 12, &l, &r);
	EXPECT(l == 24 * MiB && r == 12 * MiB, "given sizes, low raised to twice the reserve");
	p15_space_sizes(64 * GiB, 100, 10, &l, &r);
	EXPECT(l == 100 * MiB && r == 10 * MiB, "given sizes kept when consistent");
}

static void test_levels(void)
{
	struct p15_space s;

	p15_space_init(&s, 1, 100 * MiB, 20 * MiB);
	s.statfs = fake_statfs;
	EXPECT(s.level == P15_SPACE_OK && p15_space_allows(&s, P15W_RING_BULK), "before any reading: everything is written");
	fake_avail = 500 * MiB;
	EXPECT(p15_space_refresh(&s, 3) == 0 && s.level == P15_SPACE_OK, "plenty of space: OK, no change");
	fake_avail = 99 * MiB;
	EXPECT(p15_space_refresh(&s, 3) == 1 && s.level == P15_SPACE_SHED_BULK, "below low: SHED_BULK, a change");
	EXPECT(!p15_space_allows(&s, P15W_RING_BULK) && p15_space_allows(&s, P15W_RING_SPINE) &&
	       p15_space_allows(&s, P15W_RING_DAEMON), "SHED_BULK: the bulk ring shed, spine and daemon written");
	fake_avail = 19 * MiB;
	EXPECT(p15_space_refresh(&s, 3) == 1 && s.level == P15_SPACE_SHED_ALL, "below the reserve: SHED_ALL");
	EXPECT(!p15_space_allows(&s, P15W_RING_BULK) && !p15_space_allows(&s, P15W_RING_SPINE) &&
	       p15_space_allows(&s, P15W_RING_DAEMON), "SHED_ALL: only the daemon ring");
	/* hysteresis: leaving a level needs an eighth more than its threshold */
	fake_avail = 21 * MiB;
	EXPECT(p15_space_refresh(&s, 3) == 0 && s.level == P15_SPACE_SHED_ALL, "just above the reserve: still SHED_ALL");
	fake_avail = 20 * MiB + 20 * MiB / 8;
	EXPECT(p15_space_refresh(&s, 3) == 1 && s.level == P15_SPACE_SHED_BULK, "an eighth above it: back to SHED_BULK");
	fake_avail = 105 * MiB;
	EXPECT(p15_space_refresh(&s, 3) == 0 && s.level == P15_SPACE_SHED_BULK, "just above low: still SHED_BULK");
	fake_avail = 113 * MiB;
	EXPECT(p15_space_refresh(&s, 3) == 1 && s.level == P15_SPACE_OK, "an eighth above low: OK");
	fake_avail = 5 * MiB;
	EXPECT(p15_space_refresh(&s, 3) == 1 && s.level == P15_SPACE_SHED_ALL, "a fall straight past both: SHED_ALL");
	EXPECT(s.transitions == 5 && s.refreshes == 8, "every change and every reading counted");
}

static void test_estimate_between_readings(void)
{
	struct p15_space s;

	p15_space_init(&s, 1, 100 * MiB, 20 * MiB);
	s.statfs = fake_statfs;
	EXPECT(p15_space_wrote(&s, 1000 * MiB) == 0 && s.level == P15_SPACE_OK, "no reading yet: writes do not guess");
	fake_avail = 110 * MiB;
	(void)p15_space_refresh(&s, 3);
	EXPECT(p15_space_wrote(&s, 5 * MiB) == 0 && s.avail == 105 * MiB, "the estimate falls with each write");
	EXPECT(p15_space_wrote(&s, 6 * MiB) == 1 && s.level == P15_SPACE_SHED_BULK, "and crosses low without a reading");
	EXPECT(p15_space_wrote(&s, 10000 * MiB) == 1 && s.avail == 0 && s.level == P15_SPACE_SHED_ALL, "never below 0");
}

static void test_refused_and_errors(void)
{
	struct p15_space s;

	p15_space_init(&s, 1, 100 * MiB, 20 * MiB);
	s.statfs = fake_statfs;
	fake_avail = 900 * MiB;
	(void)p15_space_refresh(&s, 3);
	p15_space_full(&s);
	EXPECT(s.level == P15_SPACE_SHED_ALL && s.avail == 0, "a refused batch: SHED_ALL at once");
	fake_err = EIO;
	EXPECT(p15_space_refresh(&s, 3) == -EIO && s.refresh_errors == 1 && s.level == P15_SPACE_SHED_ALL,
	       "a failed reading: counted, the level kept");
	fake_err = 0;
	EXPECT(p15_space_refresh(&s, 3) == 1 && s.level == P15_SPACE_OK, "the next reading finds the space again");
}

static void test_off(void)
{
	struct p15_space s;

	p15_space_init(&s, 0, 100 * MiB, 20 * MiB);
	s.statfs = fake_statfs;
	fake_avail = 1 * MiB;
	EXPECT(p15_space_refresh(&s, 3) == 0 && s.refreshes == 0, "off: no reading");
	p15_space_full(&s);
	EXPECT(s.level == P15_SPACE_OK && p15_space_allows(&s, P15W_RING_SPINE) && p15_space_allows(&s, P15W_RING_BULK),
	       "off: every ring allowed, even after a refused batch (the disk decides)");
	EXPECT(p15_space_wrote(&s, 50 * MiB) == 0, "off: writes change nothing");
}

int main(void)
{
	test_sizes();
	test_levels();
	test_estimate_between_readings();
	test_refused_and_errors();
	test_off();
	printf("daemon/tests/test_space.c: %d failures\n", failures);
	return failures ? 1 : 0;
}
