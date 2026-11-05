// SPDX-License-Identifier: MIT
/*
 * Unit tests for p15_rec_check and p15_rec_format on the daemon records (CLOCK_SYNC, STATS,
 * GAP, END) and the fixed-size rule for every type. The EXEC rules are tested in
 * test_selftest.c. No root, no BPF. Run: make test-c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "records.h"

static int failures;

#define EXPECT(cond, msg) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

static unsigned char buf[2048];

static struct p15_hdr *mk(unsigned type, unsigned len)
{
	struct p15_hdr *h = (void *)buf;

	memset(buf, 0, sizeof(buf));
	h->type = type;
	h->version = 1;
	h->len = len;
	h->ts_ns = 123;
	h->tgid = h->tid = 77;
	h->start_ns = 9;
	return h;
}

static int ok(void)
{
	const char *why = "unset";
	int rc = p15_rec_check(buf, sizeof(buf), &why);

	return rc == 0 && why == NULL;
}

/* p15_rec_check on a heap copy of exactly `size` bytes, as the ring hands it over: under ASan,
 * any read past those bytes is an error. */
static int ok_exact(size_t size)
{
	unsigned char *copy = malloc(size);
	const char *why;
	int rc;

	if (!copy)
		return 0;
	memcpy(copy, buf, size);
	rc = p15_rec_check(copy, size, &why);
	free(copy);
	return rc == 0;
}

static void test_fixed_sizes(void)
{
	static const struct { unsigned type, size; const char *name; } t[] = {
		{ P15_T_FORK, sizeof(struct p15_fork_v1), "FORK" },
		{ P15_T_EXIT, sizeof(struct p15_exit_v1), "EXIT" },
		{ P15_T_RENAME, sizeof(struct p15_rename_v1), "RENAME" },
		{ P15_T_CLOCK_SYNC, sizeof(struct p15_clock_sync_v1), "CLOCK_SYNC" },
		{ P15_T_STATS, sizeof(struct p15_stats_v1), "STATS" },
		{ P15_T_GAP, sizeof(struct p15_gap_v1), "GAP" },
	};

	for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		char what[96];

		mk(t[i].type, t[i].size);
		snprintf(what, sizeof(what), "%s at its size accepted", t[i].name);
		EXPECT(ok(), what);
		mk(t[i].type, t[i].size + 8);
		snprintf(what, sizeof(what), "%s 8 bytes longer refused", t[i].name);
		EXPECT(!ok(), what);
		mk(t[i].type, t[i].size - 8);
		snprintf(what, sizeof(what), "%s 8 bytes shorter refused", t[i].name);
		EXPECT(!ok(), what);
		snprintf(what, sizeof(what), "%s named", t[i].name);
		EXPECT(!strcmp(p15_type_name(t[i].type), t[i].name), what);
	}
	EXPECT(!strcmp(p15_type_name(P15_T_EXEC), "EXEC") && !strcmp(p15_type_name(P15_T_END), "END"), "var types named");
	EXPECT(!strcmp(p15_type_name(5), "?") && !strcmp(p15_type_name(36), "?"), "unknown types");
	mk(36, 32);
	EXPECT(!ok(), "unknown type refused");
	mk(P15_T_GAP, sizeof(struct p15_gap_v1));
	EXPECT(ok_exact(sizeof(struct p15_gap_v1)), "GAP accepted from a buffer of exactly its size");
	EXPECT(!ok_exact(sizeof(struct p15_gap_v1) - 8), "GAP refused from a buffer 8 bytes short");
	mk(P15_T_STATS, sizeof(struct p15_stats_v1))->version = 2;
	EXPECT(!ok(), "unknown STATS version refused");
}

static void end_with(const char *reason)
{
	size_t rl = strlen(reason);
	struct p15_end *e = (void *)mk(P15_T_END, (sizeof(struct p15_end) + rl + 7) & ~7u);

	e->exit_code = 4;
	e->run_state = 2;
	e->invariant = 2;
	e->signal = 15;
	e->reason_len = rl;
	e->reason_full = rl;
	memcpy(e + 1, reason, rl);
}

static void test_end(void)
{
	struct p15_end *e = (void *)buf;
	char line[512];

	EXPECT(sizeof(struct p15_end) == 56, "END fixed part is 56 bytes");
	end_with("stop requested");                  /* 14 bytes: len 72, 2 bytes of padding */
	EXPECT(e->h.len == 72 && ok(), "END with a reason accepted");
	EXPECT(p15_rec_format(buf, line, sizeof(line)) > 0 &&
	       strstr(line, "END ") && strstr(line, "exit=4 state=2 invariant=2 signal=15 reason=\"stop requested\""),
	       "END formatted");
	end_with("");
	EXPECT(e->h.len == 56 && ok(), "END with an empty reason accepted");
	end_with("stop requested");
	buf[56 + 14] = 'x';
	EXPECT(!ok(), "non-zero padding after the reason refused");
	end_with("stop requested");
	e->h.len = 80;
	EXPECT(!ok(), "slack after the reason refused");
	end_with("stop requested");
	e->reason_len = 17;
	EXPECT(!ok(), "reason past len refused");
	end_with("stop requested");
	e->reason_len = P15_END_REASON_MAX + 1;
	e->h.len = P15_END_MAX_SIZE;
	EXPECT(!ok(), "reason_len above its maximum refused");
	/* above the maximum, though len, tiling and padding would all agree */
	end_with("stop requested");
	e->reason_len = P15_END_REASON_MAX + 8;
	e->h.len = sizeof(struct p15_end) + P15_END_REASON_MAX + 8;
	EXPECT(!ok(), "reason_len above its maximum refused even when it tiles exactly");
	end_with("stop requested");
	EXPECT(ok_exact(72), "END accepted from a buffer of exactly its len");
	EXPECT(!ok_exact(64), "END refused when len is beyond the bytes given");
}

/* EXEC with READ_FAILED may keep slack after its fields (the DYNPTR way), but nothing else gives */
static void test_exec_slack_rules(void)
{
	struct p15_exec *x = (void *)mk(P15_T_EXEC, 80);

	x->h.flags = P15_F_READ_FAILED;
	x->filename_len = 9;
	EXPECT(ok(), "READ_FAILED EXEC with zeroed slack accepted");
	x->h.len = 76;
	EXPECT(!ok(), "len not a multiple of 8 refused, slack or not");
	x->h.len = 72;
	x->filename_len = 9;
	x->argv_len = 4;                       /* 64 + 13 = 77 > 72 */
	EXPECT(!ok(), "fields beyond len refused, slack or not");
	x->h.len = 56;
	x->argv_len = 0;
	x->filename_len = 0;
	EXPECT(!ok_exact(56), "EXEC shorter than its fixed part refused without reading past it");
	x = (void *)mk(P15_T_EXEC, P15_EXEC_MAX_SIZE);
	x->filename_len = P15_EXEC_FILENAME_MAX - 1;
	x->argv_len = P15_EXEC_ARGV_MAX + 1;   /* 64 + 255 + 1025 = 1344: tiles exactly */
	EXPECT(!ok() && P15_EXEC_MAX_SIZE <= sizeof(buf), "argv_len above its maximum refused even when it tiles");
	x->filename_len = P15_EXEC_FILENAME_MAX + 1;
	x->argv_len = P15_EXEC_ARGV_MAX - 1;
	EXPECT(!ok(), "filename_len above its maximum refused even when it tiles");
}

static void test_format(void)
{
	char line[512];
	struct p15_gap *g = (void *)mk(P15_T_GAP, sizeof(struct p15_gap));
	struct p15_stats *st;
	struct p15_clock_sync *c;

	g->from_ns = 10;
	g->to_ns = 20;
	g->spine_seq = 5;
	g->fork_reserve_failed = 1;
	g->exec_reserve_failed = 2;
	g->exit_reserve_failed = 3;
	g->rename_reserve_failed = 4;
	g->fork_build_failed = 5;
	g->exec_build_failed = 6;
	g->exit_build_failed = 7;
	g->rename_build_failed = 8;
	EXPECT(p15_rec_format(buf, line, sizeof(line)) > 0 &&
	       strstr(line, "GAP ") && strstr(line, "from=10 to=20 spine_seq=5 reserve_failed=1/2/3/4 build_failed=5/6/7/8"),
	       "GAP formatted");
	st = (void *)mk(P15_T_STATS, sizeof(struct p15_stats));
	st->run_state = 1;
	st->fork_emitted = 2;
	st->exec_emitted = 3;
	st->fork_drained = 2;
	st->exec_drained = 3;
	st->spine_written = 5;
	st->exit_reserve_failed = 4;
	st->rename_build_failed = 1;
	EXPECT(p15_rec_format(buf, line, sizeof(line)) > 0 &&
	       strstr(line, "STATS ") && strstr(line, "state=1 emitted=5 drained=5 written=5 lost=4+1"), "STATS formatted");
	c = (void *)mk(P15_T_CLOCK_SYNC, sizeof(struct p15_clock_sync));
	c->boottime_ns = 1;
	c->monotonic_ns = 2;
	c->realtime_ns = 3;
	c->read_spread_ns = 4;
	EXPECT(p15_rec_format(buf, line, sizeof(line)) > 0 &&
	       strstr(line, "CLOCK_SYNC ") && strstr(line, "boot=1 mono=2 real=3 spread=4"), "CLOCK_SYNC formatted");
}

int main(void)
{
	test_fixed_sizes();
	test_end();
	test_exec_slack_rules();
	test_format();
	printf("%s: %d failures\n", __FILE__, failures);
	return failures != 0;
}
