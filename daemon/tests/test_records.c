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

static unsigned char buf[8192];

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
		{ P15_T_NET, sizeof(struct p15_net_v1), "NET" },
		{ P15_T_NET_STATS, sizeof(struct p15_net_stats_v1), "NET_STATS" },
	};
	struct p15_snap_done_v1 *sd;

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
	EXPECT(!strcmp(p15_type_name(41), "?") && !strcmp(p15_type_name(99), "?"), "unknown types");
	EXPECT(!strcmp(p15_type_name(P15_T_PROC), "PROC") && !strcmp(p15_type_name(P15_T_SNAP_DONE), "SNAP_DONE"),
	       "snapshot types named");
	mk(99, 32);
	EXPECT(!ok(), "unknown type refused");
	sd = (void *)mk(P15_T_SNAP_DONE, sizeof(struct p15_snap_done_v1));
	sd->kind = 1;
	EXPECT(ok(), "SNAP_DONE at its size accepted");
	sd->kind = 0;
	EXPECT(!ok(), "SNAP_DONE with an unknown kind refused");
	sd->kind = 2;
	sd->h.len += 8;
	EXPECT(!ok(), "SNAP_DONE 8 bytes longer refused");
	{   /* a PROC v1 record (old WALs) still validates; argv over its maximum is refused via the v1 branch */
		struct p15_proc_v1 *pr = (void *)mk(P15_T_PROC, sizeof(struct p15_proc_v1));

		pr->kind = 1;
		EXPECT(ok(), "PROC v1 at its size accepted");
		pr->argv_len = P15_PROC_V1_ARGV_MAX + 1;   /* tiles exactly, so only the bound catches it */
		pr->h.len = (sizeof(*pr) + pr->argv_len + 7) & ~7u;
		EXPECT(pr->h.len <= sizeof(buf) && !ok(), "PROC v1 argv_len above its maximum refused even when it tiles");
	}
	mk(P15_T_GAP, sizeof(struct p15_gap_v1));
	EXPECT(ok_exact(sizeof(struct p15_gap_v1)), "GAP accepted from a buffer of exactly its size");
	EXPECT(!ok_exact(sizeof(struct p15_gap_v1) - 8), "GAP refused from a buffer 8 bytes short");
	mk(P15_T_STATS, sizeof(struct p15_stats_v2))->version = 3;
	EXPECT(!ok(), "unknown STATS version refused");
	/* version 2 of STATS, GAP and NET_STATS (ADR-0020): accepted at their own size only */
	{
		static const struct { unsigned type, size, v1; const char *name; } t2[] = {
			{ P15_T_STATS, sizeof(struct p15_stats_v2), sizeof(struct p15_stats_v1), "STATS v2" },
			{ P15_T_GAP, sizeof(struct p15_gap_v2), sizeof(struct p15_gap_v1), "GAP v2" },
			{ P15_T_NET_STATS, sizeof(struct p15_net_stats_v2), sizeof(struct p15_net_stats_v1), "NET_STATS v2" },
		};

		for (size_t i = 0; i < sizeof(t2) / sizeof(t2[0]); i++) {
			char what[96];

			mk(t2[i].type, t2[i].size)->version = 2;
			snprintf(what, sizeof(what), "%s at its size accepted", t2[i].name);
			EXPECT(ok(), what);
			mk(t2[i].type, t2[i].v1)->version = 2;
			snprintf(what, sizeof(what), "%s at the v1 size refused", t2[i].name);
			EXPECT(!ok(), what);
		}
	}
}

static void end_with(const char *reason)
{
	size_t rl = strlen(reason);
	struct p15_end_v1 *e = (void *)mk(P15_T_END, (sizeof(struct p15_end_v1) + rl + 7) & ~7u);

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
	struct p15_end_v1 *e = (void *)buf;
	char line[512];

	EXPECT(sizeof(struct p15_end_v1) == 56, "END fixed part is 56 bytes");
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
	e->h.len = sizeof(struct p15_end_v1) + P15_END_REASON_MAX + 8;
	EXPECT(!ok(), "reason_len above its maximum refused even when it tiles exactly");
	end_with("stop requested");
	EXPECT(ok_exact(72), "END accepted from a buffer of exactly its len");
	EXPECT(!ok_exact(64), "END refused when len is beyond the bytes given");
}

/* END v2 (ADR-0023 rule 1): closing_snapshot and reserved before the reason */
static void test_end_v2(void)
{
	struct p15_end_v2 *e;
	char line[512];

	EXPECT(sizeof(struct p15_end_v2) == 64, "END v2 fixed part is 64 bytes");
	e = (void *)mk(P15_T_END, sizeof(struct p15_end_v2) + 16);
	e->h.version = 2;
	e->closing_snapshot = 1;
	e->reason_len = e->reason_full = 14;
	memcpy(e + 1, "stop requested", 14);
	EXPECT(ok(), "END v2 accepted");
	EXPECT(p15_rec_format(buf, line, sizeof(line)) > 0 && strstr(line, "closing_snapshot=1 reason=\"stop requested\""),
	       "END v2 formats closing_snapshot before the reason");
	e->reserved = 1;
	EXPECT(!ok(), "END v2: non-zero reserved refused");
	e->reserved = 0;
	e->h.version = 1;
	EXPECT(!ok(), "an END v2 read as v1 does not check (its reason is elsewhere)");
	e->h.version = 3;
	EXPECT(!ok(), "unknown END version refused");
}

/* EXEC v1 with READ_FAILED may keep slack after its fields, but nothing else gives. This exercises
 * the generic tail/slack rules on the v1 layout, which the checker must still accept (old WALs). */
static void test_exec_slack_rules(void)
{
	const unsigned f1 = sizeof(struct p15_exec_v1);
	struct p15_exec_v1 *x = (void *)mk(P15_T_EXEC, 80);

	x->h.flags = P15_F_READ_FAILED;
	x->filename_len = 9;
	EXPECT(ok(), "READ_FAILED EXEC with zeroed slack accepted");
	x->h.len = 76;
	EXPECT(!ok(), "len not a multiple of 8 refused, slack or not");
	x->h.len = 72;
	x->filename_len = 9;
	x->argv_len = 4;                       /* f1 + 13 > 72 */
	EXPECT(!ok(), "fields beyond len refused, slack or not");
	x->h.len = 56;
	x->argv_len = 0;
	x->filename_len = 0;
	EXPECT(!ok_exact(56), "EXEC shorter than its fixed part refused without reading past it");
	x = (void *)mk(P15_T_EXEC, f1 + (P15_EXEC_V1_FILENAME_MAX - 1) + (P15_EXEC_V1_ARGV_MAX + 1));
	x->filename_len = P15_EXEC_V1_FILENAME_MAX - 1;
	x->argv_len = P15_EXEC_V1_ARGV_MAX + 1; /* tiles exactly, yet argv_len is one past its maximum */
	EXPECT(!ok() && x->h.len <= sizeof(buf), "argv_len above its maximum refused even when it tiles");
	x->filename_len = P15_EXEC_V1_FILENAME_MAX + 1;
	x->argv_len = P15_EXEC_V1_ARGV_MAX - 1;
	EXPECT(!ok(), "filename_len above its maximum refused even when it tiles");
}

/* EXEC v2 (ADR-0025): the three var fields (filename, argv, exe_name) and the provenance format. */
static void test_exec_v2(void)
{
	struct p15_exec_v2 *x;
	const unsigned f2 = sizeof(struct p15_exec_v2);
	char line[800];

	x = (void *)mk(P15_T_EXEC, (f2 + 9 + 6 + 4 + 7) & ~7u);
	x->h.version = 2;
	x->filename_len = x->filename_full = 9;
	x->argv_len = x->argv_full = 6;
	x->exe_name_len = x->exe_name_full = 4;
	memcpy(buf + f2, "/bin/true", 9);
	memcpy(buf + f2 + 9, "true\0", 6);
	memcpy(buf + f2 + 9 + 6, "true", 4);
	x->exe_nlink = 0;                      /* an in-memory / deleted backing */
	x->exe_fs_magic = 0x01021994;          /* tmpfs */
	x->stdin_mode = 0140666;               /* a socket on stdin */
	EXPECT(ok(), "a well-formed EXEC v2 is accepted");
	EXPECT(p15_rec_format(buf, line, sizeof(line)) > 0 && strstr(line, "name=\"true\"") && strstr(line, "nlink=0") &&
	       strstr(line, "fsmagic=0x1021994") && strstr(line, "stdin=0:0140666"),
	       "EXEC v2 formats exe_name, nlink, fsmagic and a socket stdin");
	x->exe_name_len = P15_EXEC_V2_EXE_NAME_MAX + 1;
	EXPECT(!ok(), "exe_name_len above its maximum refused");
	x->exe_name_len = x->exe_name_full = 4;
	x->h.len += 8;                         /* slack past the three fields */
	EXPECT(!ok(), "slack after EXEC v2's fields refused");
	/* exe_name one past its maximum, but the record tiles exactly: only the bound catches it */
	x = (void *)mk(P15_T_EXEC, (f2 + P15_EXEC_V2_EXE_NAME_MAX + 1 + 7) & ~7u);
	x->h.version = 2;
	x->filename_len = x->filename_full = 0;
	x->argv_len = x->argv_full = 0;
	x->exe_name_len = x->exe_name_full = P15_EXEC_V2_EXE_NAME_MAX + 1;
	EXPECT(!ok(), "exe_name_len above its maximum refused even when the record tiles exactly");
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

static void test_net_format(void)
{
	struct p15_net *r = (void *)mk(P15_T_NET, sizeof(struct p15_net));
	char line[400];

	r->op = 2;
	r->proto = 6;
	r->family = 2;
	r->ret = 0;
	memcpy(r->laddr, "\x7f\x00\x00\x01", 4);
	memcpy(r->raddr, "\x0a\x00\x00\x05", 4);
	r->lport = 8080;
	r->rport = 41000;
	r->sock_cookie = 3;
	r->peer_cookie = 1;
	r->netns = 4026531840u;
	EXPECT(ok(), "NET accepted");
	p15_rec_format(r, line, sizeof(line));
	EXPECT(strstr(line, "op=ACCEPT proto=tcp ret=0 local=127.0.0.1:8080 remote=10.0.0.5:41000 cookie=3 peer=1 netns=4026531840") != NULL,
	       "NET formatted: op, endpoints, cookies, netns");
	r->family = 10;
	memset(r->laddr, 0, 16);
	r->laddr[15] = 1;
	p15_rec_format(r, line, sizeof(line));
	EXPECT(strstr(line, "local=[::1]:8080") != NULL, "IPv6 endpoints in brackets");
}

/* NET v2 (ADR-0022): the client ISN, its flag, and the bytes around it */
static void test_net_v2(void)
{
	struct p15_net_v2 *r;
	char line[400];

	r = (void *)mk(P15_T_NET, sizeof(struct p15_net_v2));
	r->h.version = 2;
	r->op = 1;
	r->proto = 6;
	r->family = 2;
	EXPECT(ok(), "NET v2 without an ISN accepted");
	r->tcp_isn = 0x9abcdef0u;
	EXPECT(!ok(), "NET v2: tcp_isn without P15_F_ISN refused");
	r->h.flags |= P15_F_ISN;
	EXPECT(ok(), "NET v2 with P15_F_ISN and an ISN accepted");
	r->tcp_isn = 0;
	EXPECT(ok(), "NET v2 with P15_F_ISN and ISN 0 accepted (0 is a valid ISN)");
	r->tcp_isn = 0x9abcdef0u;
	p15_rec_format(r, line, sizeof(line));
	EXPECT(strstr(line, " isn=2596069104") != NULL, "NET v2 formats its ISN");
	r->reserved = 1;
	EXPECT(!ok(), "NET v2: non-zero reserved refused");
	r->reserved = 0;
	r->h.flags |= 1u << 7;
	EXPECT(!ok(), "unknown flag bit refused");

	r = (void *)mk(P15_T_NET, sizeof(struct p15_net_v1));
	r->h.flags = P15_F_ISN;
	EXPECT(!ok(), "P15_F_ISN on a NET v1 refused");
	r->h.flags = 0;
	EXPECT(ok(), "NET v1 still accepted");
	p15_rec_format(r, line, sizeof(line));
	EXPECT(strstr(line, "isn=") == NULL, "NET v1 prints no ISN");
	mk(P15_T_EXIT, sizeof(struct p15_exit_v1))->flags = P15_F_ISN;
	EXPECT(!ok(), "P15_F_ISN on an EXIT refused");
	r = (void *)mk(P15_T_NET, sizeof(struct p15_net_v1));
	r->h.version = 2;
	r->h.len = sizeof(struct p15_net_v2) + 8;
	EXPECT(!ok(), "NET v2 longer than its fixed size refused");
}

static const char *why_of(void)
{
	const char *why = NULL;

	return p15_rec_check(buf, sizeof(buf), &why) ? why : "accepted";
}

#define WHY(msg, want) do { const char *w_ = why_of(); if (strcmp(w_, want)) { \
	printf("FAIL %s:%d %s: got \"%s\"\n", __FILE__, __LINE__, msg, w_); failures++; } } while (0)

/* An OPEN with optional facts and a path, laid out as file.bpf.c builds it. */
static struct p15_open_v1 *mk_open(__u32 fflags, int facts, const char *path)
{
	size_t plen = strlen(path), fl = facts ? sizeof(struct p15_part_objfacts) : 0;
	struct p15_open_v1 *r = (void *)mk(P15_T_OPEN, (unsigned)((sizeof(*r) + fl + plen + 7) & ~7ul));
	struct p15_part_objfacts *f = (void *)(r + 1);

	r->fid = 2;
	r->obj = 1;
	r->fflags = fflags;
	r->facts_len = r->facts_full = (__u16)fl;
	if (facts) {
		f->ino = 42;
		f->seen = 1;
	}
	r->path_len = r->path_full = (__u16)plen;
	memcpy((__u8 *)(r + 1) + fl, path, plen);
	return r;
}

/* OPEN, OPEN_VERDICT, BACKING, CLOSE, FD: the rules and wording of python/p15/records.py. */
static void test_file_records(void)
{
	struct p15_open_v1 *o;
	struct p15_part_objfacts *f;
	struct p15_backing_v1 *b;
	struct p15_fd_v1 *d;
	char line[2048];

	o = mk_open(P15_FF_OBJ_NEW, 1, "/var/tmp/f1");
	WHY("OPEN with facts and a path", "accepted");
	p15_rec_format(buf, line, sizeof(line));
	EXPECT(strstr(line, "OPEN ") && strstr(line, "path=\"/var/tmp/f1\"(11)") && strstr(line, "ino=42"), "OPEN formatted");
	mk_open(0, 0, "/var/tmp/f1");
	WHY("OPEN without facts", "accepted");
	mk_open(0, 1, "/x");
	WHY("facts without OBJ_NEW", "OPEN: facts present without its flag, or its flag without it");
	mk_open(P15_FF_OBJ_NEW, 0, "/x");
	WHY("OBJ_NEW without facts", "OPEN: facts present without its flag, or its flag without it");
	o = mk_open(P15_FF_OBJ_NEW, 1, "/x");
	o->facts_full = 0;
	WHY("facts _full differs", "OPEN: facts is neither absent nor a whole OBJFACTS");
	o = mk_open(P15_FF_OBJ_NEW, 1, "/x");
	f = (void *)(o + 1);
	f->oflags = 2;
	WHY("unknown oflags", "OBJFACTS: unknown oflags bits or an unknown 'seen'");
	f->oflags = 0;
	f->seen = 0;
	WHY("seen 0", "OBJFACTS: unknown oflags bits or an unknown 'seen'");
	mk_open(1u << 7, 0, "/x");
	WHY("unknown fflags", "OPEN: fflags bits this record never carries");
	o = mk_open(0, 0, "/x");
	o->verdict = -13;
	WHY("verdict on a fentry OPEN", "OPEN: a verdict on an OPEN the fentry wrote (a denial is OPEN_VERDICT)");
	o = mk_open(P15_FF_PATH_MISSING, 0, "");
	o->verdict = -13;
	WHY("PATH_MISSING with its verdict", "accepted");
	o = mk_open(0, 0, "/x");
	o->path_err = -22;
	WHY("path_err without the flag", "OPEN: path_err without PATH_ERROR, or PATH_ERROR without path_err");
	o = mk_open(P15_FF_PATH_ERROR, 0, "");
	o->path_err = -22;
	WHY("PATH_ERROR with path_err", "accepted");
	o = mk_open(P15_FF_FULL_SIZE, 0, "/a");
	o->h.len = P15_OPEN_V1_MAX_SIZE;
	WHY("full-size OPEN, zero slack", "accepted");
	EXPECT(ok_exact(P15_OPEN_V1_MAX_SIZE), "full-size OPEN read within its bytes");
	buf[P15_OPEN_V1_MAX_SIZE - 1] = 1;
	WHY("full-size OPEN, dirty slack", "non-zero bytes after the variable fields");
	o = mk_open(0, 0, "/a");
	o->h.len = P15_OPEN_V1_MAX_SIZE;
	WHY("slack without FULL_SIZE", "len larger than its fields need");
	o = mk_open(0, 0, "/abc");
	o->path_len = 300;
	WHY("path beyond len", "variable field beyond len");
	o = mk_open(P15_FF_OBJ_NEW, 1, "/x");
	o->facts_len = o->facts_full = 24;
	WHY("facts of 24 bytes", "OPEN: facts is neither absent nor a whole OBJFACTS");
	o = mk_open(P15_FF_FULL_SIZE, 0, "/a");
	o->h.len = P15_OPEN_V1_MAX_SIZE - 8;
	WHY("FULL_SIZE below the maximum size", "len larger than its fields need");
	o = mk_open(P15_FF_OBJ_NEW, 1, "");
	o->h.len = sizeof(*o) + 32;             /* the facts end 8 bytes past len */
	EXPECT(!ok_exact(o->h.len), "facts past len refused before they are read (ASan: no read past the bytes)");

	mk(P15_T_OPEN_VERDICT, sizeof(struct p15_open_verdict_v1));
	WHY("OPEN_VERDICT 0", "OPEN_VERDICT: the verdict is not a denial");
	((struct p15_open_verdict_v1 *)buf)->verdict = -13;
	WHY("OPEN_VERDICT -13", "accepted");

	b = (void *)mk(P15_T_BACKING, sizeof(*b) + sizeof(*f));
	b->fflags = P15_FF_USER_OBJ_NEW;
	b->user_facts_len = b->user_facts_full = sizeof(*f);
	((struct p15_part_objfacts *)(b + 1))->seen = 1;
	WHY("BACKING with the overlay facts only", "accepted");
	b->fflags = P15_FF_OBJ_NEW;
	WHY("BACKING facts flag mismatch", "BACKING: facts present without its flag, or its flag without it");

	mk(P15_T_CLOSE, sizeof(struct p15_close_v1));
	((struct p15_close_v1 *)buf)->fflags = P15_FF_NEVER_OPENED | P15_FF_KTHREAD;
	WHY("CLOSE NEVER_OPENED KTHREAD", "accepted");
	((struct p15_close_v1 *)buf)->fflags = P15_FF_OBJ_NEW;
	WHY("CLOSE OBJ_NEW", "CLOSE: fflags bits this record never carries");

	d = (void *)mk(P15_T_FD, sizeof(*d) + sizeof(*f) + 8);
	d->facts_len = d->facts_full = sizeof(*f);
	((struct p15_part_objfacts *)(d + 1))->seen = 2;
	d->path_len = d->path_full = 8;
	memcpy((__u8 *)(d + 1) + sizeof(*f), "/dev/pts", 8);
	WHY("FD with facts and path", "accepted");
	d->facts_len = d->facts_full = 0;
	d->h.len = sizeof(*d) + 8;
	memmove((__u8 *)(d + 1), "/dev/pts", 8);
	WHY("FD without facts", "FD: facts present without its flag, or its flag without it");

	EXPECT(p15_is_file_type(P15_T_OPEN) && p15_is_file_type(P15_T_CLOSE) && !p15_is_file_type(P15_T_FD) &&
	       !p15_is_file_type(P15_T_NET), "the bulk ring's file types");
}

int main(void)
{
	test_file_records();
	test_fixed_sizes();
	test_end();
	test_exec_slack_rules();
	test_exec_v2();
	test_format();
	test_net_format();
	test_net_v2();
	test_end_v2();
	printf("%s: %d failures\n", __FILE__, failures);
	return failures != 0;
}
