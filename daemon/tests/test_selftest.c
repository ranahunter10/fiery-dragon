// SPDX-License-Identifier: MIT
/*
 * Unit tests for the record checks and the self-test evaluation, on synthetic records.
 * No root, no BPF. Run: make test-c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "records.h"
#include "selftest.h"

static int failures;

#define EXPECT(cond, msg) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

enum { D = 100, C = 200, G = 300 };
static const unsigned long long SC = 5000, SG = 6000, SD = 1000;

static void hdr(struct p15_hdr *h, int type, int len, unsigned tgid, unsigned long long start, unsigned long long ts)
{
	memset(h, 0, sizeof(*h));
	h->type = type; h->version = 1; h->len = len; h->tgid = tgid; h->tid = tgid; h->start_ns = start; h->ts_ns = ts;
}

static void add_fork(struct p15_rec_list *l, unsigned by, unsigned long long by_start, unsigned child,
		     unsigned long long cstart, unsigned long long ts)
{
	struct p15_fork r;

	memset(&r, 0, sizeof(r));
	hdr(&r.h, P15_T_FORK, sizeof(r), by, by_start, ts);
	r.child_tgid = child; r.child_tid = child; r.child_start_ns = cstart; r.kind = 1;
	EXPECT(p15_rec_list_add(l, &r, sizeof(r)) == 0, "record list add");
}

static void add_rename(struct p15_rec_list *l, const char *old, const char *new, unsigned long long ts)
{
	struct p15_rename r;

	memset(&r, 0, sizeof(r));
	hdr(&r.h, P15_T_RENAME, sizeof(r), C, SC, ts);
	strncpy(r.old_comm, old, 15);
	strncpy(r.new_comm, new, 15);
	EXPECT(p15_rec_list_add(l, &r, sizeof(r)) == 0, "record list add");
}

/* ring: the size the ring gave the record; 0 = exactly its len (ADR-0017 layer 1) */
static void add_exec(struct p15_rec_list *l, const char *file, const char *argv, int argv_len, unsigned long long ts,
		     size_t ring)
{
	unsigned char buf[P15_EXEC_MAX_SIZE];
	struct p15_exec *r = (void *)buf;
	int fl = strlen(file), len = (sizeof(*r) + fl + argv_len + 7) & ~7;

	memset(buf, 0, sizeof(buf));
	hdr(&r->h, P15_T_EXEC, len, C, SC, ts);
	r->old_tid = C; r->filename_len = fl; r->filename_full = fl; r->argv_len = argv_len; r->argv_full = argv_len;
	memcpy(buf + sizeof(*r), file, fl);
	memcpy(buf + sizeof(*r) + fl, argv, argv_len);
	EXPECT(p15_rec_list_add(l, buf, ring ? ring : (size_t)len) == 0, "record list add");
}

static void add_exit(struct p15_rec_list *l, unsigned tgid, unsigned long long start, int code, unsigned long long ts)
{
	struct p15_exit r;

	memset(&r, 0, sizeof(r));
	hdr(&r.h, P15_T_EXIT, sizeof(r), tgid, start, ts);
	r.exit_code = code; r.group_dead = 1;
	EXPECT(p15_rec_list_add(l, &r, sizeof(r)) == 0, "record list add");
}

/* the record set a correct spine produces, with one knob per failure to inject */
struct knobs { int skip_exec, double_exec, bad_argv, bad_code, other_start, extra_grand, bad_order, invalid,
	       extra_child, double_daemon_fork, ring_max; };

static int run(struct knobs k)
{
	struct p15_rec_list l = { 0 };
	struct p15_selftest_expect e = { .daemon_tgid = D, .child = C, .grandchild = G };
	FILE *null = fopen("/dev/null", "w");
	int failed;

	strcpy(e.daemon_comm, "p15-spine");
	add_fork(&l, D, SD, C, SC, 10);
	if (k.double_daemon_fork)
		add_fork(&l, D, SD, C, SC, 11);
	add_rename(&l, "p15-spine", P15_ST_NAME, 20);
	add_fork(&l, C, SC, G, SG, 30);
	add_exit(&l, G, SG, k.bad_code ? 0 : 7 << 8, 35);
	if (k.extra_grand) {
		add_rename(&l, "x", "y", 36);
		((struct p15_hdr *)l.recs[l.n - 1])->tgid = G;   /* a stray record from the grandchild */
	}
	add_rename(&l, P15_ST_NAME, "true", k.bad_order ? 5 : 40);
	if (!k.skip_exec)
		add_exec(&l, "/bin/true", k.bad_argv ? "true\0fd-selftesX" : "true\0" P15_ST_NAME, 17, 50,
			 k.ring_max ? P15_EXEC_MAX_SIZE : 0);
	if (k.double_exec)
		add_exec(&l, "/bin/true", "true\0" P15_ST_NAME, 17, 55, 0);
	if (k.extra_child)
		add_fork(&l, C, SC, 777, SC, 45);   /* an unexpected extra record from the child */
	add_exit(&l, C, k.other_start ? SC + 1 : SC, 0, 60);
	add_exit(&l, 999, 1, 0, 61);   /* background noise from another process: must be ignored */
	if (k.invalid) {
		struct p15_exit r;

		memset(&r, 0, sizeof(r));
		hdr(&r.h, P15_T_EXIT, 200, C, SC, 70);   /* len beyond the bytes given */
		EXPECT(p15_rec_list_add(&l, &r, sizeof(r)) == 0, "record list add");
	}
	failed = p15_selftest_eval(&l, &e, null);
	fclose(null);
	p15_rec_list_free(&l);
	return failed;
}

static void test_record_checks(void)
{
	struct p15_exit x;
	unsigned char buf[P15_EXEC_MAX_SIZE];
	struct p15_exec *r = (void *)buf;
	const char *why;

	memset(&x, 0, sizeof(x));
	hdr(&x.h, P15_T_EXIT, sizeof(x), 1, 1, 1);
	EXPECT(p15_rec_check(&x, sizeof(x), &why) == 0, "good EXIT accepted");
	EXPECT(p15_rec_check(&x, 16, &why) != 0, "short buffer refused");
	x.h.len = 48;
	EXPECT(p15_rec_check(&x, sizeof(x), &why) != 0, "len beyond buffer refused");
	{
		unsigned char big[48] = { 0 };

		memcpy(big, &x, sizeof(x));
		((struct p15_hdr *)big)->len = 44;   /* above the fixed part, within the buffer, not a multiple of 8 */
		EXPECT(p15_rec_check(big, sizeof(big), &why) != 0, "len not multiple of 8 refused");
	}
	x.h.len = 32;
	EXPECT(p15_rec_check(&x, sizeof(x), &why) != 0, "len shorter than fixed part refused");
	x.h.len = sizeof(x); x.h.version = 9;
	EXPECT(p15_rec_check(&x, sizeof(x), &why) != 0, "unknown version refused");

	memset(buf, 0, sizeof(buf));
	hdr(&r->h, P15_T_EXEC, 80, 1, 1, 1);
	r->filename_len = 10; r->argv_len = 7;
	EXPECT(p15_rec_check(buf, sizeof(buf), &why) != 0, "var fields beyond len refused");
	r->argv_len = 6;
	EXPECT(p15_rec_check(buf, sizeof(buf), &why) == 0, "var fields exactly within len accepted");
	r->argv_len = 2;
	EXPECT(p15_rec_check(buf, sizeof(buf), &why) == 0, "zero bytes after the var fields accepted");
	buf[64 + 10 + 2 + 3] = 'x';   /* a stale byte from an earlier record in the scratch buffer */
	EXPECT(p15_rec_check(buf, sizeof(buf), &why) != 0, "non-zero bytes after the var fields refused");
	buf[64 + 10 + 2 + 3] = 0;
	buf[80] = 'x';                /* beyond len: not the record's business */
	EXPECT(p15_rec_check(buf, sizeof(buf), &why) == 0, "bytes past len ignored");
	buf[80] = 0;
	r->h.len = 88;                /* 8 bytes more than the fields need */
	EXPECT(p15_rec_check(buf, sizeof(buf), &why) != 0, "slack after the fields refused");
	r->h.flags = P15_F_READ_FAILED;
	EXPECT(p15_rec_check(buf, sizeof(buf), &why) == 0, "zeroed slack after a failed read accepted (DYNPTR)");
	buf[84] = 'x';
	EXPECT(p15_rec_check(buf, sizeof(buf), &why) != 0, "non-zero slack after a failed read refused");
	buf[84] = 0; r->h.flags = 0; r->h.len = 80;
	r->argv_len = 6;
	r->argv_len = P15_EXEC_ARGV_MAX + 1; r->h.len = P15_EXEC_MAX_SIZE;
	EXPECT(p15_rec_check(buf, sizeof(buf), &why) != 0, "argv_len above its maximum refused");
}

int main(void)
{
	test_record_checks();
	EXPECT(run((struct knobs){ 0 }) == 0, "correct records pass");
	EXPECT(run((struct knobs){ .skip_exec = 1 }) > 0, "missing EXEC fails");
	EXPECT(run((struct knobs){ .double_exec = 1 }) > 0, "duplicate EXEC fails");
	EXPECT(run((struct knobs){ .bad_argv = 1 }) > 0, "wrong argv fails");
	EXPECT(run((struct knobs){ .bad_code = 1 }) > 0, "wrong grandchild exit code fails");
	EXPECT(run((struct knobs){ .other_start = 1 }) > 0, "a child record with another start_ns fails");
	EXPECT(run((struct knobs){ .extra_grand = 1 }) > 0, "an extra grandchild record fails");
	EXPECT(run((struct knobs){ .bad_order = 1 }) > 0, "out-of-order child records fail");
	EXPECT(run((struct knobs){ .invalid = 1 }) > 0, "an invalid record fails the run");
	EXPECT(run((struct knobs){ .extra_child = 1 }) > 0, "an extra child record fails");
	EXPECT(run((struct knobs){ .double_daemon_fork = 1 }) > 0, "two FORKs of the child fail");
	EXPECT(run((struct knobs){ .ring_max = 1 }) == 1, "an EXEC reserved at its maximum fails exactly one check");
	printf("%s: %d failures\n", __FILE__, failures);
	return failures != 0;
}
