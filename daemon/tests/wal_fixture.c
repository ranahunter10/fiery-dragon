// SPDX-License-Identifier: MIT
/*
 * wal_fixture: write a small P15W run with one or more records of every type, through the C
 * writer (daemon/wal.c), so the Python reader's test (python/tests/it_wal_c.py) can check
 * that it decodes exactly what C wrote. The values are fixed; the test knows them.
 *
 *   wal_fixture RUN_DIR      (RUN_DIR must exist and hold no segments)
 *
 * Rotation is forced (1 KiB segments), so the run has several segments and the sequence
 * crosses segment boundaries.
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "p15_records.h"
#include "wal.h"

static void hdr(struct p15_hdr *h, __u16 type, __u16 len, __u64 ts, __u32 tgid, __u64 start)
{
	memset(h, 0, sizeof(*h));
	h->type = type;
	h->version = 1;
	h->len = len;
	h->ts_ns = ts;
	h->tgid = tgid;
	h->tid = tgid;
	h->start_ns = start;
}

static int put(struct p15w *w, unsigned ring, const void *rec)
{
	const struct p15_hdr *h = rec;

	return p15w_append(w, ring, 1, rec, h->len);
}

int main(int argc, char **argv)
{
	static const struct p15w_kv meta[] = {
		{ "run.id", "20261102T000000Z-fixture0" },
		{ "boot_id", "00000000-0000-4000-8000-000000000001" },
		{ "schema.hash", P15_SCHEMA_HASH },
		{ "hostname", "fixture" },
	};
	struct p15w_opts o = { .dir = argc > 1 ? argv[1] : NULL, .max_bytes = 1024, .meta = meta,
			       .nmeta = sizeof(meta) / sizeof(meta[0]) };
	struct p15w *w;
	int rc = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: wal_fixture RUN_DIR\n");
		return 2;
	}
	if (p15w_open(&w, &o)) {
		perror("p15w_open");
		return 1;
	}
	{       /* spine: process 100 forks 200, 200 execs, renames, exits */
		struct p15_fork_v1 f;
		struct p15_rename_v1 rn;
		struct p15_exit_v1 x;
		union { struct p15_exec_v1 e; unsigned char b[sizeof(struct p15_exec_v1) + 32]; } ex;
		static const char fname[] = "/bin/sh";            /* 7 bytes, no NUL */
		static const char av[] = "sh\0-c\0id";            /* 8 bytes */

		hdr(&f.h, P15_T_FORK, sizeof(f), 1000, 100, 50);
		f.child_start_ns = 990;
		f.child_task_start_ns = 990;
		f.child_tgid = 200;
		f.child_tid = 200;
		f.kind = 1;
		memset(f._pad, 0, sizeof(f._pad));
		rc |= put(w, 0, &f);

		memset(&ex, 0, sizeof(ex));
		hdr(&ex.e.h, P15_T_EXEC, (sizeof(ex.e) + 7 + 8 + 7) & ~7u, 2000, 200, 990);
		ex.e.exe_ino = 4242;
		ex.e.exe_dev = (8u << 20) | 1u;                   /* kernel encoding of 8:1 */
		ex.e.exe_gen = 7;
		ex.e.old_tid = 200;
		ex.e.filename_full = 7;
		ex.e.filename_len = 7;
		ex.e.argv_full = 8;
		ex.e.argv_len = 8;
		memcpy(ex.b + sizeof(ex.e), fname, 7);
		memcpy(ex.b + sizeof(ex.e) + 7, av, 8);
		rc |= put(w, 0, &ex);

		hdr(&rn.h, P15_T_RENAME, sizeof(rn), 2001, 200, 990);
		memset(rn.old_comm, 0, 16);
		memset(rn.new_comm, 0, 16);
		strcpy(rn.old_comm, "bash");
		strcpy(rn.new_comm, "sh");
		rc |= put(w, 0, &rn);

		hdr(&x.h, P15_T_EXIT, sizeof(x), 9000, 200, 990);
		x.exit_code = 256;
		x.group_dead = 1;
		rc |= put(w, 0, &x);
	}
	{       /* bulk: an IPv4 connect and an IPv6 accept */
		struct p15_net_v1 n;

		memset(&n, 0, sizeof(n));
		hdr(&n.h, P15_T_NET, sizeof(n), 3000, 200, 990);
		n.sock_cookie = 4105;
		inet_pton(AF_INET, "127.0.0.1", n.laddr);
		inet_pton(AF_INET, "10.0.0.0", n.raddr);  /* trailing zero bytes: the reader must keep them */
		n.netns = 4026531840u;
		n.ret = -111;
		n.op = 1;
		n.family = AF_INET;
		n.proto = 6;
		n.lport = 41508;
		n.rport = 4444;
		rc |= put(w, 1, &n);

		memset(&n, 0, sizeof(n));
		hdr(&n.h, P15_T_NET, sizeof(n), 3001, 100, 50);
		n.sock_cookie = 4106;
		n.peer_cookie = 4105;
		inet_pton(AF_INET6, "::1", n.laddr);
		inet_pton(AF_INET6, "fe80::1", n.raddr);
		n.netns = 4026531840u;
		n.op = 2;
		n.family = AF_INET6;
		n.proto = 6;
		n.lport = 8080;
		n.rport = 50000;
		rc |= put(w, 1, &n);
	}
	{       /* daemon: CLOCK_SYNC, STATS, NET_STATS, GAP, END */
		struct p15_clock_sync_v1 c;
		struct p15_stats_v1 s;
		struct p15_net_stats_v1 ns;
		struct p15_gap_v1 g;
		union { struct p15_end_v1 e; unsigned char b[sizeof(struct p15_end_v1) + 16]; } end;
		__u64 *u;
		size_t nu;

		hdr(&c.h, P15_T_CLOCK_SYNC, sizeof(c), 500, 1, 1);
		c.boottime_ns = 500;
		c.monotonic_ns = 400;
		c.realtime_ns = 1793577600000000000ull;   /* 2026-11-02T00:00:00Z */
		c.read_spread_ns = 3;
		rc |= put(w, 2, &c);

		memset(&s, 0, sizeof(s));
		hdr(&s.h, P15_T_STATS, sizeof(s), 5000, 1, 1);
		u = (__u64 *)((unsigned char *)&s + sizeof(s.h));
		nu = (offsetof(struct p15_stats_v1, spine_ring_bytes) - sizeof(s.h)) / 8;
		for (size_t i = 0; i < nu; i++)
			u[i] = 1000 + i;                      /* every u64 field: 1000 + its index */
		s.spine_ring_bytes = 4194304;
		s.queue_depth_max = 3;
		s.queue_batches = 64;
		s.run_state = 1;
		rc |= put(w, 2, &s);

		memset(&ns, 0, sizeof(ns));
		hdr(&ns.h, P15_T_NET_STATS, sizeof(ns), 5000, 1, 1);
		u = (__u64 *)((unsigned char *)&ns + sizeof(ns.h));
		for (size_t i = 0; i < 9; i++)
			u[i] = 2000 + i;
		ns.bulk_ring_bytes = 4194304;
		rc |= put(w, 2, &ns);

		hdr(&g.h, P15_T_GAP, sizeof(g), 6000, 1, 1);
		g.from_ns = 5500;
		g.to_ns = 6000;
		g.spine_seq = 4;
		g.fork_reserve_failed = 1;
		g.exec_reserve_failed = 2;
		g.exit_reserve_failed = 3;
		g.rename_reserve_failed = 4;
		g.fork_build_failed = 5;
		g.exec_build_failed = 6;
		g.exit_build_failed = 7;
		g.rename_build_failed = 8;
		rc |= put(w, 2, &g);

		memset(&end, 0, sizeof(end));
		hdr(&end.e.h, P15_T_END, (sizeof(end.e) + 14 + 7) & ~7u, 9999, 1, 1);
		end.e.exit_code = 3;
		end.e.run_state = 1;
		end.e.invariant = 1;
		end.e.signal = 15;
		end.e.reason_full = 14;
		end.e.reason_len = 14;
		memcpy(end.b + sizeof(end.e), "stop requested", 14);
		rc |= put(w, 2, &end);
	}
	if (rc) {
		fprintf(stderr, "wal_fixture: an append failed\n");
		return 1;
	}
	if (p15w_close(w)) {
		fprintf(stderr, "wal_fixture: close failed\n");
		return 1;
	}
	return 0;
}
