// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * net_probe: attach the ADR-0004 candidate hooks, make known network calls
 * from this process, and check every record against what the calls did.
 * Usage: net_probe (root). Exit 0 only if every check passes.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "net_probe.skel.h"

enum { OP_CONNECT = 1, OP_ACCEPT = 2, OP_LISTEN = 3, OP_BIND = 4, OP_N = 5 };
static const char *opname[] = { "?", "connect", "accept", "listen", "bind" };

struct net_rec {
	unsigned long long cookie, lcookie;
	unsigned char laddr[16], raddr[16];
	int ret;
	unsigned tgid;
	unsigned short op, family, proto, lport, rport, _pad[3];
};

#define MAXR 64
static struct net_rec recs[MAXR];
static int nrec, overflow;
static unsigned me;
static int failed;

static int on_rec(void *ctx, void *data, size_t size)
{
	(void)ctx;
	if (size != sizeof(struct net_rec))
		return 0;
	if (((struct net_rec *)data)->tgid != me)
		return 0;
	if (nrec < MAXR)
		memcpy(&recs[nrec++], data, sizeof(struct net_rec));
	else
		overflow++;
	return 0;
}

static void check(int ok, const char *what)
{
	printf("  %-4s %s\n", ok ? "ok" : "FAIL", what);
	failed += !ok;
}

static void show(const struct net_rec *r)
{
	char l[64], rm[64];

	inet_ntop(r->family, r->laddr, l, sizeof(l));
	inet_ntop(r->family, r->raddr, rm, sizeof(rm));
	printf("    %-7s fam=%-2u proto=%-2u ret=%-4d local=%s:%u remote=%s:%u cookie=%llu lcookie=%llu\n",
	       opname[r->op < OP_N ? r->op : 0], r->family, r->proto, r->ret, l, r->lport, rm, r->rport, r->cookie,
	       r->lcookie);
}

/* The n-th record (from 0) of op `op` within [from, nrec), or NULL. */
static const struct net_rec *find(int from, int op, int n)
{
	for (int i = from; i < nrec; i++)
		if (recs[i].op == op && n-- == 0)
			return &recs[i];
	return NULL;
}

static int count_op(int from, int op)
{
	int c = 0;

	for (int i = from; i < nrec; i++)
		c += recs[i].op == op;
	return c;
}

/* TCP listen/connect/accept over loopback in family `fam`; checks every field the records carry. */
static void tcp_case(struct ring_buffer *rb, int fam)
{
	struct sockaddr_storage ss = { 0 };
	socklen_t sl = fam == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	int from = nrec, ls, cs, as;
	unsigned short lport, cport;
	const struct net_rec *b, *l, *c, *a;
	unsigned char lo[16] = { 0 };

	if (fam == AF_INET) {
		struct sockaddr_in *in = (void *)&ss;

		in->sin_family = AF_INET;
		in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		memcpy(lo, &in->sin_addr, 4);
	} else {
		struct sockaddr_in6 *in6 = (void *)&ss;

		in6->sin6_family = AF_INET6;
		in6->sin6_addr = in6addr_loopback;
		memcpy(lo, &in6addr_loopback, 16);
	}
	ls = socket(fam, SOCK_STREAM, 0);
	if (ls < 0 || bind(ls, (void *)&ss, sl) || listen(ls, 4) || getsockname(ls, (void *)&ss, &sl)) {
		check(0, "TCP listener set up");
		return;
	}
	lport = ntohs(fam == AF_INET ? ((struct sockaddr_in *)&ss)->sin_port : ((struct sockaddr_in6 *)&ss)->sin6_port);
	cs = socket(fam, SOCK_STREAM, 0);
	if (cs < 0 || connect(cs, (void *)&ss, sl) || (as = accept(ls, NULL, NULL)) < 0) {
		check(0, "TCP connect and accept");
		return;
	}
	{
		struct sockaddr_storage cl;
		socklen_t cll = sizeof(cl);

		getsockname(cs, (void *)&cl, &cll);
		cport = ntohs(fam == AF_INET ? ((struct sockaddr_in *)&cl)->sin_port : ((struct sockaddr_in6 *)&cl)->sin6_port);
	}
	ring_buffer__consume(rb);
	printf("TCP over %s: listener port %u, client port %u\n", fam == AF_INET ? "IPv4" : "IPv6", lport, cport);
	for (int i = from; i < nrec; i++)
		show(&recs[i]);
	b = find(from, OP_BIND, 0);
	l = find(from, OP_LISTEN, 0);
	c = find(from, OP_CONNECT, 0);
	a = find(from, OP_ACCEPT, 0);
	check(count_op(from, OP_BIND) == 1 && count_op(from, OP_LISTEN) == 1 && count_op(from, OP_CONNECT) == 1 &&
	      count_op(from, OP_ACCEPT) == 1, "exactly one bind, listen, connect and accept");
	if (!b || !l || !c || !a)
		return;
	check(b->family == fam && b->proto == IPPROTO_TCP && b->ret == 0 && b->lport == lport &&
	      !memcmp(b->laddr, lo, 16), "bind: family, TCP, ret 0, local loopback:port");
	check(l->ret == 0 && l->lport == lport && l->cookie == b->cookie, "listen: ret 0, same port, same socket cookie as bind");
	check(c->ret == 0 && c->rport == lport && !memcmp(c->raddr, lo, 16) && c->lport == cport &&
	      c->cookie != l->cookie, "connect: ret 0, remote = listener, local = the client's port, its own cookie");
	check(a->lport == lport && a->rport == cport && !memcmp(a->raddr, lo, 16) && a->lcookie == l->cookie &&
	      a->cookie != l->cookie && a->cookie != c->cookie,
	      "accept: local = listener port, remote = client, lcookie = the listener, new cookie");
	close(as);
	close(cs);
	close(ls);
}

int main(void)
{
	struct net_probe_bpf *s = net_probe_bpf__open_and_load();
	struct ring_buffer *rb;
	int from;

	if (!s) {
		fprintf(stderr, "load failed: %s\n", strerror(errno));
		return 1;
	}
	if (net_probe_bpf__attach(s)) {
		fprintf(stderr, "attach failed: %s\n", strerror(errno));
		net_probe_bpf__destroy(s);
		return 1;
	}
	me = getpid();
	rb = ring_buffer__new(bpf_map__fd(s->maps.net_rb), on_rec, NULL, NULL);
	printf("net_probe: libbpf %s, 6 programs attached\n", libbpf_version_string());

	tcp_case(rb, AF_INET);
	tcp_case(rb, AF_INET6);

	/* UDP connect: no listener needed */
	{
		struct sockaddr_in in = { .sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
		int u = socket(AF_INET, SOCK_DGRAM, 0);
		const struct net_rec *c;

		from = nrec;
		check(u >= 0 && connect(u, (void *)&in, sizeof(in)) == 0, "UDP connect succeeds");
		ring_buffer__consume(rb);
		c = find(from, OP_CONNECT, 0);
		printf("UDP connect to 127.0.0.1:9\n");
		if (c)
			show(c);
		check(c && c->proto == IPPROTO_UDP && c->ret == 0 && c->rport == 9 && c->lport != 0,
		      "UDP connect: proto UDP, ret 0, remote port 9, local port assigned");
		close(u);
	}
	/* refused connect: nothing listens on the port just closed */
	{
		struct sockaddr_in in = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
		socklen_t sl = sizeof(in);
		int t = socket(AF_INET, SOCK_STREAM, 0), x = socket(AF_INET, SOCK_STREAM, 0), r;
		const struct net_rec *c;

		bind(t, (void *)&in, sizeof(in));
		getsockname(t, (void *)&in, &sl);
		close(t);
		from = nrec;
		r = connect(x, (void *)&in, sizeof(in));
		ring_buffer__consume(rb);
		c = find(from, OP_CONNECT, 0);
		printf("TCP connect to a closed port %u (connect returned %d, errno %d)\n", ntohs(in.sin_port), r, errno);
		if (c)
			show(c);
		check(c && c->ret == -ECONNREFUSED && c->rport == ntohs(in.sin_port), "refused connect: ret -ECONNREFUSED recorded");
		close(x);
	}
	/* non-blocking connect */
	{
		struct sockaddr_in in = { .sin_family = AF_INET, .sin_port = htons(80), .sin_addr.s_addr = inet_addr("192.0.2.1") };
		int x = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
		const struct net_rec *c;

		from = nrec;
		connect(x, (void *)&in, sizeof(in));
		ring_buffer__consume(rb);
		c = find(from, OP_CONNECT, 0);
		printf("non-blocking TCP connect to 192.0.2.1:80 (TEST-NET-1)\n");
		if (c)
			show(c);
		check(c && (c->ret == -EINPROGRESS || c->ret == -ENETUNREACH), "non-blocking connect: ret -EINPROGRESS (or -ENETUNREACH without a route)");
		close(x);
	}
	/* AF_UNIX connect: never reaches the inet proto_ops, so no record (outside ADR-0004 v1) */
	{
		struct sockaddr_un un = { .sun_family = AF_UNIX };
		int x = socket(AF_UNIX, SOCK_STREAM, 0);

		snprintf(un.sun_path, sizeof(un.sun_path), "/nonexistent/p15-net-probe");
		from = nrec;
		connect(x, (void *)&un, sizeof(un));
		ring_buffer__consume(rb);
		check(nrec == from, "AF_UNIX connect: no record (unix sockets are outside these hooks)");
		close(x);
	}
	check(overflow == 0, "no record lost by this probe's buffer");
	{
		int ncpu = libbpf_num_possible_cpus();
		unsigned long long vals[512];

		printf("counters:  op       seen  emitted  excluded  reserve_failed\n");
		for (int op = 1; op < OP_N; op++) {
			unsigned long long v[4] = { 0 };

			for (int kd = 0; kd < 4; kd++) {
				__u32 k = op * 4 + kd;

				if (ncpu > 0 && ncpu <= 512 && !bpf_map_lookup_elem(bpf_map__fd(s->maps.net_ctr), &k, vals))
					for (int i = 0; i < ncpu; i++)
						v[kd] += vals[i];
			}
			printf("           %-7s %6llu %8llu %9llu %15llu\n", opname[op], v[0], v[1], v[2], v[3]);
			check(v[0] == v[1] + v[2] + v[3], "  ... seen = emitted + excluded + reserve_failed");
		}
	}
	printf("net_probe: %s (%d failed checks)\n", failed ? "FAIL" : "PASS", failed);
	ring_buffer__free(rb);
	net_probe_bpf__destroy(s);
	return failed != 0;
}
