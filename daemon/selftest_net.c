// SPDX-License-Identifier: MIT
/* The network-intent self-test (ADR-0004 rule 6). See selftest_net.h. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "p15_records.h"
#include "records.h"
#include "selftest_net.h"

#define MAXR 32

enum { CONNECT = 1, ACCEPT = 2, LISTEN = 3, BIND = 4, TCP = 6, UDP = 17 };

struct coll {
	struct p15_net r[MAXR];
	int n, other, invalid;
	unsigned me;
	unsigned long long total;   /* every record taken from the ring */
};

static int on_rec(void *ctx, void *data, size_t size)
{
	struct coll *c = ctx;
	const struct p15_hdr *h = data;
	const char *why;

	c->total++;
	if (p15_rec_check(data, size, &why) || h->type != P15_T_NET) {
		c->invalid++;
		return 0;
	}
	if (h->tgid != c->me) {
		c->other++;                 /* someone else's network activity during the test: ignored */
		return 0;
	}
	if (c->n < MAXR)
		memcpy(&c->r[c->n++], data, sizeof(struct p15_net));
	return 0;
}

static const struct p15_net *find(const struct coll *c, int op, int proto, int nth)
{
	for (int i = 0; i < c->n; i++)
		if (c->r[i].op == op && c->r[i].proto == proto && nth-- == 0)
			return &c->r[i];
	return NULL;
}

static int count(const struct coll *c, int op, int proto)
{
	int k = 0;

	for (int i = 0; i < c->n; i++)
		k += c->r[i].op == op && c->r[i].proto == proto;
	return k;
}

static int check(FILE *log, int ok, const char *what)
{
	fprintf(log, "  %-4s net: %s\n", ok ? "ok" : "FAIL", what);
	return !ok;
}

int p15_selftest_net(int bulk_rb_fd, FILE *log, unsigned long long *consumed)
{
	struct coll c;
	struct ring_buffer *rb;
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) }, cl;
	socklen_t al = sizeof(a), cll = sizeof(cl);
	unsigned char lo[16] = { 127, 0, 0, 1 };
	int ls = -1, cs = -1, as = -1, us = -1, failed = 0, rc = 0;
	unsigned short port, cport;
	const struct p15_net *b, *l, *t, *x, *u;

	memset(&c, 0, sizeof(c));
	c.me = (unsigned)getpid();
	rb = ring_buffer__new(bulk_rb_fd, on_rec, &c, NULL);
	if (!rb)
		return -errno;
	ring_buffer__consume(rb);           /* forget records from before the test */
	c.n = c.other = c.invalid = 0;
	ls = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	cs = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	us = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (ls < 0 || cs < 0 || us < 0 || bind(ls, (void *)&a, sizeof(a)) || listen(ls, 4) ||
	    getsockname(ls, (void *)&a, &al) || connect(cs, (void *)&a, sizeof(a)) ||
	    (as = accept(ls, NULL, NULL)) < 0 || getsockname(cs, (void *)&cl, &cll)) {
		rc = -errno;
		goto out;
	}
	port = ntohs(a.sin_port);
	cport = ntohs(cl.sin_port);
	{
		struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };

		if (connect(us, (void *)&d, sizeof(d))) {
			rc = -errno;
			goto out;
		}
	}
	for (int i = 0; i < 5; i++)
		ring_buffer__poll(rb, 20);
	ring_buffer__consume(rb);            /* records don't wake the reader below the high-water mark (ADR-0020) */
	b = find(&c, BIND, TCP, 0);
	l = find(&c, LISTEN, TCP, 0);
	t = find(&c, CONNECT, TCP, 0);
	x = find(&c, ACCEPT, TCP, 0);
	u = find(&c, CONNECT, UDP, 0);
	fprintf(log, "selftest net: listener 127.0.0.1:%u, client port %u; %d own records, %d of other processes, %d invalid\n",
		port, cport, c.n, c.other, c.invalid);
	failed += check(log, c.invalid == 0, "every record passes the checks");
	failed += check(log, count(&c, BIND, TCP) == 1 && count(&c, LISTEN, TCP) == 1 && count(&c, CONNECT, TCP) == 1 &&
			     count(&c, ACCEPT, TCP) == 1 && count(&c, CONNECT, UDP) == 1,
			"exactly one TCP bind, listen, connect, accept and one UDP connect");
	if (!b || !l || !t || !x || !u) {
		failed++;
		goto out;
	}
	failed += check(log, b->ret == 0 && b->lport == port && !memcmp(b->laddr, lo, 4) && b->family == 2,
			"bind: ret 0, local 127.0.0.1:port");
	failed += check(log, l->ret == 0 && l->lport == port && l->sock_cookie == b->sock_cookie && l->sock_cookie,
			"listen: ret 0, the bound port, the same socket cookie");
	failed += check(log, t->ret == 0 && t->rport == port && !memcmp(t->raddr, lo, 4) && t->lport == cport &&
			     t->sock_cookie && t->sock_cookie != l->sock_cookie,
			"connect: ret 0, remote = the listener, local = the client's port, its own cookie");
	failed += check(log, x->lport == port && x->rport == cport && x->peer_cookie == l->sock_cookie &&
			     x->sock_cookie && x->sock_cookie != t->sock_cookie,
			"accept: listener port, remote = the client, peer_cookie = the listener's cookie");
	failed += check(log, u->ret == 0 && u->rport == 9 && u->lport != 0, "UDP connect: ret 0, remote port 9, local port assigned");
	failed += check(log, t->h.version >= 2 && (t->h.flags & P15_F_ISN) && (x->h.flags & P15_F_ISN) &&
			     t->tcp_isn == x->tcp_isn,
			"connect and accept carry the same client ISN (ADR-0022 rule 5)");
	failed += check(log, !(u->h.flags & P15_F_ISN) && !(b->h.flags & P15_F_ISN) && !(l->h.flags & P15_F_ISN),
			"UDP connect, bind and listen carry no ISN");
	failed += check(log, b->netns && b->netns == x->netns && b->h.start_ns == x->h.start_ns,
			"netns set; every record names this process (ADR-0009)");
out:
	if (as >= 0)
		close(as);
	if (ls >= 0)
		close(ls);
	if (cs >= 0)
		close(cs);
	if (us >= 0)
		close(us);
	ring_buffer__free(rb);
	*consumed = c.total;
	return rc ? rc : failed;
}
