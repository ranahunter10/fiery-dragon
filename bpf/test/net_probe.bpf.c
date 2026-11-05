// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * net_probe: the ADR-0004 candidate hooks for network intent, and what each
 * one can see. All are fexit on the IPv4/IPv6 proto_ops, which every entry path
 * reaches (connect(2), socketcall incl. 32-bit, io_uring) and which, being called
 * through a function pointer, can't be inlined away:
 *   connect: inet_stream_connect, inet_dgram_connect
 *   accept:  inet_accept
 *   listen:  inet_listen
 *   bind:    inet_bind, inet6_bind
 * Non-IP sockets (AF_UNIX, ...) are counted as excluded, not recorded.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET  2
#define AF_INET6 10
#define MAX_ERRNO 4095

enum { OP_CONNECT = 1, OP_ACCEPT = 2, OP_LISTEN = 3, OP_BIND = 4, OP_N = 5 };
/* counter index = op * 4 + kind */
enum { K_SEEN = 0, K_EMITTED = 1, K_EXCLUDED = 2, K_FAILED = 3 };

struct net_rec {
	__u64 cookie;          /* bpf_get_socket_cookie of the socket */
	__u64 lcookie;         /* accept: the listening socket's cookie */
	__u8 laddr[16], raddr[16];
	__s32 ret;
	__u32 tgid;
	__u16 op, family, proto, lport, rport, _pad[3];
};

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } net_rb SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, OP_N * 4); __type(key, __u32); __type(value, __u64); } net_ctr SEC(".maps");

static void bump(int op, int kind)
{
	__u32 k = op * 4 + kind;
	__u64 *v = bpf_map_lookup_elem(&net_ctr, &k);

	if (v)
		(*v)++;
}

/* Fill family, protocol and local endpoint from sk; remote too if `remote_from_sk`. The cookie is
 * taken by the caller, where sk is a trusted pointer (bpf_get_socket_cookie requires it). */
static int fill(struct net_rec *r, struct sock *sk, int remote_from_sk)
{
	r->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (r->family != AF_INET && r->family != AF_INET6)
		return -1;
	r->proto = BPF_CORE_READ(sk, sk_protocol);
	r->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	if (r->family == AF_INET) {
		__be32 a = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

		__builtin_memcpy(r->laddr, &a, 4);
		if (remote_from_sk) {
			a = BPF_CORE_READ(sk, __sk_common.skc_daddr);
			__builtin_memcpy(r->raddr, &a, 4);
		}
	} else {
		BPF_CORE_READ_INTO(&r->laddr, sk, __sk_common.skc_v6_rcv_saddr);
		if (remote_from_sk)
			BPF_CORE_READ_INTO(&r->raddr, sk, __sk_common.skc_v6_daddr);
	}
	if (remote_from_sk)
		r->rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	return 0;
}

static struct net_rec *start(int op)
{
	struct net_rec *r;

	bump(op, K_SEEN);
	r = bpf_ringbuf_reserve(&net_rb, sizeof(*r), 0);
	if (!r) {
		bump(op, K_FAILED);
		return 0;
	}
	__builtin_memset(r, 0, sizeof(*r));
	r->op = op;
	r->tgid = bpf_get_current_pid_tgid() >> 32;
	return r;
}

static int finish(struct net_rec *r, int ok, int op)
{
	if (!ok) {
		bpf_ringbuf_discard(r, 0);
		bump(op, K_EXCLUDED);
		return 0;
	}
	bpf_ringbuf_submit(r, 0);
	bump(op, K_EMITTED);
	return 0;
}

/* connect: proto_ops->connect of TCP and UDP, v4 and v6. The remote endpoint is the
 * requested one, read from the kernel's copy of the address; `sock` is a trusted argument,
 * so sock->sk is trusted-or-null and bpf_get_socket_cookie accepts it. */
static int on_connect(struct socket *sock, void *uaddr, int ret)
{
	struct sock *sk = sock->sk;
	struct net_rec *r;
	int ok;

	if (!sk) {
		bump(OP_CONNECT, K_SEEN);
		bump(OP_CONNECT, K_EXCLUDED);
		return 0;
	}
	r = start(OP_CONNECT);
	if (!r)
		return 0;
	r->ret = ret;
	ok = fill(r, sk, 0) == 0;
	if (ok)
		r->cookie = bpf_get_socket_cookie(sk);
	if (ok && r->family == AF_INET) {
		struct sockaddr_in *in = uaddr;

		__be32 a = BPF_CORE_READ(in, sin_addr.s_addr);

		r->rport = bpf_ntohs(BPF_CORE_READ(in, sin_port));
		__builtin_memcpy(r->raddr, &a, 4);
	} else if (ok) {
		struct sockaddr_in6 *in6 = uaddr;

		r->rport = bpf_ntohs(BPF_CORE_READ(in6, sin6_port));
		BPF_CORE_READ_INTO(&r->raddr, in6, sin6_addr);
	}
	return finish(r, ok, OP_CONNECT);
}

SEC("fexit/inet_stream_connect")
int BPF_PROG(net_connect_stream, struct socket *sock, void *uaddr, int addr_len, int flags, int ret)
{
	return on_connect(sock, uaddr, ret);
}

SEC("fexit/inet_dgram_connect")
int BPF_PROG(net_connect_dgram, struct socket *sock, void *uaddr, int addr_len, int flags, int ret)
{
	return on_connect(sock, uaddr, ret);
}

/* accept: proto_ops->accept of TCP v4 and v6. On success newsock->sk is the accepted
 * connection; sock->sk is the listener. A failed accept (EAGAIN etc.) is counted, not recorded. */
SEC("fexit/inet_accept")
int BPF_PROG(net_accept, struct socket *sock, struct socket *newsock, void *arg, int ret)
{
	struct sock *nsk = newsock->sk, *lsk = sock->sk;
	struct net_rec *r;
	int ok;

	if (ret || !nsk || !lsk) {
		bump(OP_ACCEPT, K_SEEN);
		bump(OP_ACCEPT, K_EXCLUDED);
		return 0;
	}
	r = start(OP_ACCEPT);
	if (!r)
		return 0;
	ok = fill(r, nsk, 1) == 0;
	if (ok) {
		r->cookie = bpf_get_socket_cookie(nsk);
		r->lcookie = bpf_get_socket_cookie(lsk);
	}
	return finish(r, ok, OP_ACCEPT);
}

static int on_sock(struct socket *sock, int ret, int op)
{
	struct sock *sk = sock->sk;
	struct net_rec *r;
	int ok;

	if (!sk) {
		bump(op, K_SEEN);
		bump(op, K_EXCLUDED);
		return 0;
	}
	r = start(op);
	if (!r)
		return 0;
	r->ret = ret;
	ok = fill(r, sk, 0) == 0;
	if (ok)
		r->cookie = bpf_get_socket_cookie(sk);
	return finish(r, ok, op);
}

SEC("fexit/inet_listen")
int BPF_PROG(net_listen, struct socket *sock, int backlog, int ret)
{
	return on_sock(sock, ret, OP_LISTEN);
}

SEC("fexit/inet_bind")
int BPF_PROG(net_bind4, struct socket *sock, void *uaddr, int addr_len, int ret)
{
	return on_sock(sock, ret, OP_BIND);
}

SEC("fexit/inet6_bind")
int BPF_PROG(net_bind6, struct socket *sock, void *uaddr, int addr_len, int ret)
{
	return on_sock(sock, ret, OP_BIND);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
