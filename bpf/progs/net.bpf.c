// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * net.bpf.c: network intent (ADR-0004). fexit on the IPv4/IPv6 proto_ops, which every entry
 * path reaches (connect(2), socketcall incl. 32-bit, io_uring) and which can't be inlined:
 *   connect: inet_stream_connect, inet_dgram_connect     accept: inet_accept
 *   listen:  inet_listen                                  bind:   inet_bind, inet6_bind
 * One NET record per operation into the bulk ring; a full ring is counted, never silent
 * (ADR-0004 rule 4). The record header names the current process (ADR-0009). The socket
 * cookie is taken where sk is trusted (sock->sk of a trusted argument; verifier.c
 * BTF_TYPE_SAFE_TRUSTED_OR_NULL(struct socket)), as bpf/test/net_probe established (E-0079).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "p15_counters.h"
#include "p15_records.h"

#define AF_INET  2
#define AF_INET6 10
#define EINPROGRESS 115   /* uapi asm-generic/errno.h; the non-blocking connect that still sent its SYN */

enum { NET_CONNECT = 1, NET_ACCEPT = 2, NET_LISTEN = 3, NET_BIND = 4 };

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Bulk ring: 4 MiB by default (ADR-0004 rule 4); the loader may resize it before load. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 << 20);
} bulk_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, P15_CTR_MAX);
	__type(key, __u32);
	__type(value, __u64);
} bulk_counters SEC(".maps");

/* The bulk ring's high-water mark (ADR-0020 rule 2): the loader sets a quarter of the ring. */
const volatile __u64 bulk_wake_bytes = 1 << 20;

static __always_inline __u64 wake(void)
{
	return bpf_ringbuf_query(&bulk_rb, BPF_RB_AVAIL_DATA) > bulk_wake_bytes ? BPF_RB_FORCE_WAKEUP
										 : BPF_RB_NO_WAKEUP;
}

static __always_inline void count(__u32 kind)
{
	__u32 k = P15_CTR_INDEX(P15_T_NET, kind);
	__u64 *v = bpf_map_lookup_elem(&bulk_counters, &k);

	/* Atomic: all six fexit programs share these slots, and fexit runs with preemption on and a
	 * per-program recursion guard, so a connect preempted mid-increment and an accept on the same
	 * CPU would lose one count (E-0097; see spine.bpf.c count()). */
	if (v)
		__sync_fetch_and_add(v, 1);
}

/* Reserve a NET record and fill its header from the current task (the same identity rule as
 * the spine's fill_hdr, ADR-0009). NULL means the ring was full, counted. */
static __always_inline struct p15_net *start(__u16 op)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct p15_net *r;

	count(P15_CK_SEEN);
	r = bpf_ringbuf_reserve(&bulk_rb, sizeof(*r), 0);
	if (!r) {
		count(P15_CK_RESERVE_FAILED);
		return 0;
	}
	__builtin_memset(r, 0, sizeof(*r));
	r->h.type = P15_T_NET;
	r->h.version = P15_NET_VERSION;
	r->h.len = sizeof(*r);
	r->h.ts_ns = bpf_ktime_get_boot_ns();
	r->h.tgid = BPF_CORE_READ(t, tgid);
	r->h.tid = BPF_CORE_READ(t, pid);
	r->h.start_ns = BPF_CORE_READ(t, group_leader, start_boottime);
	r->op = op;
	return r;
}

static __always_inline int excluded(void)
{
	count(P15_CK_SEEN);
	count(P15_CK_EXCLUDED);
	return 0;
}

/* Family, protocol, local endpoint, netns; the remote too if `remote`. -1 for a non-IP socket. */
static __always_inline int fill(struct p15_net *r, struct sock *sk, int remote)
{
	r->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (r->family != AF_INET && r->family != AF_INET6)
		return -1;
	r->proto = BPF_CORE_READ(sk, sk_protocol);
	r->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	r->netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	if (r->family == AF_INET) {
		__be32 a = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

		__builtin_memcpy(r->laddr, &a, 4);
		if (remote) {
			a = BPF_CORE_READ(sk, __sk_common.skc_daddr);
			__builtin_memcpy(r->raddr, &a, 4);
		}
	} else {
		BPF_CORE_READ_INTO(&r->laddr, sk, __sk_common.skc_v6_rcv_saddr);
		if (remote)
			BPF_CORE_READ_INTO(&r->raddr, sk, __sk_common.skc_v6_daddr);
	}
	if (remote)
		r->rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	return 0;
}

static __always_inline int finish(struct p15_net *r, int ok)
{
	if (!ok) {
		bpf_ringbuf_discard(r, BPF_RB_NO_WAKEUP);
		count(P15_CK_EXCLUDED);
		return 0;
	}
	bpf_ringbuf_submit(r, wake());
	count(P15_CK_EMITTED);
	return 0;
}

/* ADR-0022 rule 2: the client's TCP initial sequence number, the token that joins a connect to its
 * accept exactly. Each side reads it where the kernel has just set it and the process can't have
 * moved it yet. On any doubt the record carries no ISN (no P15_F_ISN), never a wrong one; the
 * reader counts TCP connects and accepts without one (rule 3). */

/* connect: tcp_connect queued the SYN at write_seq and moved write_seq to ISN + 1, and set
 * snd_nxt = write_seq (tcp_output.c 4365-4388, v7.0). The process can't write before connect
 * returns, so then snd_nxt == write_seq, and snd_una is ISN (SYN not yet acked) or ISN + 1
 * (acked). A deferred Fast Open connect (no SYN yet), a repair-mode socket, or any other state
 * fails this check. The check stands in for reading INET_FLAGS_DEFER_CONNECT, an anonymous
 * enum that CO-RE can't relocate by name. */
static __always_inline void client_isn(struct p15_net *r, struct sock *sk, int ret)
{
	struct tcp_sock *tp;
	__u32 wseq, nxt, una;

	if (r->proto != IPPROTO_TCP || (ret != 0 && ret != -EINPROGRESS))
		return;
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp || BPF_CORE_READ_BITFIELD(tp, repair))
		return;
	wseq = tp->write_seq;
	nxt = tp->snd_nxt;
	una = tp->snd_una;
	if (nxt != wseq || (una != wseq - 1 && una != wseq))
		return;
	r->tcp_isn = wseq - 1;
	r->h.flags |= P15_F_ISN;
}

/* accept: tcp_create_openreq_child set copied_seq = rcv_isn + 1 (tcp_minisocks.c 573-575, v7.0),
 * and copied_seq moves only when the process reads, which it can't before accept returns. */
static __always_inline void server_isn(struct p15_net *r, struct sock *sk)
{
	struct tcp_sock *tp;

	if (r->proto != IPPROTO_TCP)
		return;
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp)
		return;
	r->tcp_isn = tp->copied_seq - 1;
	r->h.flags |= P15_F_ISN;
}

static __always_inline int on_connect(struct socket *sock, void *uaddr, int ret)
{
	struct sock *sk = sock->sk;
	struct p15_net *r;
	int ok;

	if (!sk)
		return excluded();
	r = start(NET_CONNECT);
	if (!r)
		return 0;
	r->ret = ret;
	ok = fill(r, sk, 0) == 0;
	if (ok) {
		r->sock_cookie = bpf_get_socket_cookie(sk);
		if (r->family == AF_INET) {
			struct sockaddr_in *in = uaddr;
			__be32 a = BPF_CORE_READ(in, sin_addr.s_addr);

			r->rport = bpf_ntohs(BPF_CORE_READ(in, sin_port));
			__builtin_memcpy(r->raddr, &a, 4);
		} else {
			struct sockaddr_in6 *in6 = uaddr;

			r->rport = bpf_ntohs(BPF_CORE_READ(in6, sin6_port));
			BPF_CORE_READ_INTO(&r->raddr, in6, sin6_addr);
		}
		client_isn(r, sk, ret);
	}
	return finish(r, ok);
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

SEC("fexit/inet_accept")
int BPF_PROG(net_accept, struct socket *sock, struct socket *newsock, void *arg, int ret)
{
	struct sock *nsk = newsock->sk, *lsk = sock->sk;
	struct p15_net *r;
	int ok;

	if (ret || !nsk || !lsk)
		return excluded();           /* a failed accept (EAGAIN, ...): counted, not recorded */
	r = start(NET_ACCEPT);
	if (!r)
		return 0;
	ok = fill(r, nsk, 1) == 0;
	if (ok) {
		r->sock_cookie = bpf_get_socket_cookie(nsk);
		r->peer_cookie = bpf_get_socket_cookie(lsk);
		server_isn(r, nsk);
	}
	return finish(r, ok);
}

static __always_inline int on_sock(struct socket *sock, int ret, __u16 op)
{
	struct sock *sk = sock->sk;
	struct p15_net *r;
	int ok;

	if (!sk)
		return excluded();
	r = start(op);
	if (!r)
		return 0;
	r->ret = ret;
	ok = fill(r, sk, 0) == 0;
	if (ok)
		r->sock_cookie = bpf_get_socket_cookie(sk);
	return finish(r, ok);
}

SEC("fexit/inet_listen")
int BPF_PROG(net_listen, struct socket *sock, int backlog, int ret)
{
	return on_sock(sock, ret, NET_LISTEN);
}

SEC("fexit/inet_bind")
int BPF_PROG(net_bind4, struct socket *sock, void *uaddr, int addr_len, int ret)
{
	return on_sock(sock, ret, NET_BIND);
}

SEC("fexit/inet6_bind")
int BPF_PROG(net_bind6, struct socket *sock, void *uaddr, int addr_len, int ret)
{
	return on_sock(sock, ret, NET_BIND);
}
