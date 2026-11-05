---
status: accepted
date: 2026-11-05
owner: Ashish Rana
consulted: [capture blueprint v1 §4 and §10 (Phase 3), census v2 (E-0031, E-0032), Linux v7.0 net/socket.c, net/compat.c, io_uring/net.c, net/ipv4/af_inet.c, net/ipv6/af_inet6.c, kernel/bpf/verifier.c, the net_probe runs, maintainer's demo request of 2026-11-02, maintainer's acceptance of 2026-11-05]
supersedes: none
---

# 0004: Network intent: fexit on the IPv4/IPv6 proto_ops for connect, accept, listen and bind; one NET record on the bulk ring, keyed by socket cookie

## Context and problem statement

Fiery Dragon captures process lifecycle only. The thesis needs process ↔ network edges, so that a provenance graph can say which process talked to which endpoint, and from which process the connection came.

The maintainer's demo makes the requirement concrete: **given a port, show every process that listened on it, connected to it or was connected through it, with each one's lineage.**

The blueprint puts sockets in Phase 3. This ADR pulls forward only the **intent** slice: connect, accept, listen and bind, with endpoints and verdicts. Byte flows (`sock_send_length`/`sock_recv_length`, SOCK_FLOW) stay in Phase 3.

**Question:** which kernel hooks see every connect, accept, listen and bind, whatever the entry path? What does a record carry, and on which ring?

## Decision drivers

1. **Every entry path:**
   - the syscalls `connect`, `accept`, `accept4`, `listen` and `bind`;
   - `socketcall` (including 32-bit compat);
   - io_uring's CONNECT, ACCEPT, BIND and LISTEN.
2. **Hooks that cannot silently disappear:** not inlined, present in BTF and ftrace on 7.0.
3. **The verdict:** a refused connect is evidence (a port scan is a run of them), so the return value is recorded.
4. **A stable socket identity** that links an accepted connection to its listener and survives fd reuse.
5. **A flood of connects must not invalidate the run** (ADR-0006, ADR-0017).
6. ADR-0003's order of preference (tp_btf, then fentry/fexit, then kprobe), and a load-time check.

## Considered options

1. **fexit on the IPv4/IPv6 `proto_ops`:** `inet_stream_connect`, `inet_dgram_connect`, `inet_accept`, `inet_listen`, `inet_bind`, `inet6_bind`
2. fexit on the syscall layer: `__sys_connect_file`, `do_accept`, `__sys_listen_socket`, `__sys_bind_socket`
3. `tp_btf/inet_sock_set_state` (TCP state changes), plus fexit for the rest
4. The `sys_enter_*`/`sys_exit_*` tracepoints (v3.7's way)

## Decision outcome

**Chosen option:** option 1.
- Every entry path ends in `sock->ops->connect/accept/listen/bind` (driver 1, SRC below).
- A function called through a pointer cannot be inlined away (driver 2).
- Its `struct socket *` argument is trusted, so `sock->sk` is trusted-or-null and `bpf_get_socket_cookie` accepts it (driver 4).

Why not the others:
- **Option 2**, tried first, failed on the runner's 7.0 verifier: the socket there comes from `file->private_data`, an untrusted pointer, and the cookie helper refuses it. Its `_socket` variants are also called from the same file as their syscalls, so they may be inlined there (INF).
- **Option 3** sees TCP only, and sees accept in softirq context with no process.
- **Option 4** is ruled out by ADR-0003: it puts the syscall-tracepoint tax on every syscall, and reads user memory at entry, which is open to TOCTOU.

### Rules

1. **Hooks** (all `fexit`, all for `AF_INET` and `AF_INET6`):

   | Operation | Hook | What fexit gives |
   |---|---|---|
   | connect | `inet_stream_connect` (TCP), `inet_dgram_connect` (UDP) | the socket, the kernel's copy of the requested address, the return value |
   | accept | `inet_accept` | the listening socket, the new socket (on success), the return value |
   | listen | `inet_listen` | the socket, the return value |
   | bind | `inet_bind`, `inet6_bind` | the socket, the return value |

2. **One record type, NET (version 1),** written into the **bulk** ring. Fields:

   | Field | Content |
   |---|---|
   | `op` | CONNECT, ACCEPT, LISTEN or BIND |
   | `ret` | the hook's return value: 0, `-EINPROGRESS`, `-ECONNREFUSED`, … |
   | `family`, `proto` | the address family; IPPROTO_TCP or IPPROTO_UDP |
   | `laddr`, `lport` | the local endpoint, from `sock_common` after the operation |
   | `raddr`, `rport` | the remote endpoint: for connect, the **requested** address from the kernel's copy (TOCTOU-safe); for accept, the peer from `sock_common` |
   | `sock_cookie` | `bpf_get_socket_cookie` of the socket (for accept, the new connection) |
   | `peer_cookie` | for accept, the listening socket's cookie; otherwise 0 |
   | `netns` | the network namespace inode, `sk->__sk_common.skc_net.net->ns.inum` |

   - Ports are in host order; IPv4 addresses take the first 4 of 16 bytes.
   - The common header (ADR-0008) carries the process identity (ADR-0009). The record joins the process tree directly.
3. **Failures:**
   - **Connect, listen and bind are recorded whatever the return value.** A refused connect, a failed bind or EADDRINUSE are all evidence.
   - **A failed accept** (mostly `-EAGAIN` from non-blocking servers) is **counted, not recorded** (`excluded_by_policy`, ADR-0006 rule 6). Recording it would turn an idle Nginx into a flood.
4. **Bulk ring, counted loss.** NET records go on the bulk ring that ADR-0006 rule 2 defines, so a connect flood can never fail a spine reservation.
   - Its first size is 4 MiB, to be resized from the measured fill level (STATS).
   - A NET reservation failure is counted per type, puts the run in DEGRADED (ADR-0019 G2.3) and appears in STATS. It does not make the run INVALID.
5. **Socket identity.** The socket cookie is a slice of the planned ADR-0016 (endpoint identity). ADR-0016 will add the transport and the 4-tuple history.
   - The cookie is unique per boot, so `(boot_id, sock_cookie)` names a socket for the whole run, across fd reuse.
   - An accepted connection names its listener through `peer_cookie`. That is how "who served port 8080" is answered without matching ports and times.
6. **Load-time self-test** (ADR-0003). The test child does a loopback TCP listen, connect and accept, and a UDP connect. The self-test then requires, exactly:
   - one LISTEN with the bound port;
   - one CONNECT whose remote is that port and whose local port is the client's;
   - one ACCEPT whose `peer_cookie` equals the LISTEN's `sock_cookie` and whose remote is the client;
   - the UDP CONNECT with proto UDP.

   `bpf/test/net_probe` is the first form of this test.

### Declared limits of v1 (ADR-0013 will list them)

- **AF_UNIX** sockets never reach the inet `proto_ops`: no record and no count. Local IPC, such as `docker.sock`, is Phase 3.
- **Unconnected UDP** (`sendto`/`sendmsg` with an address, no `connect`) is invisible here; that is SOCK_FLOW, Phase 3. Most resolvers `connect` their UDP socket (INF, to be measured).
- **Other protocols:** MPTCP (`mptcp_stream_ops`), SCTP, raw and packet sockets have their own ops. Each needs its own hook, or is a declared limit.
- **Close** is not recorded; a socket's end comes with SOCK_FLOW (Phase 3) or with its process's EXIT.
- **The requested remote of a connect** is what the process asked for. If the kernel routes it elsewhere (e.g. through a transparent proxy), only the asked-for address is shown.

### Consequences

- Good: every entry path, verdicts included, with hooks that can't be inlined away. 32-bit compat and io_uring come for free (SRC).
- Good: the port question becomes a join on the record stream: listener → accepts (by cookie) → process tree (by ADR-0009 identity). Nothing is inferred from timing.
- Good: connect floods stay on the bulk ring and can't invalidate the spine.
- Bad: IP only in v1 (the limits above).
- Bad: fentry/fexit can't be loaded in the cloud dev container (EPERM, no tracefs). These hooks are tested in CI (runner kernel 7.0.0-1017-azure) and on the VM.

### Confirmation

- `make smoke-net` (CI and VM) passes every check of `net_probe`:
  - TCP over IPv4 and IPv6: one bind, listen, connect and accept each, with matching endpoints and cookies;
  - UDP connect;
  - refused connect (`-ECONNREFUSED`);
  - non-blocking connect (`-EINPROGRESS`);
  - AF_UNIX gives no record;
  - the counters close.
- The self-test of rule 6 in `p15d`'s load path.
- Phase 1 step 6: an io_uring CONNECT/ACCEPT and a 32-bit `socketcall` connect each produce exactly one NET record (closing the rest of P7).

### Falsifier

Reopen if:
- an in-scope connect, accept, listen or bind is seen by a ground-truth tracer (e.g. bpftrace on `__sys_connect_file`) and not by these hooks;
- the verifier on 7.0.0-38 refuses any of them;
- NET loss appears on the bulk ring under in-scope workloads.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | `connect(2)` → `__sys_connect` → `__sys_connect_file` → `sock->ops->connect`; `socketcall` SYS_CONNECT calls `__sys_connect` (native and compat) | SRC | v7.0 `net/socket.c` lines 2072–2108, 3114–3116; `net/compat.c` line 454 |
| 2 | io_uring CONNECT, ACCEPT, BIND and LISTEN call `__sys_connect_file`, `do_accept`, `__sys_bind_socket` and `__sys_listen_socket`, which call the socket's ops | SRC | v7.0 `io_uring/net.c` lines 1673, 1809, 1873, 1901; `net/socket.c` 1866–1930, 1951 |
| 3 | `inet_stream_ops`/`inet_dgram_ops`/`inet6_*_ops` use `inet_stream_connect`, `inet_dgram_connect`, `inet_accept`, `inet_listen`, `inet_bind`, `inet6_bind` | SRC | v7.0 `net/ipv4/af_inet.c` lines 1070–1145; `net/ipv6/af_inet6.c` lines 681–724 |
| 4 | `struct socket`'s `sk` is `BTF_TYPE_SAFE_TRUSTED_OR_NULL`, so `sock->sk` from a trusted argument is accepted by helpers that need a trusted socket | SRC | v7.0 `kernel/bpf/verifier.c` line 7323 |
| 5 | The cookie helper refuses a socket reached through `file->private_data` ("R1 type=untrusted_ptr_ expected=sock_common, …") | MEAS (runner 7.0.0-1017-azure) | CI log of PR #35, first run |
| 6 | Syscall-layer fexit on `__sys_connect_file`, `do_accept`, `__sys_bind` and `__sys_listen` delivers on the VM | MEAS | census v2, E-0032 |
| 7 | The proto_ops hooks pass the 7.0 verifier and deliver correct endpoints, verdicts and cookies | MEAS (runner; VM pending) | `net_probe` in PR #35 CI; [evidence](../evidence/probes/2026-11-02-net-probe/README.md) |
| 8 | The dev container refuses every fentry/fexit load (EPERM) | MEAS | E-0078 |

## Pros and cons of the options

### 1. proto_ops fexit
- Good: all entry paths, not inlinable, trusted socket, verdicts.
- Bad: IP families only; one hook per protocol family's ops.

### 2. Syscall-layer fexit
- Good: one hook for every family, AF_UNIX included.
- Bad: no cookie (untrusted socket); possibly inlined `_socket` variants.

### 3. `inet_sock_set_state`
- Good: a stable tracepoint.
- Bad: TCP only; accept in softirq with no process; no connect verdict.

### 4. Syscall tracepoints
- Bad: the syscall-tracepoint tax and TOCTOU (ADR-0003).
