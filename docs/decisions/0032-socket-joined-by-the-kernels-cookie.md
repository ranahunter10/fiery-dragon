---
status: proposed
date: 2026-11-14
owner: Ashish Rana
consulted: [kernel v7.0 net/core/sock_diag.c, net/core/filter.c, include/net/sock.h, net/socket.c; bpf/progs/net.bpf.c and file.bpf.c at 2131d21; bpf/vmlinux/vmlinux-7.0.0-38.h; ADR-0004, ADR-0015, ADR-0025; research note 2026-11-13-pipeline-review-and-graph-algorithms.md §2 G1 and §4 A6; STATE decision waiting 18]
supersedes: ADR-0015 rule 10's mechanism (NET v3 with the object id, step 2e) and consequence 2. A socket's object is still its sockfs inode; every other rule of ADR-0015 is unchanged. Corrects ADR-0025 rule 5's "7.0 has no stable sk_cookie field to read" (see Evidence 1 and 4).
---

# 0032: A socket's file object joins its NET records by the cookie the kernel stores in the sock, carried once in FILE v2

## Context and problem statement

A socket is two nodes in the graph (decision waiting 18, research note §2 G1). Its SEND and RECV transfers point at its file object (`o:<obj>`); its CONNECT, ACCEPT, LISTEN and BIND point at its cookie (`s:<cookie>`). Nothing in the WAL joins the two, so a trace cannot follow data across a connection: from the bytes a server received, back through the TCP pair (ADR-0022), to the client process that sent them. ADR-0015 rule 10 planned the join for step 2e: NET v3 would carry the socket's object id. That needs the NET programs to assign object ids, which today only `file.bpf.c` does, from maps and an id counter of its own. The demo and the ceiling gate need the join before step 2e. How should the two nodes be joined, exactly and soon?

## Decision drivers

1. **Exact or nothing** (ADR-0022's standard): a join by identity, never by time or address. Anything not joined is counted.
2. **No cost per transfer:** the read and write path is the budget (decision 46, criterion P2).
3. **No new record on the hot path, no new hook,** and no sharing of object ids between two BPF objects.
4. Works for the sockets NET sees: TCP and UDP connect, accept, listen and bind over IPv4 and IPv6.

## Considered options

1. **FILE v2 carries the cookie the kernel holds in the sock** when the socket is first seen at a transfer. The graph unites the socket's object with the socket node of that cookie.
2. **NET v3 carries the socket's object id** (ADR-0015 rule 10 as written). The NET programs register the socket in the object map and assign its id.
3. **FLOW v2 carries the cookie on every SEND and RECV.**
4. **Join in the graph by the socket's inode number:** NET would carry `i_ino`, and the graph would match it to the object's facts.

## Decision outcome

**Chosen option:** option 1, because it meets all four drivers.
- The cookie is already in the sock when the first transfer happens (Evidence 1 to 3), so the join is exact.
- It costs one 8-byte load per socket, when its FILE is written, and nothing per transfer (driver 2).
- It changes only the record a socket gets once (driver 3).

### Rules

1. **FILE v2** is FILE v1 with `sock_cookie` (u64) after `obj`: 88 bytes fixed. The sock tracepoints' program (`sock_flow` in `file.bpf.c`) passes `sk->__sk_common.skc_cookie.counter` when it registers a socket's file and writes its FILE. Every other FILE carries 0.
2. **0 means unknown, never a value.** 0 is written when no program has made the cookie yet. The kernel makes it on the first `sock_gen_cookie` call, so 0 covers a socket NET never saw: a UDP `sendto` without `connect`, TCP fast open, a Unix socket, a socket from before the capture.
3. **The graph's join** (`graph.sql`, `sock_obj`): an object joins the socket node `s:<cookie>` when it meets both conditions:
   - exactly one non-zero cookie names it in the run;
   - a NET record names that cookie.

   Its open files then have rule `sock-cookie` and file key `s:<cookie>`. Their SEND and RECV edges, and any HELD edge, land on the socket node, and no file node is made for the object. Anything else keeps ADR-0015's object node.
4. **Counted, never guessed:**
   - `flow_sock_joined` and `flow_sock_not_joined`;
   - `sock_cookie_without_net`: a cookie made by another program, or a socket NET does not hook;
   - `sock_obj_two_cookies`: must be 0, and the CLI marks the graph INVALID otherwise.
5. **Readers accept both versions.** `p15_rec_check`, the formatter and the Python reader read v1 and v2. A v1 record has no cookie and builds as before.

### Consequences

- Good:
  - a trace crosses a local TCP connection: server RECV ← server socket ← ISN pair ← client socket ← client SEND ← what the client read first (the test `test_a_socket_with_its_cookie_is_the_socket_node_of_its_net_records`);
  - the socket node carries both its endpoints and its bytes.
- Good: no change to FLOW (decision 14's 96 bytes), NET, the hooks or the maps; one load per socket.
- Bad: a socket whose first transfer comes before NET makes its cookie is not joined. The cases:
  - another thread's send that completes while the connecting thread has not yet returned from `connect`;
  - a UDP socket that sent before it connected.

  These are counted in `flow_sock_not_joined`. Reading the field at every transfer (option 3) would close the gap, at 8 bytes per FLOW.
- Bad: the join depends on the kernel keeping `skc_cookie` in `struct sock_common`. CO-RE relocates the field. If a kernel drops it, the program fails to load, which is loud, not silent.
- Neutral: a listening socket has no transfers, so it gets no FILE and needs none: its accepts name it as `peer_cookie`.

### Confirmation

- `daemon/tests/it_p15d.sh` case 13: over a TCP loopback pair, both ends' FILE records carry the cookies of their CONNECT and ACCEPT records (2 of 2). On CI's 7.0 runner and on the VM.
- `python/tests/test_graph.py`: the join, the trace across the pair, no cookie, a cookie no NET record names, two cookies for one object, and a FILE v1.
- `daemon/tests/test_records.c`: FILE v2's checks.
- Mutants: `daemon/tests/mutate_p15d.py` (the cookie read and its store), `mutate_records.py` (v2's size and fields) and `tools/ci/mutate_py.py` (the join's conditions and counts).

### Falsifier

Either of these reopens the decision:
- `sock_obj_two_cookies` > 0 on any run;
- on a real workload's graph, `flow_sock_not_joined` counts transfers on TCP sockets whose CONNECT or ACCEPT is in the run. That would mean the cookie is often not yet made when a socket's first transfer happens.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | `__sock_gen_cookie` stores the cookie in `sk->sk_cookie`, which is `__sk_common.skc_cookie`, and returns the stored value from then on | SRC | v7.0 `net/core/sock_diag.c` `__sock_gen_cookie`; `include/net/sock.h:192, :396` |
| 2 | `bpf_get_socket_cookie` on a `struct sock` in a tracing program is `sock_gen_cookie(sk)` | SRC | v7.0 `net/core/filter.c:5175` (`bpf_get_socket_ptr_cookie`) |
| 3 | The NET programs call it on the socket at connect, accept (the new socket, and the listener as `peer_cookie`), listen and bind | SRC | `bpf/progs/net.bpf.c:204, 248-249, 269` |
| 4 | The VM's kernel has `atomic64_t skc_cookie` in `struct sock_common` | SRC | `bpf/vmlinux/vmlinux-7.0.0-38.h`, `struct sock_common` |
| 5 | The sock tracepoints' program has a trusted `sk` (`bpf_core_cast`) and already reads `sk->sk_socket` by direct load, so reading a field is no helper call and is allowed in a classic tracepoint | SRC | `bpf/progs/file.bpf.c` `sock_flow` |
| 6 | An accepted socket's descriptor is installed after `do_accept` returns, so after the fexit on `inet_accept` has made its cookie: no transfer on it can come first | SRC | v7.0 `net/socket.c:1988, 2022` (`ops->accept`, then `FD_ADD`) |
| 7 | An aligned 8-byte load is how `atomic64_read` reads on x86-64 | INF | `arch/x86` `arch_atomic64_read` is `__READ_ONCE` (not re-read here) |
| 8 | The cookie read and the FILE v2 layout load and run on 7.0, with both TCP ends joined | MEAS (CI's 7.0 runner; the VM: OPEN) | [`docs/evidence/probes/2026-11-14-socket-join-ci`](../evidence/probes/2026-11-14-socket-join-ci/README.md): 2 of 2 on 7.0.0-1017-azure |

## Pros and cons of the options

### 1. FILE v2 with the cookie
- Good: exact, one load per socket, no new hook or map, no change to FLOW or NET.
- Bad: a socket first seen before its cookie exists stays unjoined (counted).

### 2. NET v3 with the object id
- Good: exact for every socket NET sees, whatever the order.
- Bad: the NET programs would have to share the object map, the open-file map and the id counter with `file.bpf.c`, and write the object's facts. Two programs in two objects assigning one id space is new code on the hook path, for the same join.

### 3. FLOW v2 with the cookie on every SEND and RECV
- Good: closes option 1's ordering gap.
- Bad: 8 more bytes on every FLOW (decision 14 kept 96 for the ceiling gate). FLOW's padding has 6 bytes, not 8.

### 4. By inode number
- Bad: sockfs inode numbers come from `get_next_ino`, a 32-bit counter that can repeat. That is not an identity (ADR-0015 rule 3's own reason).
