---
status: proposed
date: —
owner: Ashish Rana
consulted: [E-0092 to E-0095 (the accept stamped before its connect), Linux v7.0 net/ipv4/tcp_minisocks.c, tcp_output.c, tcp_ipv4.c, net/ipv6/tcp_ipv6.c, RFC 6528, Lamport 1978, research note 2026-11-05 §4]
supersedes: ADR-0004 rule 2 (NET's field table, version 1 → 2) and rule 6 (the self-test gains one check). Every other rule of ADR-0004 stands.
---

# 0022: Join a TCP client to its accept by the client's initial sequence number

## Context and problem statement

`p15-trace` answers "which local process made this connection" by matching an ACCEPT with a CONNECT on the same 4-tuple and network namespace. Two problems:
- The match is by time, so it is an inference. Each record is stamped when its call returns, and on the VM an accept returned 12 µs before its own connect (E-0092). PR #45 widened the rule to "nearest in time on either side, within 5 s", and both the 5 s and the choice of the nearest are heuristics.
- In the graph that Layer 3 learns from, this is the edge that links two processes through a socket. A heuristic there becomes a wrong causal edge whenever a port is reused inside the window.

Is there an exact key both records can carry?

## Decision drivers

1. Exactness: the join must not depend on timestamps taken at two observation points (Lamport, R-028).
2. No new kernel state: no maps to evict, no ordering between the two hooks.
3. The hooks ADR-0004 already has: fexit on `inet_stream_connect` and `inet_accept`.
4. Every case without the key is counted, and falls back to today's labelled inference.

## Considered options

1. **Keep the time window** (today, PR #45).
2. **The client's initial sequence number (ISN)**, read on both sides at fexit.
3. **A kernel-side pairing map:** connect writes `(netns, 4-tuple) → client cookie`, and accept looks the key up and records the client's cookie.
4. **The request socket:** follow the accepted socket back to the SYN's sender. In the kernel the accepted socket keeps no pointer to the client socket, so this option doesn't exist.

## Decision outcome

**Chosen option: 2.** It is the only option that is both exact and stateless (drivers 1 and 2), and the ISN is already where the two hooks can read it (driver 3).

### Rules

1. **NET version 2** adds two things (supersedes ADR-0004 rule 2's table):
   - `tcp_isn` (u32): the connection's client ISN;
   - the header flag `P15_F_ISN`, set when `tcp_isn` is valid. Nothing else changes; NET v1 stays readable.
2. **Where it comes from** (SRC, v7.0):
   - **ACCEPT** (`inet_accept` fexit, the new socket): `copied_seq − 1`. `tcp_create_openreq_child` sets `copied_seq = rcv_isn + 1` (`tcp_minisocks.c` 573–575), and the server process can't read anything before `accept()` returns.
   - **CONNECT** (`inet_stream_connect` fexit): `write_seq − 1`. `tcp_v4_connect`/`tcp_v6_connect` set `write_seq` to the ISN (`tcp_ipv4.c` 329–335, `tcp_ipv6.c` 321–327), and `tcp_connect` queues the SYN and moves `write_seq` to ISN + 1 (`tcp_output.c` 4179–4188, 4365–4371). The process can't write before `connect()` returns. This holds for blocking connects and for `-EINPROGRESS`.
3. **`P15_F_ISN` is left unset, and the case counted, when:**
   - the socket isn't TCP;
   - the call failed (`ret < 0`, other than `-EINPROGRESS`);
   - the socket is in repair mode (`tp->repair`);
   - a Fast Open connect was deferred: bit `INET_FLAGS_DEFER_CONNECT` (19) of `inet_sk(sk)->inet_flags` on 7.0. That path returns before `tcp_connect` (`tcp_ipv4.c` 341), so `write_seq` is the ISN, not ISN + 1.
4. **The join** (p15-trace):
   - an ACCEPT and a CONNECT match **exactly** when the 4-tuple, the network namespace and `tcp_isn` agree and both carry `P15_F_ISN`. The report labels the match "exact (ISN)";
   - when either side has no ISN, PR #45's time-window rule applies, labelled an inference as today;
   - a CONNECT with the same 4-tuple inside the window but a **different** ISN is a different connection. It is never joined, and it is counted (`isn_mismatch`).
5. **Self-test** (adds to ADR-0004 rule 6): the test child's CONNECT and ACCEPT must both carry `P15_F_ISN` with equal `tcp_isn`.

### Consequences

- Good:
  - the cross-process socket edge becomes exact for TCP on this host. That covers loopback, containers on one host, and the demo's attack story;
  - it needs no map and no ordering between hooks, so the 12 µs inversion can't matter;
  - two reads per event, with CO-RE.
- Bad:
  - 4 bytes more per NET record (inside its padding, or a size change; the generator decides), and a schema version (ADR-0008);
  - Fast Open deferred connects and repair-mode sockets fall back to the inference. Both are counted;
  - UDP has no handshake, so a connected UDP socket's peer stays an inference.

### Confirmation

1. `make smoke-net` (CI, VM): rule 5's check passes.
2. `it_p15d.sh` case 5: both clients are joined "exact (ISN)", with `isn_mismatch = 0`.
3. Unit tests in `test_trace.py`:
   - an exact match is taken over a nearer-in-time candidate with a different ISN;
   - a mismatch is counted;
   - a v1 run falls back to the window.
4. The VM's full `vm_verify.sh`.

### Falsifier

Reopen if, on an in-scope TCP workload, an accept and the connect that made it carry different ISNs, or one of them lacks `P15_F_ISN` without a counted reason.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | The accepted socket's `copied_seq` starts at `rcv_isn + 1` | SRC | v7.0 `net/ipv4/tcp_minisocks.c` 573–575 |
| 2 | `write_seq` is set to the ISN at connect, and moved to ISN + 1 when the SYN is queued | SRC | v7.0 `net/ipv4/tcp_ipv4.c` 329–335, `net/ipv6/tcp_ipv6.c` 321–327, `net/ipv4/tcp_output.c` 4179–4188 and 4365–4371 |
| 3 | A deferred Fast Open connect returns before `tcp_connect` | SRC | v7.0 `net/ipv4/tcp_ipv4.c` 341 |
| 4 | The ISN is a keyed hash of the 4-tuple plus a clock | DOC | RFC 6528 §3 |
| 5 | The accept can be stamped before its connect | MEAS | [E-0092, E-0095](../evidence/probes/2026-11-04-trace-join/README.md) |
| 6 | Timestamps from separate observers don't define causal order | PDF | Lamport 1978 (R-028) |
| 7 | On the target, `tcp_sock` has `copied_seq`, `write_seq` and the `repair` bit, and `inet_sock.inet_flags` has `INET_FLAGS_DEFER_CONNECT` = 19 | SRC | `bpf/vmlinux/vmlinux-7.0.0-38.h`: `struct tcp_sock`, `struct inet_sock`, `enum` line 4107 |

## Pros and cons of the options

### 1. Time window
- Good: no change to capture.
- Bad: an inference with two heuristics (the window and the nearest pick). A reused port inside the window can be joined wrongly, counted only as "ambiguous".

### 2. Client ISN (chosen)
- Good: exact, stateless, independent of order, uses the existing hooks.
- Bad: TCP only; Fast Open deferred and repair-mode sockets fall back; a schema version.

### 3. Pairing map
- Good: exact when it works, and records the client's cookie directly.
- Bad:
  - kernel state to size and evict;
  - when the accept returns first (E-0092), the lookup finds nothing, unless the map is written at an earlier hook than ADR-0004 has;
  - map pressure becomes a loss to count.
