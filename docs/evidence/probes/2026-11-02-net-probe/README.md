# Network-intent probe (ADR-0004), on the CI runner (2026-11-02)

**Where:** the GitHub Actions runner, `ubuntu-24.04` image, kernel **7.0.0-1017-azure**, in the BPF job of PR #35 (commit `e8ca72f`). Same kernel major as the target, but **not the target**: the VM (7.0.0-38-generic) repeats it with `sudo make smoke-net`. The cloud dev container can't run it: it refuses every fentry/fexit load with EPERM and has no tracefs (E-0078).

**What:** [`bpf/test/net_probe`](../../../../bpf/test/net_probe.c).
- **Hooks:** fexit on `inet_stream_connect`, `inet_dgram_connect`, `inet_accept`, `inet_listen`, `inet_bind` and `inet6_bind`.
- **Calls it makes from its own process:**
  - TCP over IPv4 and over IPv6: bind, listen, connect, accept;
  - a UDP connect;
  - a TCP connect to a closed port;
  - a non-blocking connect to TEST-NET-1;
  - an AF_UNIX connect.
- **Checks:** every record field against what those calls did.

| File | Content |
|---|---|
| [`runner-ci-log.txt`](runner-ci-log.txt) | the job log of the passing run, from the `smoke-net` step to the job's end |
| [`runner-ci-log-first-draft.txt`](runner-ci-log-first-draft.txt) | the whole BPF job log of the first draft, which hooked `__sys_connect_file` and `do_accept`: the verifier's refusal |

## Findings (MEAS, runner kernel 7.0.0-1017-azure)

1. **All six hooks pass the 7.0 verifier and attach.**
2. **TCP over IPv4 and IPv6:**
   - exactly one bind, listen, connect and accept per run;
   - bind and listen carry the listener's port and **the same socket cookie**;
   - connect carries the requested remote (the listener) and the client's own port;
   - accept carries the listener port as local, the client as remote, and **`lcookie` equal to the listener's cookie**.
3. **UDP connect:** proto 17, ret 0, remote port 9, local port assigned.
4. **Verdicts are recorded:**
   - a refused connect gives `ret = -111` (`-ECONNREFUSED`), with the requested remote port;
   - a non-blocking connect gives `ret = -115` (`-EINPROGRESS`).
5. **AF_UNIX connect produces no record:** unix sockets don't use the inet proto_ops. This is a declared limit of ADR-0004 v1.
6. **The counters close:** seen = emitted + excluded + reserve_failed for every operation (connect 5, accept 2, listen 2, bind 3). The third bind is the probe's own temporary bind that frees a port for the refused-connect case.
7. **The first draft was refused by the verifier.** It hooked the syscall layer: `__sys_connect_file`, with the socket from `file->private_data`. The verifier said: `R1 type=untrusted_ptr_ expected=sock_common, sock, tcp_sock, xdp_sock, ptr_, trusted_ptr_` at `bpf_get_socket_cookie`. This is why ADR-0004 chooses the proto_ops, whose `struct socket *` argument is trusted.
