# Network-intent capture through p15d, on the CI runner (2026-11-02)

**Where:** GitHub Actions runner, kernel **7.0.0-1017-azure**, in PR #38's BPF job (`sudo P15_IT_NET=1 make it-p15d`). Same kernel major as the target, but **not the target**: the VM repeats it. The cloud dev container can't run it (fentry/fexit refused, E-0078).

**What:** [`runner-it-p15d.txt`](runner-it-p15d.txt): the job's end-to-end test log. Case 5 runs `p15d` with network capture on, while three things happen:
- a Python TCP server binds and listens on 127.0.0.1:18077 and accepts twice;
- two Python clients connect to it;
- one more client connects, blocking, to the closed port 18078.

## Findings (MEAS, runner 7.0)

1. **Every step of "what happened on port 18077" is in the WAL**, joinable without timing:
   - the server (tgid 4969): **BIND** then **LISTEN** on 127.0.0.1:18077, socket cookie **4105**;
   - client 1 (tgid 4971): **CONNECT** to 127.0.0.1:18077, ret 0, local port 41508;
   - the server: **ACCEPT** on 127.0.0.1:18077 from 127.0.0.1:41508, **peer cookie 4105**, the listener's;
   - the same for client 2 (tgid 4972, local port 41524);
   - client 3 (tgid 4973): **CONNECT** to 127.0.0.1:18078 with **ret −111** (ECONNREFUSED).
2. **The run is valid:** exit 0, every segment valid, END with the invariant closed. That includes the NET books: seen = emitted + reserve_failed + excluded, and emitted = drained + taken by the self-test + invalid.
3. Each NET record carries its process's ADR-0009 identity (`tgid`, `start_ns`), so the same WAL's FORK/EXEC records give each client's and the server's lineage. The query tool (demo-track item 4) does that join.
4. **All five cases of the end-to-end test pass on the runner,** including the forced spine overflow with network capture on.
