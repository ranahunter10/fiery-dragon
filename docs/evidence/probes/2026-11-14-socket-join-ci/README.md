# The socket join by the kernel's cookie, on CI's runner kernel (2026-11-14)

Evidence for E-0258 and ADR-0032's confirmation. This was not the target kernel; the VM run is the maintainer's.

| File | What | Where it ran |
|---|---|---|
| `it-p15d-case13.txt` | it_p15d case 13, as the job printed it, timestamps removed | GitHub Actions job 132157897497, kernel 7.0.0-1017-azure, PR #99 at commit `c3ddfeb` |

What it shows (MEAS, runner kernel):
- **The cookie read loads and works.** The workload's TCP loopback pair gave two NET records of its own (the client's CONNECT, the server's ACCEPT). The FILE records written for the two ends at their first transfer carry exactly those two cookies: 2 of 2 joined.
- **Case 13 is otherwise unchanged:** every transfer is one FLOW with its bytes, nothing refused or lost, books B1 to B5 closed, and the flow self-test ran at load and passed.
- The whole of `it_p15d` passed in that job (0 failed checks).

One run on a shared runner: correctness, not cost. The graph built from such a run is not in this evidence; the join's graph side is tested on generated runs (`python/tests/test_graph.py`).

`SHA256SUMS` covers every file here, this README included.
