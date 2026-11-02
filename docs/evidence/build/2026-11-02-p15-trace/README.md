# p15-trace: the port query, its tree and its reports (2026-11-02)

**Where:** the cloud dev container, on the synthetic run of [`python/tests/scenario.py`](../../../../python/tests/scenario.py). That run has a known story: a web server on 18077, two local clients, one off-host peer, and a child shell whose `nc` is refused on 4444. **These are tests of the query logic, not measurements of a capture.** The real-capture check is `it_p15d.sh` case 5 (CI and the VM). It runs p15-trace on a real p15d run and keeps that run and its reports as the CI artifact `it-p15d-net-run`.

**File:** [`container.txt`](container.txt): the unit tests and the mutation sweep.

## Findings (MEAS, dev container, synthetic input)

1. **22 tests pass.** They cover:
   - the tree: lineage, exits by signal, threads kept out, the ADR-0009 double-fork and double-exit counters, pre-existing processes versus missing FORKs, processes alive during a GAP;
   - the port query: the cookie join, the endpoint join and each rule that refuses it (after the accept, failed, another netns, another target), the nearest of two candidates, an accept whose listener isn't in the run, UDP and failed binds, -EINPROGRESS counted as not a failure;
   - both reports: exact lines, the trust lines (network capture off, no END, GAP), the nearest clock anchor;
   - the HTML: it is self-contained (no URL, no script) and well formed, and it escapes text from the run.
2. **Mutation sweep: 93/93 planted bugs caught.** 22 of them are new, in the tree, the query and the reports. One mutant was replaced because it was equivalent: `st & 0xFF` for `st & 0x7F` in the exit decoding, since a wait status with signal 0 never has the core-dump bit set.
