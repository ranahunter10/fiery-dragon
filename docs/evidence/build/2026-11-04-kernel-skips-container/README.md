# ADR-0020 implemented: container checks (2026-11-04)

**Where:** the cloud dev container, kernel 6.18. On 6.18 tracepoint callbacks still run with preemption off, so the kernel skips nothing here. These checks show that the change is correct and complete; whether it removes the skips is for the VM to show (E-0089, E-0090). tracefs was mounted by hand (`mount -t tracefs nodev /sys/kernel/tracing`): exec, exit and rename are classic tracepoints now.

**File:** [`container.txt`](container.txt).

## Findings (MEAS, dev container)

1. **`make check` passes**, all 14 Python test files included:
   - the schema check, with STATS, GAP and NET_STATS v2 locked;
   - the three-way layout check, the C unit tests, the hardening and exit checks;
   - the C writer cross-checked against the Python reader, now including v2 records.
2. **`make smoke` passes:** the spine self-test passes with exec, exit and rename on classic tracepoints and fork on `tp_btf`.
3. **The end-to-end test passes**, with these new checks:
   - it waits for p15d's `code=start` instead of a fixed time;
   - all 200 of the children's EXECs of `/bin/true` are in the WAL;
   - "the kernel skipped no spine event": fork, exec, exit and rename skips are all 0, read from STATS v2;
   - the forced overflow still ends INVALID with GAP records and closed books.
4. **Every planted bug is caught:**

   | Sweep | Caught | New in this change |
   |---|---|---|
   | p15d | 20/20 | two on the skip check (a skip not calling for a GAP; FORK's skips ignored) |
   | record checks | 22/22 | the v2 sizes |
   | spine EXEC | 7/7 | — |
   | Python | 96/96 | three on the skip lines and GAP v2 |
