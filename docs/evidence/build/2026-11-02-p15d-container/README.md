# p15d, the capture daemon: dev-container run (2026-11-02)

**Where:** the cloud dev container (kernel 6.18.44, gcc 13.3, clang 18.1, root, 2 vCPUs). **Not the target.** The VM repeats it with `sudo make it-p15d`. Branch `feat/p15d`.

**What:** [`run.txt`](run.txt): every check from `make clean`, then the end-to-end test and the mutation sweep. `p15d` itself:
- the drain on the main thread, at `SCHED_FIFO` 1;
- the bounded SPSC queue;
- the WAL writer thread;
- STATS, CLOCK_SYNC, GAP and END records;
- the run state machine and the accounting invariant;
- the Prometheus textfile;
- a strict command line.

## Findings (MEAS, dev container)

1. **The end-to-end test passes all four cases** (`daemon/tests/it_p15d.sh`; real BPF programs, WAL checked by `p15w-inspect`):
   - **A 4 s run with 200 short processes.**
     - Exit 0, every segment valid to its end, every record passes `p15_rec_check`.
     - END: exit 0, RUNNING, invariant closed.
     - ≥ 200 EXEC records, a STATS record every 200 ms, the textfile written, the hook manifest in the header.
   - **A stop by SIGTERM:** exit 0; END records signal 15.
   - **A forced spine overflow** (4 KiB ring, drain paused 300 ms per poll, 400 processes).
     - Exit 4, INVALID.
     - GAP records present.
     - The WAL itself still valid, and the books still close: every lost record is counted, so seen = emitted + lost.
     - This is ADR-0017's confirmation test.
   - **A bad flag:** exit 64.
2. **The queue passes under ThreadSanitizer:** 200,000 items between two threads, in order, none lost.
3. **Every C test passes under gcc, clang, and ASan/UBSan.** The hardening check passes for `p15d` (PIE, RELRO, BIND_NOW, NX stack, canary, FORTIFY, CET).
4. **`make mutate-p15d` catches 17 of 17 planted bugs** across the queue, config, drain, writer and run.
   - The first sweep exposed a gap: a broken invariant's INVALID state was set where no test could reach it. That logic moved into `p15_invariant_check`, which `test_run.c` now covers.
   - One mutant didn't build under `-Werror`. It was replaced by one that does, so no build failure counts as a kill.
5. **The first draft's books did not close** ("emitted 813 != drained 806"). The difference was the self-test's own 7 records, which the self-test consumes itself. The run's counters now start after the self-test (`bpf_base`), and `test_run.c` checks that.

## Also on the CI runner (MEAS, kernel 7.0.0-1017-azure, not the target)

[`runner-it-p15d.txt`](runner-it-p15d.txt): the same end-to-end test in PR #36's CI job passes all four cases, including the forced overflow (exit 4, a GAP record, books closed). That is the daemon on a 7.0 kernel.

## Not shown here

- The drain-stall test of ADR-0017's Confirmation (a writer slowed in `fdatasync`) is not written yet.
- The NET records and the bulk ring come with ADR-0004.
