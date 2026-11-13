# The detach fix on the VM: it_p15d, its cost per call, its mutants and the `--flow` matrix (2026-11-13/14)

Evidence for E-0255. PR #95 (`dragon/detach-fix`) at commit `4e923ba`, clean, on the VM (7.0.0-38-generic, 3 CPUs), run by the maintainer on 2026-11-13 between 17:45 and 19:12 UTC.

| File | What |
|---|---|
| `it-detach.txt` | `sudo P15_IT_NET=1 make it-p15d`: the end-to-end test, cases 13 to 17 included |
| `flow-cost-count.txt` | `sudo make bench-flow-cost`: 20 rounds x 200,000 one-byte reads per arm, raw rows, then the report (CPU time primary, wall time secondary) |
| `mutants-detach-first-try.txt` | `mutate_p15d.py 74 75 76 77 78 79`, first try, as pasted in the maintainer's terminal: its baseline end-to-end run failed (case 1: "network self-test failed (2)"), so no mutant ran |
| `mutants-detach.txt` | the same sweep, second try |
| `manifest.txt`, `steps.txt`, `summary.md`, `<step>.txt`, `<step>.err` | the `--flow` matrix (`sudo tools/vm/measure_capture.sh -- --flow`), stamp 20261113T184233Z |
| `kernel_log.txt`, `stalls.txt` | the guest's kernel log for the matrix's window, and the stalls found in it (`tools/vm/stalls.py`, #93) |
| `run-SHA256SUMS.txt` | the matrix's own checksums, written on the VM; they match every matrix file here |

Not copied: the matrix's `perf/perf-*.data` (binary).

What it shows (MEAS, VM):

- **it_p15d: PASS, 0 failed checks.**
  - Case 16 (three calls held across the detach): `open_at_end` 3, nothing failed, END RUNNING with every book closed.
  - Case 17: `returned_after_count` 1, its 4201-byte FLOW written with its entry's start time; `v_gated` 116.
  - Before the fix, a `--flow` run with a blocked reader ended INVALID (E-0246).
- **The fix's cost per call (decision waiting 116).** The `count` arm against `ts`, CPU time: −20.2 ns per read, 95 % interval −62.1 to +22.7 ns (−0.17 null syscalls at 117.5 ns). Not resolved: the A/A interval is −15.74 % to +9.50 %. Wall time gives the same: −19.7 ns, −61.8 to +22.7.
  - So the fix costs no more than the host can resolve, and at most about 23 ns per read.
  - No arm had a kernel skip, and 20,000 of 20,000 start times fell inside their reads.
- **Mutants: 5 of 6 killed, 1 did not build.**
  - Killed: 74 (the count skipped), 75 (the gate never shut), 76 (the entry no longer counts), 78 (the claimed half ignored) and 79 (the gate check removed).
  - Mutant 77 (the release removed) did not build: it leaves `rw_release` unused, which `-Werror` refuses. It is not a survivor; it needs an anchor that keeps a reference to the function, as mutant 31 got in #90.
  - The sweep's first try did not run any mutant: its baseline end-to-end run failed once in case 1, at the network self-test (2 checks), which then reported nothing. #96 retries a missing record and prints the report. The second try's baseline passed.
- **The `--flow` matrix: all 12 steps rc=0.**
  - open_cost: 21 rounds, every one with its books closed (`invariant=1`), 4,400,000 opens and closes recorded, none lost. On 2026-11-13 one round in 21 ended INVALID (E-0246).
  - Soak: PASS, recall 100 % on every step kind, END exit 0, state 0, invariant 1; 179,919 FLOW records.
  - **Three stalls** (`stalls.txt`, the first matrix to look for them): 1.5 s in it_p15d, 5.7 s in open_cost, and **490.3 s in the soak** (18:59:36 to 19:07:46 UTC, a soft lockup and the clocksource watchdog). The soak's own report says STALL and that its rates are not quotable. The rates of open_cost and the soak are not used anywhere; their correctness results stand.
- **Not in this evidence:** the soak's own `open_at_end`. The soak's WAL is not kept, and its report does not print FLOW_STATS.

`SHA256SUMS` covers every file here, this README included.
