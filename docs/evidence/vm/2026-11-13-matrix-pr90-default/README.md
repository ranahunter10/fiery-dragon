# The capture matrix on PR #90's head, p15d's defaults (2026-11-13, 02:33 UTC)

Evidence for E-0248 and E-0249. The full matrix (`sudo tools/vm/measure_capture.sh`, soak 600 s) on the VM at commit `99dc5bc`, clean, with p15d's defaults. `--flow` is off by default, so this run checks that #90 moved nothing else. The `--flow` run is in `../2026-11-13-matrix-pr90-flow/`.

| File | What |
|---|---|
| `manifest.txt` | stamp, commit, kernel 7.0.0-38-generic, 3 CPUs, the Python used, options, the binaries' hashes |
| `steps.txt` | every step's exit code and duration: 12 steps, all `rc=0` |
| `summary.md` | one line per figure, each from its step's report |
| `<step>.txt`, `<step>.err` | each step's raw output and its stderr |
| `run-SHA256SUMS.txt` | the run's own checksums, written on the VM; they match every file here |

Not copied: the `perf/perf-*.data` files (binary). `profile.txt` and `profile_callers.txt` are the reports made from them.

What it shows (MEAS, VM):

| | #88's run (`../2026-11-12-matrix-pr88/`) | This run |
|---|---|---|
| it_p15d | PASS, 0 failed checks | PASS, 0 failed checks |
| Soak | PASS: no kernel skips, queue never full, no GAPs | PASS: no spine or NET skips, queue never full, no GAPs; 22 fentry skips on the open path, all 22 written by the session return (below) |
| Opens and closes recorded | 4,400,000 of 4,400,000, none lost | 4,400,000 of 4,400,000, none lost |
| Null syscall (median) | 93.8 ns | 88.2 ns |
| Added per open+close, in null syscalls (four arms) | 12.30, 12.79, 14.68, 15.28 | 11.67, 12.50, 14.74, 15.60 |
| p15d per open+close, after idle (median) | 224.0 ns | 221.2 ns |
| p15d in the soak, median | 4.71 ms/s, 23.3 MiB | 2.54 ms/s, 24.2 MiB (not comparable: the stall below) |

The two runs' 95 % intervals overlap on every open_cost arm. As with #88, two runs give no paired comparison between commits, so these are not a regression result in either direction.

**The soak was stalled (E-0249).** The soak samples every 60 s, and its first sample came at t=454 s: one `time.sleep(60)` took about 454 s of `CLOCK_MONOTONIC`. Then samples came 60 s apart (t=514, 574, 634). Over its 600 s, the workload finished 16 or 17 steps of each kind, against 45 in the `--flow` run 30 minutes earlier. That fits roughly 200 s of real work (INF). The soak's harness does not detect this; nothing in `soak_report.txt` marks it. The correctness results stand: recall is 100 % on every step kind, the books closed and the graph checks match. The rates (CPU per second, WAL KiB/s) cover a run that was mostly frozen, so they are not compared with any other run. p15d's `poll_gap_max` did not show the stall because the gauge is reset at every stats interval.

**The 22 fentry skips.** `file_stats` in `soak.txt`: `fentry_missed=22`, `missing_emitted=22` (14 with their path walked, 8 without a path), `open_lost=0`. Each open the path program missed was written by the session return, as the fallback was built to do (E-0089's recursion guard). This is the first soak that shows the fallback being used.

`SHA256SUMS` covers every file here, this README included.
