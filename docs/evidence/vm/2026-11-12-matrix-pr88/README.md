# The capture matrix on PR #88's head (2026-11-12, 20:16 UTC)

Evidence for E-0234. The full matrix (`sudo tools/vm/measure_capture.sh`, soak 600 s) on the VM at commit `5a5fe4b`, clean, with p15d's defaults (16 × 1 MiB batches). #88 adds the FLOW and FILE records and their checks. No program writes either record yet, so this run checks that nothing else moved.

| File | What |
|---|---|
| `manifest.txt` | stamp, commit, kernel 7.0.0-38-generic, 3 CPUs, the Python used, options, the binaries' hashes |
| `steps.txt` | every step's exit code and duration: 12 steps, all `rc=0` |
| `summary.md` | one line per figure, each from its step's report |
| `<step>.txt`, `<step>.err` | each step's raw output and its stderr |
| `run-SHA256SUMS.txt` | the run's own checksums, written on the VM; they match every file here |

Not copied: the `perf/perf-*.data` files (binary). `profile.txt` and `profile_callers.txt` are the reports made from them.

What it shows (MEAS, VM):

| | #87's run (`../2026-11-12-matrix-pr87/`) | This run |
|---|---|---|
| it_p15d | PASS, 0 failed checks | PASS, 0 failed checks |
| Soak | PASS: no kernel skips, queue never full, no GAPs | PASS: no kernel skips, queue never full, no GAPs |
| Opens and closes recorded | 4,400,000 of 4,400,000, none lost | 4,400,000 of 4,400,000, none lost |
| Null syscall (median) | 99.9 ns | 93.8 ns |
| Added per open+close, in null syscalls (four arms) | 11.42, 11.72, 14.10, 14.76 | 12.30, 12.79, 14.68, 15.28 |
| p15d per open+close, after idle (median) | 251.4 ns | 224.0 ns |
| p15d in the soak, median | 5.34 ms/s, 23.4 MiB | 4.71 ms/s, 23.3 MiB |

The two runs' 95 % intervals overlap on every arm. Two runs give no paired comparison between commits, and #88 adds no work on any record p15d receives today (one more type compare in `p15_rec_check`, for types no program writes). The added-cost figures are therefore not a regression result in either direction.

`SHA256SUMS` covers every file here, this README included.
