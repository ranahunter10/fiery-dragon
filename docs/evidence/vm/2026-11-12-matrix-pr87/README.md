# The capture matrix on PR #87's head (2026-11-12, 19:26 to 19:48 UTC)

Evidence for E-0230. The first full matrix (`sudo tools/vm/measure_capture.sh`, not `--quick`, soak 600 s) in which every step passed. It ran on the VM at commit `5c6f1e3`, clean, with p15d's own defaults, which are now 16 × 1 MiB batches.

| File | What |
|---|---|
| `manifest.txt` | stamp, commit, kernel 7.0.0-38-generic, 3 CPUs, the Python used, options, the binaries' hashes |
| `steps.txt` | every step's exit code and duration: 12 steps, all `rc=0` |
| `summary.md` | one line per figure, each from its step's report |
| `<step>.txt`, `<step>.err` | each step's raw output and its stderr |
| `run-SHA256SUMS.txt` | the run's own checksums, written on the VM; they match every file here (`sha256sum -c run-SHA256SUMS.txt`) |

Not copied: the four `perf/perf-*.data` files (6.6 MB, binary). `profile.txt` and `profile_callers.txt` are the reports made from them.

What it shows (MEAS, VM):
- **it_p15d:** PASS, 0 failed checks.
- **soak** (600 s, seven workloads, three attack chains): PASS. Every expected record was found, there were no kernel skips (spine 0, NET 0), the queue was never full, and there were no GAP records. p15d used 5.34 ms of CPU per second (median) and 23.4 MiB resident.
- **open_cost:** 4,400,000 opens and closes, every one with its OPEN (path included) and CLOSE record, none lost to the ring. Capture added 1,140.8 to 1,475.2 ns per open+close over the four arms.
- **The host was slower than in the b1024 run** (`../2026-11-12-matrix-defaults-vs-b1024/`, same 1 MiB batches, commit `b45a795`): the null syscall's median was 99.9 ns here against 86.3 ns there. Counted in null syscalls, the added cost is the same within 0.8 of one (11.42, 11.72, 14.10, 14.76 here against 11.55, 12.38, 14.51, 14.90). The rise in nanoseconds is the host's, not the code's: between the two commits only the defaults' location changed (an option became the default).
- **p15d per open+close:** 251.4 ns after idle (201.2 ns in the b1024 run). This figure is not normalized; 16 % of the rise is the host's (the null syscall), and the rest is not explained by this run.
- **The profile's top symbol is `tiles`** (daemon/wal.c L57), the writer's walk over every record header in a batch before its CRC: 25.8 % of 97 samples here, 18.9 % of 90 in the b1024 run. 97 samples are too few for a share to be a result, so its cost is INF until a longer profile measures it.

`SHA256SUMS` covers every file here, this README included.
