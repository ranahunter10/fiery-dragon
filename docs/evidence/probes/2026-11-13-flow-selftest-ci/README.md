# The flow self-test and the planted lost FILE, on CI's runner kernel (2026-11-13)

Evidence for E-0251. This was not the target kernel. The VM run with `--flow` is the maintainer's (the matrix).

| File | What | Where it ran |
|---|---|---|
| `it-p15d-case13-14.txt` | it_p15d cases 13 and 14, as the job printed them, timestamps removed | GitHub Actions job 131679071323, kernel 7.0.0-1017-azure, PR #90 at commit `e3495b0` |

What it shows (MEAS, runner kernel):
- **The flow self-test ran at load and passed.** Case 13's p15d wrote `selftest.result: pass (spine, files, net, flow)` in its WAL header. A forked child made eight known transfers (a file's write and read, a writev and readv, a pipe, an AF_UNIX socketpair). Each was one FLOW with its kind and bytes, the file's on the open-file id of its OPEN, and each pseudo file had its FILE. A failure would have stopped p15d (exit SELFTEST).
- **Case 13 as before:** every transfer one FLOW with its bytes, nothing refused or lost, books B1 to B5 closed.
- **Case 14, a planted lost FILE** (`--test-flow-file-fail-first`: the first FILE of every file lost at the ring-reserve point):
  - on each of the four ends (a pipe's write and read ends, a socketpair's send and receive ends), the first FLOW names an id that never gets a FILE, and the next two name a new id whose FILE was written: the retry of review V3 works;
  - `file_lost` 12 (the four planted on the workload, the rest other processes' first FILEs), no FLOW lost, none refused;
  - the run ended exit 3, DEGRADED, with every book closed and the WAL valid in both readers.
- The first run of case 14 (job 131677481629, commit `67c54dd`) failed on the pipe's ends, because the check matched the interpreter's own module reads and its write of the pid. Commit `e3495b0` matches the workload's transfers by size too. The programs did not change between the two runs.

One run on a shared runner: correctness, not cost.

`SHA256SUMS` covers every file here, this README included.
