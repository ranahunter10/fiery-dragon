# The first standing-matrix runs: today's defaults against 1 MiB batches (2026-11-12)

VM `p15-dev-2604`, kernel 7.0.0-38, 3 vCPUs. Branch `audit/capture-review` at b45a795, clean tree, same binaries in both runs (`build/p15d` f883465…). `sudo tools/vm/measure_capture.sh`, full mode (7 rounds of `prog_stats`, 20 of `open_cost`, 5 of `idle`, a 600 s soak). The defaults ran at 13:32Z and `--batch-kb 1024 --queue-batches 16` at 14:19Z, back to back in one tmux session; the first attempt died with its SSH window and is not used. `vm-session.txt` is the maintainer's terminal, as sent: both `summary.md` files and the failed steps' errors.

## 1. it_p15d "FAIL": the matrix's fault, not p15d's

In both runs `it_p15d` reported 43 failed checks. Every error is `ModuleNotFoundError: No module named 'google_crc32c'`. `it_p15d.sh` reads the WAL with `$P15_PYTHON`, which defaults to `python3`, and under sudo that is the system Python (`daemon/tests/it_p15d.sh` L14). The script did not export the Python it had found. **Fixed in this PR** (`export P15_PYTHON="$PY"` before the step). The functional cases are still to be rerun; nothing here says they fail.

The summary's `idle` and `soak` lines kept only the table headers (the greps missed the rows). Also fixed: the rows are kept now. The `soak` PASS lines are the soak's own verdict (recall 100 % for every step kind, graph checks complete, books 0).

## 2. The figures, side by side (MEAS)

| | defaults (256 KiB x 64) | 1 MiB x 16 |
|---|---|---|
| **programs, per open+close** (`prog_stats`, medians of 7 rounds): path / free / session | 281.0 / 211.5 / 172.1 = **664.6 ns** | 263.6 / 175.8 / 167.4 = **606.8 ns** |
| **added to a known file's open+close**, thread CPU (`open_cost`, 95 % interval) | 1,043.3 ns (990.6 to 1,100.2) | 996.9 ns (955.2 to 1,031.5) |
| added to a new file's open+close | 1,375.0 ns (1,304.7 to 1,485.0) | **1,251.9 ns (1,216.0 to 1,286.9)** |
| books | 4,400,000 opens and closes, none lost | the same |
| p15d per open+close above idle, mean | 420.4 ns | **201.2 ns** |
| p15d's thread switches per 1,000 open+close | 2.7 | 0.4 |
| p15d idle (during `open_cost`) | 1.26 ms per s | 1.28 ms per s |
| soak, 600 s of real programs | **PASS**; memory 23.5 to 25.7 MiB; WAL 27.4 MiB; skips 0; queue full 0; GAP 0 | **PASS**; 23.1 to 23.8 MiB; 26.7 MiB; the same zeros |
| checksum (`crc32c`, 4 KiB) | 0.0935 ns per byte, 22.9x the table | 0.0911, 21.5x |

What it shows:
- **p15d's CPU per open+close is halved by 1 MiB batches, again** (E-0220): 420 to 201 ns, and the wakes fall from 2.7 to 0.4 per 1,000.
- **The calling program may pay less too:**
  - A new file's open+close costs 123 ns less with 1 MiB batches, and the two intervals do not overlap.
  - For a known file the difference is 46 ns, and the intervals overlap.
  - The programs' bodies are 58 ns less, most of it in `file_free` (36 ns), whose code is the same in both runs.
  - E-0220 saw no such difference, and across sessions `file_free` has varied by about 50 ns. So this is **INF**: fewer cross-CPU wakes from p15d may disturb the workload's CPU less. A paired measurement in one run would settle it.
- **With 1 MiB batches the soak's real programs pass,** with nothing lost, and memory is no higher.

## 3. p15d's profile with 1 MiB batches (MEAS, `perf`, 90 samples, round 0)

| share | where |
|---|---|
| 18.9 % | `tiles`, the writer's first pass over a batch |
| 15.6 % | `finish_task_switch` (kernel: time with interrupts off, credited here, E-0218) |
| 7.8 % + 6.7 % + 6.7 % + 3.3 % | `bpf_prog_get_target_btf`, `fdget`, `after_poll`, `bpf_prog_get_info_by_fd` |
| 5.6 % | `on_bulk` |

**The drain's per-poll reading of each program's skip counter** (`BPF_OBJ_GET_INFO_BY_FD` per program, E-0199) now shows as about a quarter of p15d's samples: 24.5 % in those four lines. That cost is per poll, not per record, and the rest of p15d has shrunk, so it shows. **Next to measure**, before any change: how often the counters must be read. Today they are read after every poll (E-0199); how fast a skip must be noticed is ADR-0020's to say.

`SHA256SUMS` covers `vm-session.txt`.
