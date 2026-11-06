# EXEC cost per build way on the VM (decision 4, ADR-0025 rule 8; 2026-11-06)

**Where:** the VM `p15-dev-2604` (7.0.0-38-generic, 3 vCPUs), host on its charger in Best performance mode, `main` at `5edf081` (the last commit with `bench/rb_cost`). `sudo stdbuf -oL make bench-exec-cost`: 10 rounds x 1,000 execs x argv 20, 200, 1,000 B, the way order rotated each round, a null-syscall baseline per round.

**Files:**
- [`exec-cost-raw.txt`](exec-cost-raw.txt): the harness's raw lines (`build/exec_cost.txt`).
- [`exec-cost-vm.txt`](exec-cost-vm.txt): the terminal: the build, the same raw lines, and `summarize.py`'s report.

The raw lines are identical in the two files, and `summarize.py` from `main`, run on `exec-cost-raw.txt` in the dev container, reproduces the VM's report byte for byte. Neither file has been checked against a sha256 printed on the VM.

## Results (MEAS: raw per-run costs with `bpf_stats` on, not an ADR-0018 overhead estimate)
- Every measurement delivered all 1,000 records, each one correct (`invalid`, `wrong_size`, `wrong_argv` all 0). 5 records from other processes' execs, in one row, are inside that row's `run_cnt`.
- Self-test per way as designed: `fixed` fails exactly the one check "every record takes exactly its len in the ring" (it reserves 1,344 B per exec); `output` and `dynptr` pass all.
- Null syscall: median 100.5 ns (95.0-110.7). One EXEC run costs about 2.9-3.8 µs median, 29-38 null syscalls.
- Paired by round, minus `output` (median Δ, rounds where the other way was cheaper):

| argv | fixed | dynptr |
|---|---|---|
| 20 B | +160 ns, 3 of 10 | +592 ns, 1 of 10 |
| 200 B | +106 ns, 3 of 10 | +524 ns, 0 of 10 |
| 1,000 B | -85 ns, 6 of 10 | +389 ns, 3 of 10 |

## Reading
- `output` against `fixed`: not resolved. The sign changes between rounds at every argv size, and the paired ranges span about -1,000 to +670 ns.
- `dynptr` costs more than `output` at every size by median; at 200 B in all 10 rounds.
- So `output` is not shown to cost more than either removed way: ADR-0025 rule 8's condition for removing them holds. This differs from the dev container (E-0076), where `fixed` was 51-379 ns cheaper at 200 and 1,000 B.
- The criterion is the paired sign count and range, not an A/A floor: this bench has no A/A arm.
