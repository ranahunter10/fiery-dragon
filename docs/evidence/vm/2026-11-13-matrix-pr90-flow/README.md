# The capture matrix on PR #90's head, with `--flow` (2026-11-13, 02:03 UTC)

Evidence for E-0246 and E-0247. The full matrix (`sudo tools/vm/measure_capture.sh -- --flow`, soak 600 s) on the VM at commit `99dc5bc`, clean. The run with p15d's defaults is in `../2026-11-13-matrix-pr90-default/`.

| File | What |
|---|---|
| `manifest.txt` | stamp, commit, kernel 7.0.0-38-generic, 3 CPUs, the Python used, options (`--flow`), the binaries' hashes |
| `steps.txt` | every step's exit code and duration: `open_cost` and `open_cost_report` `rc=1`, the other ten `rc=0` |
| `summary.md` | one line per figure, each from its step's report |
| `<step>.txt`, `<step>.err` | each step's raw output and its stderr |
| `open_cost-round3-p15d.log` | p15d's log of open_cost's round 3, kept on the VM because the round failed, as printed in the maintainer's terminal |
| `run-SHA256SUMS.txt` | the run's own checksums, written on the VM; they match every file here except the round-3 log, which was not part of the run directory |

Not copied: the `perf/perf-*.data` files (binary). `profile.txt` and `profile_callers.txt` are the reports made from them.

What it shows (MEAS, VM):

- **it_p15d: PASS, 0 failed checks.** That includes case 13, the flow programs under a workload of known sizes: every transfer is one FLOW with its bytes, books B1 to B5 closed. This is the first run of the flow programs on the target kernel. E-0245 was on CI's 7.0 runner.
- **Soak: PASS.** 96,835 FLOW records in 10 minutes. End: exit 0, state 0, invariant 1. Recall 100 % on every step kind; graph checks dropper 45/45, socket pairs 352/352, memfd 44/44. No spine or NET skips, no fentry skips, queue never full, no GAPs. p15d used 3.10 ms/s CPU (median) and 24.4 MiB. Samples came every 60 to 61 s, so this soak was not stalled.
- **open_cost: 20 of 21 rounds closed their books; round 3 did not.** Round 3 ended `exit=4 state=2 invariant=2` (INVALID, invariant broken), with reason `FLOW: vfs entries 250 != returns + excluded self + excluded kthread + owned by a socket`: book B1. Under its rule, the harness reports no timing for the whole step. The other rounds' timings are in `open_cost.txt` and were not summarised by hand.
- **Why B1 broke (SRC, E-0247).** p15d detaches the programs and then checks the books. In Linux 7.0, `unregister_fprobe()` removes the probe from the fprobe hash (`del_fprobe_hash`, `kernel/trace/fprobe.c`). From then on `fprobe_return()` skips the exit handler of every call that had already entered (`is_fprobe_still_exist(fp)`, line 485). A `vfs_read` or `vfs_write` that entered during the run and was still blocked at detach is therefore counted in SESS_ENTRY and never in SESS_RETURN. That the round-3 shortfall came from such a call is the only mechanism found that fits (INF). The log cannot show the size of the shortfall, because B1's message prints only the entry count.

`SHA256SUMS` covers every file here, this README included.
