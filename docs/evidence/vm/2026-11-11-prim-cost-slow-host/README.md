# The first cost-breakdown run on the VM: the host was slow, so no cost is quotable (2026-11-11)

Evidence for E-0180. VM `p15-dev-2604`, 7.0.0-38-generic, 3 vCPU, tree at `13bbbf0` (PR #69 stacked on #67 and #68; `build/p15d` from `6adb48e`, whose daemon, BPF and schema sources are the same). Commands: `sudo build/prim_cost 20 20000`, `summarize.py`, and `prog_stats.py --p15d build/p15d --ops 220000 -- build/open_cost /var/tmp/p15-open-cost 200000 20000`.

`prim_cost.txt`, `prim_cost.md` and `prog_stats.txt` are the maintainer's files, rebuilt here from his paste, byte for byte: sha256 `7b90b03c...1d094`, `cfd6d716...4594e` and `bd979ecb...5a1b5`, as the VM printed them.

## What the files show (MEAS)

- **The host was not at the speed of the open-cost run (E-0176).** `prog_stats.txt`'s workload rows: 10^6 null syscalls took 355,199,666 ns of thread CPU, and 200,000 open+close of the known file took 2,259,999,315 ns. E-0176 measured 89.1 ns per null syscall and 2,281.2 ns per open+close with p15d running. No BPF program runs on `getppid`, so the statistics switch does not explain the null syscall.
- **The speed changed inside the `prim_cost` run.** Round 16 has the empty loop at 79,321 ns and the clock read at 553,573 ns for 20,000 iterations; the other rounds have 160,626 to 329,377 ns and 1,260,835 to 1,950,733 ns.
- **Run counts (exact, not timings):** 880,289 program runs for 220,000 open+close: `file_open_path` 220,047, `file_open_session` 440,094 (entry and return), `file_free` 220,132.

## What is not shown

- No cost per run, per record or per map operation: every nanosecond figure in these files was taken on a host of unknown and changing speed. They are not laid next to E-0176 or E-0138.
- Why the host was slow (power source, power mode, another load): not recorded by the run. E-0108 saw a 2-4 times slowdown on battery.

## What follows

Neither harness could tell this run from a good one. Both now record a null-syscall cost in every round and the report judges it (E-0181, `bench/prim_cost/README.md`). `summarize.py` at that commit, run on `prim_cost.txt`, gives the same table and the line "no host line in this run ... Not quotable".
