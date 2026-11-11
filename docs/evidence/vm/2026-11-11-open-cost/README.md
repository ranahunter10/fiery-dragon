# What capture adds to an open and a close: the first whole-pipeline numbers (VM, 2026-11-11)

Evidence for E-0176. VM `p15-dev-2604`, 7.0.0-38-generic, 3 vCPU. The harness of PR #67 (`bench/open_cost`, at `bench/open-cost`) run against p15d built from PR #68 (`daemon/drain-room-first`, the drain fix of E-0174): the first run, on main's daemon, could not be timed (E-0173).

`open_cost.txt` (raw lines) and `open_cost.md` (the report) are the maintainer's files, byte for byte: sha256 `8616c248...30b6` and `f65a9e9e...a5ad`, as the VM printed them. `summarize.py` run here on the raw lines gives the same report, byte for byte.

20 rounds, p15d with its default options (spine, NET, file identity), 200,000 + 20,000 open+close per arm. **Every traced arm's books closed:** 4,400,000 of 4,400,000 opens in the WAL with their CLOSE, no PATH_MISSING, nothing lost, exit 0 each time.

| What (MEAS) | Value |
|---|---|
| open+close of a file capture knows, thread CPU, without capture | 885.4 ns (median; 856.7 to 910.5) |
| ... with p15d | 2,281.2 ns (2,221.4 to 2,323.3) |
| ... added (the primary metric) | **1,396.3 ns** (1,367.6 to 1,440.6); +157.8 % (+153.3 to +162.4), p = 1.9e-6 |
| open+close of a file never seen, thread CPU, added | **1,748.0 ns** (1,662.3 to 1,860.5); +145.9 % |
| added wall time, known file / new file | 1,560.1 ns / 1,997.9 ns (the host drifted during the run: the report's flag) |
| A/A control (none2 against none), known file | 879.3 ns against 885.4 ns |
| null syscall without / with p15d | 87.5 ns / 89.1 ns |
| records per open+close | 2.000 |
| bytes per open+close in the WAL | 171.6 (OPEN 115.6, CLOSE 56.0) |
| p15d idle | 14.65 ms of CPU per second |
| p15d per open+close, above its idle rate | 552.1 ns (mean) |
| agent overhead of the opens (p15d CPU above idle / the opens' CPU without capture) | 60.1 % (51.2 to 71.7) |
| agent overhead, eAudit's definition, whole workload | 46.0 % |

How to read it:
- The percentages are an upper bound by construction: the workload does nothing but open and close. The numbers that transfer are the added ns.
- Per open+close, capture costs about 1.4 µs on the program's own thread and about 0.55 µs of p15d's CPU elsewhere.
- The hook paths alone, measured earlier with trivial bodies on this VM (E-0138, on `vfs_read`): fentry 14.2 ns, kprobe.multi entry about 24 ns, kprobe.session 141.0 ns. One open+close runs one of each. That is about 180 ns; **the rest, about 1.2 µs, is in the programs' bodies (INF, by subtraction across two harnesses)**. Which part (the maps, `bpf_d_path`, the two ring records) is not known: a per-program measurement is the next step.

Limits: one thread, one burst of about 0.5 s per arm, an idle VM otherwise; the host was on its charger (not re-checked for this run). Not a workload overhead.
