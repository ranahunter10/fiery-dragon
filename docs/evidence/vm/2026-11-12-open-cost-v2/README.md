# The open path's cost on today's main: the shipped programs over 7 rounds, the whole pipeline over 20, and the graph's WAL read timed against main (2026-11-12)

VM `p15-dev-2604`, kernel 7.0.0-38. The repository was at branch `docs/open-cost-research` 56b41c6; its BPF programs and p15d are main's 7273603. `vm-session.txt` is the maintainer's terminal, as sent. It completes `../2026-11-12-graph3-and-costs/` (E-0212), which had one round of `prog_stats` and no `open_cost`.

## 1. The shipped programs, unprofiled (MEAS, `bench/prim_cost/prog_stats.py`, 7 rounds, medians)

| program | ns per run | runs per open+close | ns per open+close | range of rounds |
|---|---|---|---|---|
| file_open_path (fentry) | 306.6 | 1.000 | 306.7 | 285.5 to 377.5 |
| file_free | 229.3 | 1.001 | 229.5 | 214.9 to 267.0 |
| file_open_session (entry + return) | 91.4 | 2.000 | 182.9 | 88.3 to 103.0 per run |
| **all** | | 4.003 | **741.4** | |

- This includes the kernel statistics' own cost in every run. The tool's README gives about 20 ns per run, so about 80 ns here (INF).
- The 500 ns budget (E-0193) is missed: by 241 ns as measured, about 160 net of that cost (INF).
- The profiled build gave 897.3 ns (E-0192), 156 ns more. That difference is about what its brackets cost (INF).

## 2. The whole pipeline (MEAS, `bench/open_cost`, 20 paired rounds; every traced arm's books closed, 4,400,000 of 4,400,000 opens and closes, none lost)

| | E-0176 (v1, 2026-11-11) | today (v2 + walk + adaptive poll) |
|---|---|---|
| null syscall without capture | 87.5 ns | 105.0 ns: **the host was about 20 % slower today** |
| open+close of a known file without capture | 885.4 ns | 1,061.4 ns |
| added by capture, known file (thread CPU) | 1,396.3 ns | **1,140.5 ns** (95 % 1,047.3 to 1,386.8; +108.6 %) |
| added, a file never seen | 1,748.0 ns | 1,606.1 ns |
| p15d idle | 14.65 ms per s | 1.83 ms per s |
| p15d per open+close above idle | 552.1 ns | 699.4 ns (median 656.8) |
| agent overhead as eAudit defines it | 46.0 % | 43.6 % (median) |
| bytes per open+close in the WAL | 171.6 | 171.6 |

How to read it:
- What capture adds to the program making the call fell by 256 ns (18 %) on a host that ran 20 % slower. Scaled by the null syscall, the fall is about 32 % (INF: host slowness need not scale every path alike).
- p15d's own CPU per open+close rose by 147 ns as measured, about 583 ns once scaled the same way: no change beyond noise (INF).
- The idle rate fell eightfold (ADR-0030). It is under the 2 ms per second budget (E-0193).

## 3. The graph's WAL read, main against this branch (MEAS, one build each, main first)

| phase | main 7273603 | branch (#79 to #81) |
|---|---|---|
| read the WAL, the process tree | 37.0 s | 45.6 s (+23 %) |
| raw tables | 25.0 s | 27.7 s (+11 %) |

- In the first phase, the branch changes only the RENAME branch of `proctree.py`: one comparison for each of the run's 58,756 RENAME records (SRC: `python/p15/proctree.py`; the counts are E-0211's `rename` 55,128 plus `rename_thread` 3,628). Even at 10 µs a comparison that is 0.6 s, not 8.6 s.
- The raw tables phase, which the branch does not change at all, slowed by 11 % in the same pair.
- So the difference is most likely the host (INF). One build each cannot show it either way; alternating builds would.
- E-0211's 67.7 s for the same phase is a third data point on how far this VM varies.

`SHA256SUMS` covers `vm-session.txt`.
