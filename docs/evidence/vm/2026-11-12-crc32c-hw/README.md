# p15d with CRC32C by the CPU's crc32 instruction (#83), and its thread switches (#84) (2026-11-12)

VM `p15-dev-2604`, kernel 7.0.0-38, branch `bench/open-cost-switches` at 34284f0 (#82, #83 and #84 stacked; BPF as main's). `vm-session.txt` is the maintainer's terminal, as sent.

## 1. The function alone (MEAS, `bench/crc32c`, 9 rounds, medians)

| buffer | table | SSE4.2 | speed-up |
|---|---|---|---|
| 4,096 bytes (a batch) | 1.977 ns per byte | 0.0916 | 21.6x |
| 120 bytes (about an OPEN) | 2.029 | 0.1008 | 20.1x |

Both gave the same CRC. At the table's rate, the 171.6 bytes of an open+close's records cost about 339 ns to checksum once; at the instruction's rate, about 16 (INF: one buffer, a hot cache).

## 2. p15d per open+close (MEAS, `bench/open_cost`, 20 paired rounds; books closed, 4,400,000 opens and closes, none lost)

| | E-0213 (table) | now (SSE4.2) |
|---|---|---|
| p15d CPU per open+close above idle, mean | 699.4 ns | **455.1 ns** (−244, −35 %) |
| the same, median | 656.8 ns | **417.3 ns** (−36 %) |
| agent overhead, eAudit's definition (median) | 43.6 % | **28.6 %** |
| p15d idle | 1.83 ms per s | 1.12 ms per s |

- This session's untraced arms disagreed: `none` 987.0 and `none2` 1,089.8 ns per known-file open+close, and the report flags drift. So the end-to-end added cost from this run is weak. p15d's own CPU is read from p15d's threads alone and does not depend on those arms.
- The terminal's `grep -A8` stopped one line short of the "added per open+close" line; it is in `build/oc_crc.md` on the VM.

## 3. Thread switches: few (MEAS, #84)

- **p15d's threads switched 3.1 times per 1,000 open+close** in the workload's window (median), and 8.7 times per second idle.
- That is too few to be a third of p15d's time. So **the reading of E-0215's kernel samples as "thread switching" was wrong.** `_raw_spin_unlock_irq` and `finish_task_switch` are where samples land when interrupts come back on.
- On this VM, perf samples by `task-clock`, a software timer (VirtualBox gives no hardware PMU), and a timer interrupt cannot fire while interrupts are off. So time spent with interrupts off is credited to the point that turns them back on (INF; the standard behaviour of timer-based sampling).
- The time is real, but its owner is whatever ran with interrupts off just before. The call graphs in `/var/tmp/p15-perf2/perf-0.data` can name it (command in the session).

## 4. p15d's profile now (MEAS, `perf`, round 0 of 3, 107 samples)

| share | where |
|---|---|
| 30.8 % + 9.3 % | `_raw_spin_unlock_irq`, `finish_task_switch` (kernel; see §3) |
| 10.3 % | `tiles`: the writer's first pass over a batch, so likely carrying the cache misses of reading what the drain wrote on another CPU (INF) |
| 7.5 % | `on_bulk` |
| **6.5 %** | `crc_hw`, from 32.6 % |
| 5.6 % | `p15_rec_check` |

`SHA256SUMS` covers `vm-session.txt`.
