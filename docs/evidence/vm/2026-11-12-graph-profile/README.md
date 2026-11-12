# The soak's recheck, its memory trend, and where the graph build's time goes (2026-11-12)

Evidence for E-0203. VM `p15-dev-2604`, PR #75 at `f9297f1`, on the files of the one-hour soak (E-0202, `/var/tmp/p15-soak`). `vm-session.txt` is the whole terminal.

## The recheck (MEAS)

With the per-step pairing check (E-0202), the hour **passes**: dropper chain 452 of 452, connections paired by ISN 3,608 of 3,608, memfd executions 451 of 451 (`build/soak2.txt`, sha256 `4cb80c6d...aa52c`, the hour's lines with the rechecked `graph_truth` lines spliced in).

## Memory over the hour (MEAS)

p15d's resident memory at each minute's sample: 24.4 MiB after the first minute, then +1.9 MiB over minutes 1 to 10, +0.56 over 10 to 20, +0.38 over 20 to 30, +0.25 over 30 to 40, +0.17 over 40 to 50, +0.03 over 50 to 60, ending at 27.65 MiB. Growth slows every ten minutes and flattens; the last 15 minutes add 24 KiB. That is a working set filling (map-mirrors, allocator arenas), not a leak at this rate. A longer run would check it; nothing here asks for one. CPU per minute: 4.0 to 5.4 ms/s, no trend.

## Where the 782 s went (MEAS)

`python -m p15.graph --profile` on the hour's WAL (1.92 M records; 55,247 processes):

| phase | s |
|---|---|
| proc_src (the process rows, DuckDB `executemany`) | 626.4 |
| raw tables (records to numpy columns) | 57.7 |
| reading the WAL, the process tree | 36.7 |
| all 36 statements of graph.sql | about 10 |

`executemany` costs about 11 ms per row on the VM (626 s / 55,247): DuckDB runs one statement per row. Loading the same rows as columns in one statement takes 2.4 us per row in the dev container, against 1,105 us with `executemany` (460 times faster; container, not the target).
