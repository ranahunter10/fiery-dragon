## Self-test per way

| Way | Verdict | Failed checks |
|---|---|---:|
| fixed | FAIL | 1 |
| output | PASS | 0 |
| dynptr | PASS | 0 |

Null syscall (getppid), ns per call over 10 rounds: median 109.7, min 97.5, max 133.2.

Records from other processes' execs during the measurements: 0 (their runs are inside run_cnt).

## argv 20 bytes

| Way | Rounds | Median ns/run | Min | Max | Median / null syscall |
|---|---:|---:|---:|---:|---:|
| fixed | 10 | 1918 | 1545 | 2315 | 17.5 |
| output | 10 | 1841 | 1639 | 3712 | 16.8 |
| dynptr | 10 | 1947 | 1475 | 2170 | 17.7 |

Paired by round, minus OUTPUT:

| Way | Median Δ ns | Min Δ | Max Δ | Rounds cheaper than OUTPUT |
|---|---:|---:|---:|---:|
| fixed | +18 | -2113 | +549 | 5 of 10 |
| dynptr | +84 | -2013 | +502 | 4 of 10 |

## argv 200 bytes

| Way | Rounds | Median ns/run | Min | Max | Median / null syscall |
|---|---:|---:|---:|---:|---:|
| fixed | 10 | 1696 | 1599 | 2213 | 15.5 |
| output | 10 | 1951 | 1611 | 2206 | 17.8 |
| dynptr | 10 | 1800 | 1632 | 2547 | 16.4 |

Paired by round, minus OUTPUT:

| Way | Median Δ ns | Min Δ | Max Δ | Rounds cheaper than OUTPUT |
|---|---:|---:|---:|---:|
| fixed | -280 | -434 | +334 | 8 of 10 |
| dynptr | -34 | -373 | +669 | 6 of 10 |

## argv 1000 bytes

| Way | Rounds | Median ns/run | Min | Max | Median / null syscall |
|---|---:|---:|---:|---:|---:|
| fixed | 10 | 1913 | 1739 | 2073 | 17.4 |
| output | 10 | 2092 | 1818 | 2649 | 19.1 |
| dynptr | 10 | 2187 | 1906 | 2467 | 19.9 |

Paired by round, minus OUTPUT:

| Way | Median Δ ns | Min Δ | Max Δ | Rounds cheaper than OUTPUT |
|---|---:|---:|---:|---:|
| fixed | -199 | -576 | +69 | 9 of 10 |
| dynptr | +105 | -190 | +425 | 4 of 10 |
