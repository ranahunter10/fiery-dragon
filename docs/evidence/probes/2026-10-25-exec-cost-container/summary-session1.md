## Self-test per way

| Way | Verdict | Failed checks |
|---|---|---:|
| fixed | FAIL | 1 |
| output | PASS | 0 |
| dynptr | PASS | 0 |

Null syscall (getppid), ns per call over 10 rounds: median 101.3, min 96.3, max 144.4.

Records from other processes' execs during the measurements: 161 (their runs are inside run_cnt).

## argv 20 bytes

| Way | Rounds | Median ns/run | Min | Max | Median / null syscall |
|---|---:|---:|---:|---:|---:|
| fixed | 10 | 1797 | 1626 | 2170 | 17.7 |
| output | 10 | 1938 | 1704 | 2341 | 19.1 |
| dynptr | 10 | 1983 | 1742 | 4165 | 19.6 |

Paired by round, minus OUTPUT:

| Way | Median Δ ns | Min Δ | Max Δ | Rounds cheaper than OUTPUT |
|---|---:|---:|---:|---:|
| fixed | -166 | -523 | +257 | 8 of 10 |
| dynptr | -12 | -316 | +2460 | 6 of 10 |

## argv 200 bytes

| Way | Rounds | Median ns/run | Min | Max | Median / null syscall |
|---|---:|---:|---:|---:|---:|
| fixed | 10 | 1875 | 1529 | 2028 | 18.5 |
| output | 10 | 1940 | 1678 | 2225 | 19.2 |
| dynptr | 10 | 2092 | 1746 | 2461 | 20.7 |

Paired by round, minus OUTPUT:

| Way | Median Δ ns | Min Δ | Max Δ | Rounds cheaper than OUTPUT |
|---|---:|---:|---:|---:|
| fixed | -51 | -553 | +6 | 9 of 10 |
| dynptr | +94 | -177 | +344 | 3 of 10 |

## argv 1000 bytes

| Way | Rounds | Median ns/run | Min | Max | Median / null syscall |
|---|---:|---:|---:|---:|---:|
| fixed | 10 | 1859 | 1671 | 2061 | 18.4 |
| output | 10 | 2244 | 1888 | 2461 | 22.2 |
| dynptr | 10 | 2093 | 1892 | 2342 | 20.7 |

Paired by round, minus OUTPUT:

| Way | Median Δ ns | Min Δ | Max Δ | Rounds cheaper than OUTPUT |
|---|---:|---:|---:|---:|
| fixed | -379 | -561 | -123 | 10 of 10 |
| dynptr | -124 | -364 | +252 | 8 of 10 |
