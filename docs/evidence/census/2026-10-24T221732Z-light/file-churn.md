## Census: file-churn

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 61.4 s, 614 windows, 20 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 9 | 0 | 0 | 0 | 40 | 0.00 |
| exit | spine | yes | 6 | 0 | 0 | 0 | 40 | 0.00 |
| fork | spine | yes | 8 | 0 | 0 | 0 | 30 | 0.00 |
| rename | spine | yes | 4 | 0 | 0 | 0 | 40 | 0.00 |
| open | open | yes | 734,538 | 11,955 | 11,207 | 24,784 | 27,870 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 752,122 | 12,242 | 11,379 | 26,655 | 29,773 | 42.09 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 867,489 | 14,119 | 13,025 | 29,312 | 34,143 | 42.03 |
| rd_chr | file-not-emitted | no | 2 | 0 | 0 | 0 | 20 | 0.00 |
| rd_other | file-not-emitted | no | 15 | 0 | 0 | 10 | 60 | 0.00 |
| rd_sock | file-not-emitted | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_chr | file-not-emitted | no | 2 | 0 | 0 | 0 | 20 | 0.00 |
| wr_other | file-not-emitted | no | 63 | 1 | 0 | 10 | 20 | 0.00 |
| wr_sock | file-not-emitted | no | 7 | 0 | 0 | 0 | 60 | 0.00 |
| copy_range | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice_direct | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rcv | sock | yes | 103 | 2 | 0 | 10 | 339 | 0.00 |
| snd | sock | yes | 79 | 1 | 0 | 10 | 259 | 0.00 |
| uring | uring | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rename_exec | info | no | 9 | 0 | 0 | 0 | 40 | 0.00 |
| sys | info | no | 3,589,348 | 58,420 | 54,437 | 121,475 | 137,014 | 0.00 |

- Emitted records/s: mean 38,320, p99 79,951, max 90,990
- Estimated log bandwidth: mean 3.22 MB/s, p99 6.69 MB/s, max 7.61 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.656
- **Verdict (p99 vs budget): WITHIN BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
