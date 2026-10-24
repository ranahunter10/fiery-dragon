## Census: super-producer

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 60.9 s, 408 windows, 20 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 556 | 9 | 0 | 40 | 57 | 0.00 |
| exit | spine | yes | 561 | 9 | 0 | 29 | 43 | 0.00 |
| fork | spine | yes | 562 | 9 | 0 | 36 | 61 | 0.00 |
| rename | spine | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| open | open | yes | 6,437,017 | 105,637 | 3,012 | 221,434 | 353,167 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 4,011 | 66 | 0 | 350 | 611 | 0.05 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 8 | 0 | 0 | 5 | 20 | 0.00 |
| rd_chr | file-not-emitted | no | 5 | 0 | 0 | 0 | 10 | 0.00 |
| rd_other | file-not-emitted | no | 11 | 0 | 0 | 9 | 10 | 0.00 |
| rd_sock | file-not-emitted | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_chr | file-not-emitted | no | 838,091 | 13,754 | 551 | 30,387 | 43,792 | 56.33 |
| wr_other | file-not-emitted | no | 60 | 1 | 0 | 10 | 20 | 0.00 |
| wr_sock | file-not-emitted | no | 1 | 0 | 0 | 0 | 5 | 0.00 |
| copy_range | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice_direct | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rcv | sock | yes | 23 | 0 | 0 | 5 | 60 | 0.00 |
| snd | sock | yes | 19 | 0 | 0 | 5 | 40 | 0.00 |
| uring | uring | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rename_exec | info | no | 556 | 9 | 0 | 39 | 57 | 0.00 |
| sys | info | no | 96,619,085 | 1,585,601 | 45,789 | 3,323,264 | 5,299,549 | 0.00 |

- Emitted records/s: mean 105,731, p99 221,670, max 353,461
- Estimated log bandwidth: mean 13.53 MB/s, p99 28.36 MB/s, max 45.23 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.067
- **Verdict (p99 vs budget): EXCEEDS BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
