## Census: idle

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 61.2 s, 611 windows, 20 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 4 | 0 | 0 | 0 | 40 | 0.00 |
| exit | spine | yes | 2 | 0 | 0 | 0 | 20 | 0.00 |
| fork | spine | yes | 2 | 0 | 0 | 0 | 10 | 0.00 |
| rename | spine | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| open | open | yes | 168 | 3 | 0 | 0 | 1,205 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 142 | 2 | 0 | 0 | 978 | 0.00 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 2 | 0 | 0 | 0 | 10 | 0.00 |
| rd_chr | file-not-emitted | no | 2 | 0 | 0 | 0 | 21 | 0.00 |
| rd_other | file-not-emitted | no | 5 | 0 | 0 | 0 | 10 | 0.00 |
| rd_sock | file-not-emitted | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_chr | file-not-emitted | no | 2 | 0 | 0 | 0 | 21 | 0.00 |
| wr_other | file-not-emitted | no | 64 | 1 | 0 | 10 | 20 | 0.00 |
| wr_sock | file-not-emitted | no | 1 | 0 | 0 | 0 | 10 | 0.00 |
| copy_range | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice_direct | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rcv | sock | yes | 17 | 0 | 0 | 0 | 79 | 0.00 |
| snd | sock | yes | 14 | 0 | 0 | 0 | 59 | 0.00 |
| uring | uring | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rename_exec | info | no | 4 | 0 | 0 | 0 | 40 | 0.00 |
| sys | info | no | 8,228 | 135 | 40 | 168 | 18,692 | 0.00 |

- Emitted records/s: mean 6, p99 0, max 2,381
- Estimated log bandwidth: mean 0.00 MB/s, p99 0.00 MB/s, max 0.24 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.043
- **Verdict (p99 vs budget): WITHIN BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
