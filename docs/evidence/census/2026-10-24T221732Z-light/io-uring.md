## Census: io-uring

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 64.8 s, 648 windows, 20 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 4 | 0 | 0 | 0 | 30 | 0.00 |
| exit | spine | yes | 13 | 0 | 0 | 0 | 40 | 0.00 |
| fork | spine | yes | 11 | 0 | 0 | 10 | 40 | 0.00 |
| rename | spine | yes | 3 | 0 | 0 | 0 | 10 | 0.00 |
| open | open | yes | 612 | 9 | 0 | 80 | 1,243 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 466 | 7 | 0 | 79 | 932 | 0.00 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 65,545 | 1,011 | 0 | 23,099 | 234,066 | 4.14 |
| rd_chr | file-not-emitted | no | 3 | 0 | 0 | 0 | 20 | 0.00 |
| rd_other | file-not-emitted | no | 381 | 6 | 10 | 20 | 30 | 0.00 |
| rd_sock | file-not-emitted | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_chr | file-not-emitted | no | 3 | 0 | 0 | 0 | 20 | 0.00 |
| wr_other | file-not-emitted | no | 67 | 1 | 0 | 10 | 20 | 0.00 |
| wr_sock | file-not-emitted | no | 1 | 0 | 0 | 0 | 10 | 0.00 |
| copy_range | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice_direct | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rcv | sock | yes | 19 | 0 | 0 | 0 | 80 | 0.00 |
| snd | sock | yes | 16 | 0 | 0 | 10 | 60 | 0.00 |
| uring | uring | yes | 159,145 | 2,454 | 2,711 | 5,315 | 6,525 | 0.00 |
| rename_exec | info | no | 4 | 0 | 0 | 0 | 30 | 0.00 |
| sys | info | no | 256,759 | 3,960 | 3,141 | 24,100 | 234,453 | 0.00 |

- Emitted records/s: mean 3,483, p99 23,099, max 234,106
- Estimated log bandwidth: mean 0.22 MB/s, p99 1.48 MB/s, max 14.98 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.880
- **Verdict (p99 vs budget): WITHIN BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
