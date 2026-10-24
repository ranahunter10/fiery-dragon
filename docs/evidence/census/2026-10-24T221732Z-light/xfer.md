## Census: xfer

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 62.0 s, 618 windows, 20 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 185 | 3 | 0 | 20 | 30 | 0.00 |
| exit | spine | yes | 185 | 3 | 0 | 30 | 30 | 0.00 |
| fork | spine | yes | 189 | 3 | 0 | 20 | 20 | 0.00 |
| rename | spine | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| open | open | yes | 4,578 | 74 | 0 | 474 | 1,110 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 3,031 | 49 | 0 | 403 | 837 | 0.11 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 68 | 1 | 0 | 0 | 295 | 1.08 |
| rd_chr | file-not-emitted | no | 67 | 1 | 0 | 0 | 295 | 1.08 |
| rd_other | file-not-emitted | no | 5 | 0 | 0 | 0 | 12 | 0.00 |
| rd_sock | file-not-emitted | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_chr | file-not-emitted | no | 2 | 0 | 0 | 0 | 20 | 0.00 |
| wr_other | file-not-emitted | no | 64 | 1 | 0 | 10 | 10 | 0.00 |
| wr_sock | file-not-emitted | no | 2 | 0 | 0 | 0 | 10 | 0.00 |
| copy_range | xfer | yes | 60 | 1 | 0 | 10 | 11 | 64.98 |
| splice | xfer | yes | 7,680 | 124 | 0 | 1,294 | 1,305 | 129.95 |
| splice_direct | xfer | yes | 120 | 2 | 0 | 10 | 11 | 129.95 |
| rcv | sock | yes | 32 | 1 | 0 | 0 | 141 | 0.00 |
| snd | sock | yes | 20 | 0 | 0 | 0 | 71 | 0.00 |
| uring | uring | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rename_exec | info | no | 185 | 3 | 0 | 20 | 30 | 0.00 |
| sys | info | no | 64,541 | 1,042 | 41 | 7,506 | 18,674 | 0.00 |

- Emitted records/s: mean 261, p99 2,236, max 2,527
- Estimated log bandwidth: mean 0.02 MB/s, p99 0.18 MB/s, max 0.21 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.250
- **Verdict (p99 vs budget): WITHIN BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
