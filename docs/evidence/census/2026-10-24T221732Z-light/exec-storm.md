## Census: exec-storm

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 60.5 s, 603 windows, 20 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 4,681 | 77 | 71 | 130 | 151 | 0.00 |
| exit | spine | yes | 4,686 | 77 | 71 | 131 | 151 | 0.00 |
| fork | spine | yes | 4,684 | 77 | 71 | 130 | 151 | 0.00 |
| rename | spine | yes | 2 | 0 | 0 | 0 | 20 | 0.00 |
| open | open | yes | 60,988 | 1,008 | 970 | 1,745 | 1,944 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 74,984 | 1,239 | 1,194 | 2,147 | 2,357 | 1.28 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 4 | 0 | 0 | 0 | 19 | 0.00 |
| rd_chr | file-not-emitted | no | 3 | 0 | 0 | 0 | 10 | 0.00 |
| rd_other | file-not-emitted | no | 10 | 0 | 0 | 10 | 40 | 0.00 |
| rd_sock | file-not-emitted | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_chr | file-not-emitted | no | 4,680 | 77 | 71 | 131 | 151 | 0.00 |
| wr_other | file-not-emitted | no | 63 | 1 | 0 | 10 | 20 | 0.00 |
| wr_sock | file-not-emitted | no | 2 | 0 | 0 | 0 | 10 | 0.00 |
| copy_range | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice_direct | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rcv | sock | yes | 21 | 0 | 0 | 0 | 60 | 0.00 |
| snd | sock | yes | 18 | 0 | 0 | 0 | 40 | 0.00 |
| uring | uring | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rename_exec | info | no | 4,681 | 77 | 71 | 130 | 151 | 0.00 |
| sys | info | no | 775,557 | 12,820 | 12,245 | 22,575 | 32,882 | 0.00 |

- Emitted records/s: mean 2,481, p99 4,274, max 4,753
- Estimated log bandwidth: mean 0.24 MB/s, p99 0.41 MB/s, max 0.46 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.193
- **Verdict (p99 vs budget): WITHIN BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
