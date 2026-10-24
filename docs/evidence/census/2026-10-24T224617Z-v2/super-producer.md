## Census: super-producer

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 63.2 s, 474 windows, 39 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 100 | 2 | 0 | 24 | 60 | 0.00 |
| exit | spine | yes | 111 | 2 | 0 | 16 | 37 | 0.00 |
| fork | spine | yes | 106 | 2 | 0 | 20 | 101 | 0.00 |
| rename | spine | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| open | open | yes | 1,127,169 | 17,825 | 1,588 | 64,027 | 71,467 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 774 | 12 | 0 | 140 | 615 | 0.01 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 6 | 0 | 0 | 0 | 20 | 0.00 |
| rd_chr | file-not-emitted | no | 4 | 0 | 0 | 0 | 20 | 0.00 |
| rd_other | file-not-emitted | no | 4 | 0 | 0 | 0 | 10 | 0.00 |
| rd_sock | file-not-emitted | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_chr | file-not-emitted | no | 146,860 | 2,322 | 101 | 8,601 | 9,305 | 9.51 |
| wr_other | file-not-emitted | no | 59 | 1 | 0 | 10 | 13 | 0.00 |
| wr_sock | file-not-emitted | no | 1 | 0 | 0 | 0 | 10 | 0.00 |
| copy_range | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice_direct | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rcv | sock | yes | 24 | 0 | 0 | 10 | 69 | 0.00 |
| snd | sock | yes | 16 | 0 | 0 | 10 | 60 | 0.00 |
| uring | uring | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| chmod | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| chown | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| link | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mkdir | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rename_file | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rmdir | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| symlink | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| truncate | meta | yes | 4 | 0 | 0 | 0 | 10 | 0.00 |
| unlink | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| accept | net | yes | 1 | 0 | 0 | 0 | 10 | 0.00 |
| bind | net | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| connect | net | yes | 7 | 0 | 0 | 10 | 20 | 0.00 |
| connect_fail | net | yes | 6 | 0 | 0 | 0 | 40 | 0.00 |
| listen | net | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| io_uring_setup | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| memfd | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mmap_shared_w | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| module_load | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mprotect_exec | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| process_vm_writev | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| ptrace | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| attr_other | info | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mmap_exec | info | no | 617 | 10 | 0 | 139 | 402 | 0.00 |
| rename_exec | info | no | 100 | 2 | 0 | 25 | 60 | 0.00 |
| sys | info | no | 16,919,902 | 267,565 | 23,920 | 962,519 | 1,073,362 | 0.00 |

- Emitted records/s: mean 17,843, p99 64,032, max 71,470
- Estimated log bandwidth: mean 2.28 MB/s, p99 8.20 MB/s, max 9.15 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.067
- **Verdict (p99 vs budget): WITHIN BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
