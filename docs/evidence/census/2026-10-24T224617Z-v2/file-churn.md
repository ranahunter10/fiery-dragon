## Census: file-churn

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 63.8 s, 629 windows, 39 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 8 | 0 | 0 | 4 | 20 | 0.00 |
| exit | spine | yes | 17 | 0 | 0 | 0 | 70 | 0.00 |
| fork | spine | yes | 11 | 0 | 0 | 10 | 40 | 0.00 |
| rename | spine | yes | 8 | 0 | 0 | 0 | 30 | 0.00 |
| open | open | yes | 206,878 | 3,244 | 3,415 | 4,685 | 7,587 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 211,580 | 3,318 | 3,462 | 5,338 | 8,879 | 11.42 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 243,726 | 3,822 | 4,020 | 5,318 | 8,289 | 11.38 |
| rd_chr | file-not-emitted | no | 3 | 0 | 0 | 0 | 20 | 0.00 |
| rd_other | file-not-emitted | no | 33 | 1 | 0 | 11 | 50 | 0.00 |
| rd_sock | file-not-emitted | no | 1 | 0 | 0 | 0 | 10 | 0.00 |
| wr_chr | file-not-emitted | no | 2 | 0 | 0 | 0 | 20 | 0.00 |
| wr_other | file-not-emitted | no | 76 | 1 | 0 | 10 | 70 | 0.00 |
| wr_sock | file-not-emitted | no | 7 | 0 | 0 | 0 | 11 | 0.00 |
| copy_range | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice_direct | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rcv | sock | yes | 261 | 4 | 0 | 140 | 543 | 0.00 |
| snd | sock | yes | 191 | 3 | 0 | 80 | 404 | 0.00 |
| uring | uring | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| chmod | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| chown | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| link | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mkdir | meta | yes | 8 | 0 | 0 | 0 | 50 | 0.00 |
| rename_file | meta | yes | 4 | 0 | 0 | 0 | 11 | 0.00 |
| rmdir | meta | yes | 8 | 0 | 0 | 0 | 50 | 0.00 |
| symlink | meta | yes | 2 | 0 | 0 | 0 | 11 | 0.00 |
| truncate | meta | yes | 12 | 0 | 0 | 10 | 17 | 0.00 |
| unlink | meta | yes | 68,878 | 1,080 | 1,128 | 1,593 | 3,459 | 0.00 |
| accept | net | yes | 4 | 0 | 0 | 0 | 10 | 0.00 |
| bind | net | yes | 1 | 0 | 0 | 0 | 10 | 0.00 |
| connect | net | yes | 14 | 0 | 0 | 10 | 21 | 0.00 |
| connect_fail | net | yes | 9 | 0 | 0 | 0 | 40 | 0.00 |
| listen | net | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| io_uring_setup | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| memfd | cap | yes | 2 | 0 | 0 | 0 | 11 | 0.00 |
| mmap_shared_w | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| module_load | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mprotect_exec | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| process_vm_writev | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| ptrace | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| attr_other | info | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mmap_exec | info | no | 120 | 2 | 0 | 71 | 292 | 0.00 |
| rename_exec | info | no | 8 | 0 | 0 | 4 | 20 | 0.00 |
| sys | info | no | 1,020,092 | 15,997 | 16,699 | 23,881 | 37,774 | 0.00 |

- Emitted records/s: mean 11,473, p99 16,669, max 27,308
- Estimated log bandwidth: mean 0.94 MB/s, p99 1.37 MB/s, max 2.23 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.717
- **Verdict (p99 vs budget): WITHIN BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
