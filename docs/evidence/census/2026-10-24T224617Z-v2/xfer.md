## Census: xfer

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 65.5 s, 642 windows, 39 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 143 | 2 | 0 | 20 | 30 | 0.00 |
| exit | spine | yes | 145 | 2 | 0 | 20 | 21 | 0.00 |
| fork | spine | yes | 145 | 2 | 0 | 20 | 40 | 0.00 |
| rename | spine | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| open | open | yes | 3,526 | 54 | 0 | 308 | 722 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 2,331 | 36 | 0 | 329 | 623 | 0.08 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 72 | 1 | 0 | 30 | 50 | 1.03 |
| rd_chr | file-not-emitted | no | 69 | 1 | 0 | 30 | 60 | 1.03 |
| rd_other | file-not-emitted | no | 9 | 0 | 0 | 0 | 40 | 0.00 |
| rd_sock | file-not-emitted | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_chr | file-not-emitted | no | 2 | 0 | 0 | 0 | 20 | 0.00 |
| wr_other | file-not-emitted | no | 65 | 1 | 0 | 10 | 20 | 0.00 |
| wr_sock | file-not-emitted | no | 2 | 0 | 0 | 0 | 10 | 0.00 |
| copy_range | xfer | yes | 46 | 1 | 0 | 10 | 10 | 47.16 |
| splice | xfer | yes | 5,888 | 90 | 0 | 1,305 | 1,316 | 94.32 |
| splice_direct | xfer | yes | 92 | 1 | 0 | 10 | 11 | 94.32 |
| rcv | sock | yes | 30 | 0 | 0 | 10 | 79 | 0.00 |
| snd | sock | yes | 22 | 0 | 0 | 10 | 59 | 0.00 |
| uring | uring | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| chmod | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| chown | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| link | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mkdir | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rename_file | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rmdir | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| symlink | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| truncate | meta | yes | 97 | 1 | 0 | 10 | 11 | 0.00 |
| unlink | meta | yes | 3 | 0 | 0 | 0 | 20 | 0.00 |
| accept | net | yes | 1 | 0 | 0 | 0 | 10 | 0.00 |
| bind | net | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| connect | net | yes | 8 | 0 | 0 | 5 | 20 | 0.00 |
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
| mmap_exec | info | no | 1,012 | 15 | 0 | 142 | 218 | 0.00 |
| rename_exec | info | no | 143 | 2 | 0 | 20 | 30 | 0.00 |
| sys | info | no | 47,983 | 733 | 62 | 5,158 | 10,388 | 0.00 |

- Emitted records/s: mean 192, p99 1,940, max 2,109
- Estimated log bandwidth: mean 0.02 MB/s, p99 0.15 MB/s, max 0.16 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.262
- **Verdict (p99 vs budget): WITHIN BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
