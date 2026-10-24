## Census: exec-storm

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 62.1 s, 610 windows, 39 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 1,641 | 26 | 30 | 40 | 60 | 0.00 |
| exit | spine | yes | 1,639 | 26 | 30 | 40 | 49 | 0.00 |
| fork | spine | yes | 1,640 | 26 | 30 | 41 | 50 | 0.00 |
| rename | spine | yes | 4 | 0 | 0 | 0 | 20 | 0.00 |
| open | open | yes | 21,573 | 347 | 369 | 543 | 1,007 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 26,407 | 425 | 476 | 632 | 1,177 | 0.44 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 57 | 1 | 0 | 10 | 269 | 0.00 |
| rd_chr | file-not-emitted | no | 4 | 0 | 0 | 0 | 20 | 0.00 |
| rd_other | file-not-emitted | no | 17 | 0 | 0 | 10 | 40 | 0.00 |
| rd_sock | file-not-emitted | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_chr | file-not-emitted | no | 1,635 | 26 | 30 | 40 | 49 | 0.00 |
| wr_other | file-not-emitted | no | 61 | 1 | 0 | 10 | 11 | 0.00 |
| wr_sock | file-not-emitted | no | 7 | 0 | 0 | 0 | 30 | 0.00 |
| copy_range | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice_direct | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rcv | sock | yes | 113 | 2 | 0 | 20 | 269 | 0.00 |
| snd | sock | yes | 85 | 1 | 0 | 20 | 219 | 0.00 |
| uring | uring | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| chmod | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| chown | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| link | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mkdir | meta | yes | 1 | 0 | 0 | 0 | 10 | 0.00 |
| rename_file | meta | yes | 3 | 0 | 0 | 0 | 10 | 0.00 |
| rmdir | meta | yes | 1 | 0 | 0 | 0 | 10 | 0.00 |
| symlink | meta | yes | 1 | 0 | 0 | 0 | 10 | 0.00 |
| truncate | meta | yes | 7 | 0 | 0 | 10 | 10 | 0.00 |
| unlink | meta | yes | 3 | 0 | 0 | 0 | 20 | 0.00 |
| accept | net | yes | 3 | 0 | 0 | 0 | 10 | 0.00 |
| bind | net | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| connect | net | yes | 11 | 0 | 0 | 10 | 20 | 0.00 |
| connect_fail | net | yes | 6 | 0 | 0 | 0 | 41 | 0.00 |
| listen | net | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| io_uring_setup | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| memfd | cap | yes | 2 | 0 | 0 | 0 | 10 | 0.00 |
| mmap_shared_w | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| module_load | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mprotect_exec | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| process_vm_writev | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| ptrace | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| attr_other | info | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mmap_exec | info | no | 13,156 | 212 | 238 | 306 | 460 | 0.00 |
| rename_exec | info | no | 1,641 | 26 | 30 | 40 | 60 | 0.00 |
| sys | info | no | 275,294 | 4,430 | 4,744 | 6,850 | 13,807 | 0.00 |

- Emitted records/s: mean 856, p99 1,332, max 3,062
- Estimated log bandwidth: mean 0.08 MB/s, p99 0.13 MB/s, max 0.26 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.193
- **Verdict (p99 vs budget): WITHIN BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
