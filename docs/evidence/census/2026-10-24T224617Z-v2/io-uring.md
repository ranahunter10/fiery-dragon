## Census: io-uring

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 72.5 s, 696 windows, 39 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 4 | 0 | 0 | 0 | 30 | 0.00 |
| exit | spine | yes | 12 | 0 | 0 | 0 | 30 | 0.00 |
| fork | spine | yes | 12 | 0 | 0 | 0 | 30 | 0.00 |
| rename | spine | yes | 2 | 0 | 0 | 0 | 10 | 0.00 |
| open | open | yes | 584 | 8 | 0 | 80 | 1,126 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 447 | 6 | 0 | 40 | 827 | 0.00 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 65,554 | 904 | 0 | 20 | 34,467 | 3.70 |
| rd_chr | file-not-emitted | no | 10 | 0 | 0 | 10 | 20 | 0.00 |
| rd_other | file-not-emitted | no | 405 | 6 | 10 | 20 | 40 | 0.00 |
| rd_sock | file-not-emitted | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_chr | file-not-emitted | no | 3 | 0 | 0 | 0 | 20 | 0.00 |
| wr_other | file-not-emitted | no | 68 | 1 | 0 | 10 | 14 | 0.00 |
| wr_sock | file-not-emitted | no | 1 | 0 | 0 | 0 | 10 | 0.00 |
| copy_range | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice_direct | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rcv | sock | yes | 29 | 0 | 0 | 10 | 80 | 0.00 |
| snd | sock | yes | 21 | 0 | 0 | 10 | 60 | 0.00 |
| uring | uring | yes | 65,537 | 904 | 1,038 | 1,744 | 1,873 | 0.00 |
| chmod | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| chown | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| link | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mkdir | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rename_file | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rmdir | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| symlink | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| truncate | meta | yes | 11 | 0 | 0 | 10 | 10 | 0.00 |
| unlink | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| accept | net | yes | 1 | 0 | 0 | 0 | 10 | 0.00 |
| bind | net | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| connect | net | yes | 7 | 0 | 0 | 0 | 20 | 0.00 |
| connect_fail | net | yes | 6 | 0 | 0 | 0 | 60 | 0.00 |
| listen | net | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| io_uring_setup | cap | yes | 1 | 0 | 0 | 0 | 10 | 0.00 |
| memfd | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mmap_shared_w | cap | yes | 4 | 0 | 0 | 0 | 30 | 0.00 |
| module_load | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mprotect_exec | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| process_vm_writev | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| ptrace | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| attr_other | info | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mmap_exec | info | no | 95 | 1 | 0 | 0 | 430 | 0.00 |
| rename_exec | info | no | 4 | 0 | 0 | 0 | 30 | 0.00 |
| sys | info | no | 158,558 | 2,186 | 1,408 | 2,405 | 34,535 | 0.00 |

- Emitted records/s: mean 1,823, p99 1,809, max 34,474
- Estimated log bandwidth: mean 0.12 MB/s, p99 0.12 MB/s, max 2.21 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.834
- **Verdict (p99 vs budget): WITHIN BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
