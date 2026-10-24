## Census: idle

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 62.7 s, 619 windows, 39 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 4 | 0 | 0 | 0 | 20 | 0.00 |
| exit | spine | yes | 2 | 0 | 0 | 0 | 20 | 0.00 |
| fork | spine | yes | 3 | 0 | 0 | 0 | 10 | 0.00 |
| rename | spine | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| open | open | yes | 142 | 2 | 0 | 20 | 894 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 114 | 2 | 0 | 10 | 775 | 0.00 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 4 | 0 | 0 | 0 | 15 | 0.00 |
| rd_chr | file-not-emitted | no | 3 | 0 | 0 | 0 | 20 | 0.00 |
| rd_other | file-not-emitted | no | 17 | 0 | 0 | 10 | 110 | 0.00 |
| rd_sock | file-not-emitted | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_chr | file-not-emitted | no | 2 | 0 | 0 | 0 | 20 | 0.00 |
| wr_other | file-not-emitted | no | 74 | 1 | 0 | 10 | 110 | 0.00 |
| wr_sock | file-not-emitted | no | 2 | 0 | 0 | 0 | 10 | 0.00 |
| copy_range | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice_direct | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rcv | sock | yes | 28 | 0 | 0 | 10 | 79 | 0.00 |
| snd | sock | yes | 20 | 0 | 0 | 10 | 60 | 0.00 |
| uring | uring | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| chmod | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| chown | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| link | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mkdir | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rename_file | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rmdir | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| symlink | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| truncate | meta | yes | 3 | 0 | 0 | 0 | 10 | 0.00 |
| unlink | meta | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| accept | net | yes | 1 | 0 | 0 | 0 | 10 | 0.00 |
| bind | net | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| connect | net | yes | 8 | 0 | 0 | 10 | 20 | 0.00 |
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
| mmap_exec | info | no | 43 | 1 | 0 | 0 | 318 | 0.00 |
| rename_exec | info | no | 4 | 0 | 0 | 0 | 20 | 0.00 |
| sys | info | no | 4,895 | 78 | 40 | 325 | 10,294 | 0.00 |

- Emitted records/s: mean 5, p99 51, max 1,918
- Estimated log bandwidth: mean 0.00 MB/s, p99 0.00 MB/s, max 0.18 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.068
- **Verdict (p99 vs budget): WITHIN BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
