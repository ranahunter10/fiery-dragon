## Census: known-ops

- bpftrace printed 6 non-JSON lines before starting (2 warnings); see the raw file

Duration 63.2 s, 625 windows, 39 probes attached.

| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |
|---|---|---|---:|---:|---:|---:|---:|---:|
| exec | spine | yes | 4 | 0 | 0 | 0 | 30 | 0.00 |
| exit | spine | yes | 52 | 1 | 0 | 0 | 120 | 0.00 |
| fork | spine | yes | 58 | 1 | 0 | 10 | 130 | 0.00 |
| rename | spine | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| open | open | yes | 391 | 6 | 0 | 160 | 1,021 | 0.00 |
| open_fail | open | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rd_reg | file | yes | 246 | 4 | 0 | 120 | 880 | 0.03 |
| wr_pipe | file | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_reg | file | yes | 61 | 1 | 0 | 10 | 497 | 0.00 |
| rd_chr | file-not-emitted | no | 5 | 0 | 0 | 0 | 20 | 0.00 |
| rd_other | file-not-emitted | no | 7 | 0 | 0 | 10 | 10 | 0.00 |
| rd_sock | file-not-emitted | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| wr_chr | file-not-emitted | no | 2 | 0 | 0 | 0 | 20 | 0.00 |
| wr_other | file-not-emitted | no | 63 | 1 | 0 | 10 | 12 | 0.00 |
| wr_sock | file-not-emitted | no | 1 | 0 | 0 | 0 | 10 | 0.00 |
| copy_range | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| splice_direct | xfer | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| rcv | sock | yes | 77 | 1 | 0 | 10 | 497 | 0.00 |
| snd | sock | yes | 69 | 1 | 0 | 10 | 497 | 0.00 |
| uring | uring | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| chmod | meta | yes | 50 | 1 | 0 | 0 | 497 | 0.00 |
| chown | meta | yes | 50 | 1 | 0 | 0 | 497 | 0.00 |
| link | meta | yes | 50 | 1 | 0 | 0 | 497 | 0.00 |
| mkdir | meta | yes | 51 | 1 | 0 | 0 | 507 | 0.00 |
| rename_file | meta | yes | 50 | 1 | 0 | 0 | 497 | 0.00 |
| rmdir | meta | yes | 51 | 1 | 0 | 0 | 497 | 0.00 |
| symlink | meta | yes | 50 | 1 | 0 | 0 | 497 | 0.00 |
| truncate | meta | yes | 56 | 1 | 0 | 10 | 497 | 0.00 |
| unlink | meta | yes | 151 | 2 | 0 | 0 | 1,492 | 0.00 |
| accept | net | yes | 51 | 1 | 0 | 0 | 497 | 0.00 |
| bind | net | yes | 2 | 0 | 0 | 0 | 20 | 0.00 |
| connect | net | yes | 57 | 1 | 0 | 10 | 497 | 0.00 |
| connect_fail | net | yes | 56 | 1 | 0 | 0 | 271 | 0.00 |
| listen | net | yes | 1 | 0 | 0 | 0 | 10 | 0.00 |
| io_uring_setup | cap | yes | 50 | 1 | 0 | 0 | 502 | 0.00 |
| memfd | cap | yes | 50 | 1 | 0 | 0 | 502 | 0.00 |
| mmap_shared_w | cap | yes | 50 | 1 | 0 | 0 | 502 | 0.00 |
| module_load | cap | yes | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mprotect_exec | cap | yes | 50 | 1 | 0 | 0 | 502 | 0.00 |
| process_vm_writev | cap | yes | 50 | 1 | 0 | 0 | 502 | 0.00 |
| ptrace | cap | yes | 50 | 1 | 0 | 0 | 120 | 0.00 |
| attr_other | info | no | 0 | 0 | 0 | 0 | 0 | 0.00 |
| mmap_exec | info | no | 51 | 1 | 0 | 0 | 344 | 0.00 |
| rename_exec | info | no | 4 | 0 | 0 | 0 | 30 | 0.00 |
| sys | info | no | 8,992 | 142 | 40 | 2,711 | 12,054 | 0.00 |

- Emitted records/s: mean 31, p99 590, max 8,762
- Estimated log bandwidth: mean 0.00 MB/s, p99 0.05 MB/s, max 0.59 MB/s
- Budget: 63.7 MB/s disk / 3.0x headroom = 21.23 MB/s
- Selectivity (emitted records per syscall): 0.221
- **Verdict (p99 vs budget): WITHIN BUDGET**
- Assumed record sizes (INF until ADR-0008): default 64 B, overrides {'exec': 256, 'open': 128, 'open_fail': 128}
