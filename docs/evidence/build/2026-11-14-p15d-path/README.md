# p15d's user-space path per step: container run (2026-11-14)

Dev container (`env.txt`: kernel 6.18, 2 vCPU, Xeon 2.1 GHz, gcc 13.3). Harness: `bench/p15d_path/p15d_path.c` (p15d's own `p15_rec_check`, queue, CRC32C and `p15w_append`; no kernel ring). Note: `docs/research/2026-11-14-costs-and-sota-lessons.md` §2. Journal: E-0314.

```
make build/p15d_path
D=$(mktemp -d /dev/shm/p15path-XXXX); build/p15d_path $D 9 1024; rm -rf $D     # p15d_path-1024k.txt
D=$(mktemp -d /dev/shm/p15path-XXXX); build/p15d_path $D 7 64; rm -rf $D       # p15d_path-64k.txt
```

| Step (ns per record, median) | 1 MiB batches | 64 KiB batches |
|---|---|---|
| check | 6.6 | 6.1 |
| copy | 2.6 | 2.3 |
| queue | 0.0 | 0.2 |
| crc | 8.9 | 8.3 |
| append | 38.3 | 33.7 |
| pipe (two threads, CPU) | 82.5 | 66.1 |

The container's figures are not the VM's; the same commands on the VM give the target's. On tmpfs no disk is in the figure.
