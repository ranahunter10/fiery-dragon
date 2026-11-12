# Where p15d's kernel samples go: waking the writer (2026-11-12)

VM `p15-dev-2604`, kernel 7.0.0-38, the same run as `../2026-11-12-crc32c-hw/` (34284f0). `vm-session.txt` holds the maintainer's two commands of 2026-11-12 17:54 and their output, copied from the session.

## 1. The run's end-to-end lines (MEAS; the four "added per open+close" lines of `build/oc_crc.md`)

| | added per open+close |
|---|---|
| known file, thread CPU (primary) | 1,125.0 ns (95 % 1,006.8 to 1,676.0) |
| known file, wall time | 1,220.8 ns |
| file never seen, thread CPU | 1,808.2 ns (1,324.1 to 2,400.8) |
| file never seen, wall time | 1,835.9 ns |

The untraced arms of this session disagreed (`none` 987.0 against `none2` 1,089.8), and the report flags drift. So these are weak; E-0213's 1,140.5 is the figure to compare under steadier conditions.

## 2. The call graph of p15d's hottest kernel symbol (MEAS, `perf report`, 107 samples)

- **29.9 % of all p15d's samples** sit under `_raw_spin_unlock_irq`. Of these, 29.0 % come through `p15_drain_poll → take_all → take → p15_drain_room → publish → p15q_publish → write → eventfd_write`, and 0.9 % through `after_poll → publish → p15q_publish`.
- **That is the drain thread kicking the writer's eventfd each time it publishes a batch** (`daemon/queue.c` `p15q_publish`; SRC).
- `eventfd_write` wakes the writer's `poll` while holding the eventfd's lock with interrupts off. Timer sampling cannot land there (`../2026-11-12-crc32c-hw/README.md` §3), so the wake's whole cost shows at the unlock.
- The writer's own disk writes appear once (0.9 %, `ext4_buffered_write_iter`).

## 3. How much one wake costs (INF)

- p15d spent 455.1 ns per open+close (E-0218) over 220,000 open+closes per arm: about 100 ms. 29.9 % of that is about 30 ms.
- The arm wrote 171.6 bytes per open+close into 256 KiB batches: about 144 batches, so about 144 publishes.
- That makes **about 200 µs per wake** (INF: a small profile, and batches also close at each poll).
- A wake of a sleeping thread usually costs a few µs. Here the writer's vCPU is likely idle and halted, and waking it takes the host: VirtualBox over Hyper-V (CLAUDE.md, E-0088). So this is likely a cost of this VM more than of p15d's design. But this VM is the target, and every figure is measured on it.

## 4. What follows (decision waiting 10, (b) re-opened on this evidence)

Fewer wakes per record. Two ways:
1. **Larger batches**, no code: `--batch-kb` (256 by default, at most 4096), with `--queue-batches` lowered to keep the queue's memory the same. Batches also close at each poll (`after_poll` publishes), so 1 MiB batches should about halve the wakes of this workload and 4 MiB add little more (INF). This is measured first.
2. **One wake per poll**, by code: `p15q_publish` publishes without kicking, and the drain kicks once at the end of `p15_drain_poll`, at once when the queue is full, and at the final drain. That bounds wakes by the poll rate however many batches a poll fills: a spine batch and a bulk batch in one poll are two wakes today. It adds at most one poll's reading time to when the writer sees a batch.

`SHA256SUMS` covers `vm-session.txt`.
