# Batch size against p15d's wake-ups (2026-11-12)

VM `p15-dev-2604`, kernel 7.0.0-38, branch `bench/open-cost-switches` 326dc5c (p15d with the SSE4.2 CRC, #83). `bench/open_cost`, 20 paired rounds per size, all three in one session, queue memory held at 16 MiB. Every arm's books closed: 4,400,000 opens and closes each, none lost. `vm-session.txt` is the maintainer's terminal (two messages), as sent. The first grep's pattern `open+close` is unescaped, so it never matched the "added" lines; the second command shows them.

| `--batch-kb` x `--queue-batches` | p15d CPU per open+close above idle, mean (median) | p15d's switches per 1,000 open+close | added to the workload's open+close, known file, thread CPU | added, new file, thread CPU |
|---|---|---|---|---|
| 256 x 64 (default) | 413.0 (293.0) ns | 3.4 | 1,034.8 ns (1,001.3 to 1,081.2) | 1,390.5 ns |
| **1024 x 16** | **203.6 (198.6) ns** | 0.4 | 1,018.3 ns (984.9 to 1,054.8) | 1,314.4 ns |
| 4096 x 4 | 186.6 (170.8) ns | 0.4 | 1,060.8 ns (1,017.9 to 1,214.4) | 1,315.7 ns |

What it shows (MEAS):
- **The wakes were p15d's cost** (E-0219). Batches four times larger cut p15d's switches eightfold and its CPU per open+close by half: 413.0 to 203.6 ns. 4 MiB saves 17 ns more.
- **What the program making the call pays does not move with batch size:** 1,018 to 1,061 ns, within each other's intervals. That cost is in the kernel (the BPF programs and their hook paths, E-0213: 741.4 ns of bodies), and p15d runs on another CPU.
- The idle rate's switches are about 9 per second at every size: the drain's adaptive poll (ADR-0030).

`SHA256SUMS` covers `vm-session.txt`.
