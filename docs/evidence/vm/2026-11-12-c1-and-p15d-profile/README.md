# Candidate C1 measured, and where p15d's time goes (2026-11-12)

VM `p15-dev-2604`, kernel 7.0.0-38, branch `bench/open-cost-perf` at 9361172 (BPF and p15d as main's 6b1e177). `vm-session.txt` is the maintainer's terminal, as sent. Today's design is "base". C1 is p15d with `--test-no-path-fentry`: the fentry is left unattached, so the session's return writes every OPEN by the walk (STATE decision 40). Depth 3 is `/var/tmp/p15-open-cost/same`; depth 10 is `/var/tmp/p15-oc/a/b/c/d/e/f/same`.

## 1. C1 is not cheaper (MEAS)

Programs, unprofiled (`prog_stats.py`, 7 rounds, medians, ns per open+close; the kernel statistics' own cost is included in both arms alike):

| | base, depth 3 (E-0213) | C1, depth 3 | base, depth 10 | C1, depth 10 |
|---|---|---|---|---|
| the open: fentry + session | 306.7 + 182.9 = **489.6** | session alone **540.4** | 359.1 + 176.9 = **536.0** | session alone **571.5** |
| close (`file_free`, the same code in both) | 229.5 | 224.1 | 221.0 | 178.6 |
| all | 741.4 | 760.2 | 754.3 | 749.5 |
| host: null syscall | 92.4 | 97.3 | 96.2 | 87.7 |

- **The open costs 35 to 51 ns more in C1, in its program bodies.** The fentry's work moves into the return; nothing is saved but the fentry's own hook path, about 14 ns (E-0138).
- `file_free` runs the same code in both arms, yet ranges from 178.6 to 229.5. So differences of about 50 ns between separate runs here are within this VM's variation. The "all" row is no better than a tie.

Whole pipeline (`open_cost`, 20 paired rounds each; every arm's books closed, 4,400,000 opens and closes, none lost):

| added per open+close, a file never seen (thread CPU, primary) | base | C1 |
|---|---|---|
| depth 3 | 1,606.1 (E-0213, another session) | 1,471.2 |
| depth 10, the same session | **1,656.8** (95 % 1,585.6 to 1,839.6) | **1,657.0** (1,469.0 to 1,960.6) |

- At depth 10, the one pair run back to back, C1 and base are the same to 0.2 ns.
- The terminal's `tail -32` cut each report's "same" (known file) section. The full reports are in `build/oc_*.md` on the VM.
- p15d per open+close above idle: base 753.7 and C1 695.6 at depth 10; C1 688.9 at depth 3.

**What this corrects:** the note's estimate for C1 ("saves about 250 ns", `docs/research/2026-11-12-open-cost-against-the-tools.md` §4) is falsified. It counted the fentry's whole profiled body as saved. But most of that body (header, facts, objects, ring copy) has to be done by whichever program writes the OPEN.

## 2. Where p15d's time goes (MEAS, `perf record`, round 0 of a 3-round `--perf` run, 132 samples, 66 ms of p15d CPU)

| share | where | what |
|---|---|---|
| **32.6 %** | `p15_crc32c` (p15d) | the WAL's checksums, one byte per table step (`daemon/crc32c.c`, whose own comment defers a faster version "for a measurement that asks for it") |
| 16.7 % + 16.7 % | `_raw_spin_unlock_irq`, `finish_task_switch` (kernel) | **switching between threads**: p15d's threads waking and sleeping around each batch |
| 9.1 % | `on_bulk` | the drain's per-record callback |
| 6.8 % | `tiles` | `p15w_append`'s check that the records tile the batch |
| 3.0 % | `p15_rec_check` | the record check |
| the rest | below 4 % each | |

- 132 samples is a small profile: the ranking is solid at the top, and the shares are within a few points (INF).
- **The two largest items are both in p15d, not in the kernel's programs: the byte-at-a-time CRC (about a third) and thread switching (about a third).**
- eAudit's collector has neither: it writes raw buffers with one `write` per wake-up (R-042 §3.3).

`SHA256SUMS` covers `vm-session.txt`.
