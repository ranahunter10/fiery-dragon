# flow_cost on the VM (2026-11-12)

Evidence for E-0233 and decision waiting 13. Run by the maintainer on the VM (7.0.0-38-generic, 3 CPUs) at commit `3cd568f` (#89's head): `sudo make bench-flow-cost ROUNDS=20`, so 20 paired rounds × 200,000 one-byte reads of `/dev/zero` per arm. The reads ran on CPU 2 and the drain on CPU 0.

| File | What |
|---|---|
| `vm-session.txt` | the terminal as pasted: the commit, the harness's first and last lines, the `check` line, and `summarize.py`'s whole report |

The raw `row` lines (`build/flow_cost.txt`) are not here yet. Every figure below is the report's, and the report is computed from those rows.

What it shows (MEAS, VM; thread CPU time per read, the primary metric):

| Arm | Median per read | Added per read against none (95 % interval) | In null syscalls (146.9 ns) |
|---|---|---|---|
| none | 289.8 ns | — | — |
| session | 570.7 ns | 281.0 ns (237.5 to 318.5) | 1.91 |
| ts (option A, no record) | 618.9 ns | 320.4 ns (272.3 to 377.9) | 2.18 |
| end_rec (option D, record) | 688.1 ns | 405.7 ns (336.5 to 442.0) | 2.76 |
| ts_rec (option A, record) | 683.2 ns | 426.4 ns (364.1 to 484.3) | 2.90 |

- **The deciding comparison, ts_rec against end_rec, is not resolved on this host.** The A/A interval is −8.9 % to +10.1 %. The estimate is +19.6 ns per read, with a 95 % interval of −55.9 to +99.3 ns (p = 0.546). Option A's start time therefore costs less than this host can resolve, and at most about 99 ns per read.
- **ts against session is not resolved either:** +54.0 ns (−6.2 to +104.3).
- **Writing a 96-byte FLOW costs 113.9 ns per read** (61.2 to 179.7) over the bare session (end_rec against session, +19.4 %, p = 0.000851).
- **Option A's start times are right:** 20,000 of 20,000 FLOWs had `first_ts` inside their read's `CLOCK_BOOTTIME` bracket. No start time was lost and no creation failed.
- Every book closed in every arm and round. Every arm had 0 `recursion_misses` and 0 `kprobe_multi.missed` (one thread, no contention).
- Wall time gives the same figures to within 0.5 ns.

**The host.** The untraced read cost 289.8 ns here against 125.8 ns in E-0138 (2026-11-09, same read). The null syscall was 146.9 ns here against 99.9 ns in the matrix run three hours earlier (E-0230). Nanoseconds from different sessions on this VM are not comparable; null syscalls are. In null syscalls, today's session arm is 1.91. The same unit is not available for E-0138, so no comparison with it is drawn.

`SHA256SUMS` covers every file here.
