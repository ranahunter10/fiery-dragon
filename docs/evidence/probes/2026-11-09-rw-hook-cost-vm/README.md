# Read-path hook types on vfs_read, on the VM (2026-11-09)

**Where:** VM `p15-dev-2604` (7.0.0-38-generic, `PREEMPT(lazy)`, 3 vCPUs, VirtualBox on Hyper-V). The maintainer ran it from branch `bench/rw-hook-cost` (PR #60): `sudo make bench-rw-hook-cost ROUNDS=20`.

**Files:**
- [`rw_hook_cost.txt`](rw_hook_cost.txt): the raw lines (`build/rw_hook_cost.txt`);
- [`rw-hook-cost-summary.md`](rw-hook-cost-summary.md): the terminal output of the make target, which ends with `summarize.py`'s report. Re-running `python3 bench/rw_hook_cost/summarize.py rw_hook_cost.txt` in the dev container gives the same report line for line.

**Run:** 20 rounds after one warm-up, 200,000 one-byte reads of `/dev/zero` per arm per round, pinned to CPU 2. Every book closed (`rw_hook_cost: ok`); no return without its entry in any arm.

## Results (MEAS, the harness thread's CPU time per read; trivial body)

| Arm | Median per read | Added per read vs none (95 % interval) |
|---|---|---|
| none | 125.8 ns | — |
| none2 (A/A) | 121.9 ns | — |
| fentry | 140.4 ns | 14.2 ns (7.9 to 17.8) |
| fexit | 150.0 ns | 21.5 ns (16.8 to 26.1) |
| kprobe.multi, entry only | 149.1 ns | 20.8 ns (15.0 to 30.6) |
| kprobe.multi + kretprobe.multi, per-thread stash | 436.4 ns | 315.1 ns (302.8 to 331.7) |
| kprobe.session, cookie | 268.4 ns | 141.0 ns (130.8 to 149.0) |

- **session against pair:** −39.3 % (−42.6 to −36.7), −174.8 ns per read, p = 1.9e-6.
- **session against fexit:** +77.6 % (+70.1 to +85.9), +118.2 ns per read.
- **session against kprobe.multi entry:** +78.1 %, +116.8 ns per read: the return half of a session costs about 117 ns here.
- Every comparison above is quoted under ADR-0018 rule 2.4 (p < 0.05, outside the A/A interval). Wall time agrees to within 0.2 ns.
- **Skip counters:** 0 `recursion_misses` and 0 `kprobe_multi.missed` in every arm. The harness is one thread on one CPU, so nothing contends for the programs: this shows no skip under no contention, not that skips cannot happen.
- **Design check O2:** a kprobe.session and a fentry on `security_file_open` at once each saw 2,000 of 2,000 opens.

## Limits

- Trivial bodies: slice B's real bodies (map lookups, marks, ring writes) add their own cost on top, the same for every hook type.
- A one-byte read of `/dev/zero` is about the cheapest `vfs_read`; the relative overheads are upper bounds for real reads, the ns per call are the transferable figures.
- Round 5's untraced arms ran about 60 % slower than the others (host interference); the paired design absorbs it, and the A/A arm moved with them.
- Skips under contention (several tasks, an RT drain thread, as in E-0089/E-0090) are not exercised here; slice B's own tests do that (STATE decision 17).

`SHA256SUMS` covers the files here. The maintainer's `sha256sum` on the VM (2026-11-10) printed the same values for `~/rw_hook_cost.txt` (`63db39cc…ff37`) and `~/rw-hook-cost-summary.md` (`d60bc87b…4ca2`): the committed files are byte for byte what was run.
