# Open path v2 on the VM (2026-11-12)

Evidence for E-0192. VM `p15-dev-2604`, 7.0.0-38-generic, PR #71 at `7d58f45`. Host on its charger: a null syscall cost 85.9 ns (83.1 to 100.0) against the 87.5 ns reference.

`open_sections.md` and `open_contend.md` are the reports as the VM printed them; their sha256 equal the VM's (`1e0dacd6...a08a`, `914541e8...b5ef6`). `vm-session.txt` is the whole pasted terminal, with the sha256 of the raw files that stayed on the VM.

## Section timing, net of the empty bracket, median of 20 rounds of 200,000 open+close (MEAS)

| section | v1 (E-0187) | v2 (this run) | change |
|---|---|---|---|
| path program, all | 624.3 ns | 492.5 ns | -131.8 |
| ... record header | 54.0 | 15.8 | -38.2 |
| ... the inode's facts | 65.1 | 5.9 | -59.2 |
| ... bpf_d_path | 86.7 | 93.7 | +7.0 |
| ... ring copy | 36.7 | 37.6 | +0.9 |
| session entry, all | 250.2 | 139.6 | -110.6 |
| ... open-file insert | 93.9 | 82.4 | -11.5 |
| session return | 22.1 | 20.3 | -1.8 |
| close, all | 304.7 | 244.9 | -59.8 |
| ... CLOSE record | 115.6 | 52.6 | -63.0 |
| **sum of the four programs** | **1,201.3** | **897.3** | **-304.0 (-25.3 %)** |

The whole-program figures hold their inner brackets' own cost (about 15 ns each: 7 in the path program, 1 in the entry, 3 in the close), so the production build's programs are shorter than these; open_cost measures that build.

## Under contention (MEAS): unchanged

12 processes, 200,000 open+close each, 3 vCPUs: the path program was skipped for 258,504 of 2,400,026 opens (10.8 %; v1: 10.2 %), equal to its `recursion_misses`; the session and close programs skipped none; nothing lost to the ring.

A 21 % shorter path program did not lower the skip rate. Why (INF): the recursion context is held from `__bpf_prog_enter_recur` to `__bpf_prog_exit_recur` (kernel/bpf/trampoline.c L1143-1196, v7.0), and the program's helpers that take and release a lock are preemption points inside that window; a task preempted at one blocks its CPU's other opens for a whole time slice. Shortening the program does not remove those points. What removes the skips is not running the work in a preemptible program: gate 2.

## it_p15d.sh (MEAS)
PASS, 0 failed checks. Case 12 (the path program unattached): 4 OPEN, all PATH_MISSING; 2 CLOSE of them, each naming its OPEN's object.
