# The hour's graph rebuilt after the insert fix (2026-11-12)

Evidence for E-0204. VM `p15-dev-2604`, PR #75 at `1adfb17` (merged as `4720ac2`), the one-hour soak's WAL (E-0202). `vm-session.txt` is the terminal as the maintainer pasted it (the git transfer lines trimmed). `build/graph2.txt` stayed on the VM.

- **The same graph:** every line of its books equals the first build's (`diff` of the two outputs: SAME).
- **Where the time goes now (MEAS):** reading the WAL and the process tree 42.2 s; the raw tables 24.6 s; the slowest statement of graph.sql 3.4 s, and the next two 1.2 and 1.1 s. `proc_src`, 626.4 s before the fix (E-0203), is no longer among the five slowest phases, so it takes under 1.1 s. The total is not printed. By the sum of the profile it is about 80 s (INF), against 782 s before.
- **Against the target of decision 34** (an hour's graph in under 60 s): over, by about 20 s. Nearly all of what is left is Python decoding each record and building its row (about 67 s). Gate 10's streaming builder takes that on, with bulk decoding of the WAL's layouts.
