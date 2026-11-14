# Why case 21's canary was late on the VM, 2026-11-14

VM `p15-dev` (7.0.0-38-generic, 3 vCPU), tree `vm/integration-4`. The maintainer ran case 21's p15d command by hand and pasted the outputs; they are kept here as text (the runs' WALs were not kept). Journal: E-0317.

| File | What it shows |
|---|---|
| `loop20.txt` | 6 of 30 runs had one late canary (26-232 ms past the 1 s deadline); every signal arrived (mask 0x6f of 0x6f); canaries 1, 2 and 3, not only the first |
| `canary_timing.txt` | the canary child takes 3-4 ms from fork to exit; the drain's longest poll gaps were 955 and 1,164 ms (the timer is at most 200 ms), and the writer's 1 s STATS stopped for 2.9 s |
| `ticker.txt` | a plain 10 ms sleep loop beside p15d overslept 945 ms once; p15d's drain had a 331-587 ms gap in every interval |
| `bpftrace.txt` | p15d's forks take 64 us to 1 ms (not the cause); its timed-out epoll waits returned up to 512-1,000 ms after their timeout |
| `kernel-log.txt` | stalls the kernel noticed: at boot, and one 76 s host stall at 16:02:59; none during the canary loops (sub-second stalls are not logged) |

Conclusion (MEAS for the numbers, INF for the cause): the guest does not run p15d's drain thread (SCHED_FIFO 1) when its timer fires, for up to about a second at a time, below the kernel's stall report. The canary's lateness is that delay, not the pipeline's. Fix: `p15_canary_oversleep` moves a canary's deadline by a drain wait's overshoot beyond 20 ms (counted stalled); a drain slow in its own work, as case 23's pause, stays late.

`canary_timing.py` (run from the repository root with the venv's python, argument a run directory):
```python
import sys, pathlib
sys.path.insert(0, "python")
from p15 import wal
run = wal.read_run(pathlib.Path(sys.argv[1]))
spine = list(run.ring_records(0)); daemon = list(run.ring_records(2))
bulk = [r for r in run.ring_records(1) if r.name == "OPEN"]
t0 = min(r.h["ts_ns"] for r in spine)
for e in (r for r in spine if r.name == "EXEC" and r.var["argv"].startswith(b"fd-canary")):
    pid = e.h["tgid"]
    fk = [r.h["ts_ns"] for r in spine if r.name == "FORK" and r.f["child_tgid"] == pid]
    ex = [r.h["ts_ns"] for r in spine if r.name == "EXIT" and r.h["tgid"] == pid]
    op = [r.h["ts_ns"] for r in bulk if r.h["tgid"] == pid]
    f = fk[0] if fk else e.h["ts_ns"]
    ms = lambda x: f"{(x[0] - f) / 1e6:.1f}" if x else "none"
    print(f"canary pid {pid}: forked at +{(f - t0) / 1e9:.3f} s; exec +{(e.h['ts_ns'] - f) / 1e6:.1f} ms, open +{ms(op)} ms, exit +{ms(ex)} ms")
for s in (r for r in daemon if r.name == "STATS"):
    print(f"STATS at +{(s.h['ts_ns'] - t0) / 1e9:.3f} s: longest poll gap {s.f['poll_gap_max_ns'] / 1e6:.0f} ms")
```
