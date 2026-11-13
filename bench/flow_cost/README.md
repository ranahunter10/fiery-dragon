# What step 2b's read hook costs with each way of keeping FLOW's start time (decision waiting 13)

**Question.** ADR-0005 rule 8 asks FLOW for the start of its first event. A kprobe.session's cookie is 8 bytes, so on `vfs_read` it cannot keep both the file (needed at the return) and the entry time ([design checks](../../docs/research/2026-11-12-step-2b-design-checks.md) §2, D1). Option A keeps {file, entry time} in task storage. Option D keeps no start time (an ADR would have to supersede rule 8). This harness measures what A adds, alone and with the record, and checks that A's start times are right.

**Design.** `flow_cost.bpf.c` has one kprobe.session program per arm on `vfs_read`. Each counts only the harness's own calls, and the cookie keeps the file pointer:

| Arm | Entry | Return |
|---|---|---|
| none, none2 | nothing attached: untraced, and its A/A control | — |
| session | the cookie | count (E-0138's anchor, as `rw_hook_cost`'s session arm) |
| ts | the cookie; task storage {file, `bpf_ktime_get_boot_ns`} | look up task storage, compare the file, count |
| count | as ts, and an atomic add of the task's open-call count | as ts, and a compare-and-exchange taking the call off the count (the end's count of open calls, `bpf/include/p15_flow.h`; its cost is count against ts) |
| end_rec | the cookie | a 96-byte FLOW (`schema/records.toml`): end time only, `START_UNKNOWN` |
| ts_rec | as ts | the FLOW with `first_ts` from task storage |

- The record arms reserve, fill and submit on a 64 MiB ring without a wakeup. A drain thread pinned to another CPU consumes the ring as it fills, as p15d's drain does, and checks every FLOW: its type, length, kind, bytes, `first_ts ≤ last_ts`, and `START_UNKNOWN` exactly in `end_rec`.
- There is no file map and there are no marks: those are the same for A and D, and they are measured with step 2b's programs.
- **Workload:** per round, each arm does READS × `read(/dev/zero, 1 byte)` on the harness's thread, pinned to the last allowed CPU, in an order rotated each round, after one untimed warm-up of every arm.
- **Primary metric (declared before the run):** the thread's CPU time per read. Secondary: wall time per read.
- **Books per arm:**
  - a traced arm's hits equal READS, and the untraced arms see none;
  - nothing is lost (no cookie, no start time, a failed storage creation, a failed reservation);
  - the record arms' drained FLOWs equal READS, with none refused.
- **Check pass**, before the rounds: CHECKS reads with `ts_rec` attached, each bracketed by `CLOCK_BOOTTIME` before and after. The i-th FLOW must satisfy before ≤ `first_ts` ≤ `last_ts` ≤ after.
- **Skip counters:** each arm's program's `recursion_misses` and its link's `kprobe_multi.missed`, as deltas.
- **Baseline:** a null syscall (`getppid`, 10^6 calls) per round, as ADR-0018 rule 3.2 requires.

**Report.** [`summarize.py`](summarize.py) uses [`bench/quant/paired.py`](../quant/paired.py) and the comparison lines of [`rw_hook_cost`'s summarize](../rw_hook_cost/summarize.py). Timings are reported only if every book closes and the check passes. The questions:
- **ts against session:** task storage's cost on its own;
- **ts_rec against end_rec:** what A adds to a record, the number that decides;
- **count against ts:** what the end's count of open calls adds to every call (decision waiting 110);
- **end_rec against session:** what writing the record costs.

An overhead is quoted only if ADR-0018 rule 2.4 allows it.

```
sudo mount -t tracefs nodev /sys/kernel/tracing   # if not mounted (containers)
sudo make bench-flow-cost ROUNDS=20               # raw lines in build/flow_cost.txt
```

**Limits.**
- A 1-byte read of `/dev/zero` is about the cheapest `vfs_read` there is. The relative overheads are upper bounds; the absolute nanoseconds per call are the number that transfers.
- One thread makes the calls, so task storage always hits its cache after the first call (D3). A workload with many short-lived threads pays the creation (an allocation and an rqspinlock) once per thread. That cost is not measured here.
- The dev container (6.18) cannot load the session programs, because its session kfuncs take no `ctx`. The CI runner's 7.0 kernel runs every arm as a smoke test, not a measurement. Only the VM gives the numbers.
- Whether the VM's kernel offers task storage at all is checked by the load. On the dev container, the map is created before the programs fail.
