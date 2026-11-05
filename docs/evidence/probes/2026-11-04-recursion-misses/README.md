# The kernel's recursion misses, and which design avoids them (2026-11-04)

**Where:**
- **VM `p15-dev-2604`** (target kernel 7.0.0-38-generic, `PREEMPT(lazy)`, 3 vCPUs, VirtualBox on a Windows host with Hyper-V on). The maintainer ran it.
- **CI runner** (7.0.0-1017-azure, 4 CPUs): not the target.

**Files:**
- [`vm-recur-probe.txt`](vm-recur-probe.txt): `bpf/test/recur_probe 3 2000` on the VM;
- [`runner-recur-probe.txt`](runner-recur-probe.txt): the same in CI;
- [`vm-rmcheck.txt`](vm-rmcheck.txt): p15d with 200 execs, and the kernel's per-program `recursion_misses`, as pasted in the session;
- [`demo-run-seg-00000000.p15w`](demo-run-seg-00000000.p15w): the WAL of the demo run (`run_demo.sh`, 2026-11-04 15:06 UTC), in which PID 12224 has EXEC, RENAME and EXIT records but no FORK, while `fork_seen = fork_emitted = 59`.

## Mechanism (SRC, Linux v7.0)

1. Tracepoint callbacks run under `guard(srcu_fast_notrace)` (`include/linux/tracepoint.h`), not with preemption off. `__bpf_trace_run` only disables migration (`rcu_read_lock_dont_migrate`).
2. The recursion guard, `bpf_prog_get_recursion_context`, is one counter per CPU per program (x86: `this_cpu_inc_return(prog->active) == 1`).
3. So when a task is preempted inside one of our programs, any other task that hits the same tracepoint on that CPU is skipped. The skip is counted only in `recursion_misses`. Our `seen` counter never runs, so our books close regardless.
4. The upstream change is "tracing: Guard `__DECLARE_TRACE()` use of `__DO_TRACE_CALL()` with SRCU-fast" (Rostedt, McKenney). Classic `tracepoint/` programs go through the perf path, which keeps `guard(preempt_notrace)` (`include/trace/perf.h`).

## Findings

1. **p15d on the VM loses spine events, and only the kernel counts them** (MEAS, `vm-rmcheck.txt`):
   - with a 200-exec burst, `spine_exec` misses 13–22, `spine_exit` 12–17 and `spine_rename` 10–14, while `spine_fork` misses 0;
   - EXEC records + misses ≈ forks in each run;
   - with `--no-rt`, the EXEC and RENAME misses drop (0–7), but EXIT misses don't (1–28);
   - the network programs show 0 everywhere.
2. **Comparing the designs on the VM** (MEAS, `recur_probe`, 3 interleaved rounds × 2,000 execs per variant, 6 workers):

   | Variant | EXEC missed | EXIT missed | Burst time, ms (median of 3) |
   |---|---|---|---|
   | tp_btf, every record wakes, FIFO reader (**today**) | 200 / 6,000 (3.33 %) | 231 / 6,000 (3.85 %) | 3,106 |
   | tp_btf, every record wakes, normal-priority reader | 103 (1.72 %) | 59 (0.98 %) | 2,619 |
   | tp_btf, no wake-ups (poll every 5 ms), FIFO | 1 (0.02 %) | 0 | 2,548 |
   | tp_btf, adaptive wake-ups (> 256 KiB), FIFO | 2 (0.03 %) | 0 | 2,387 |
   | tp_btf + `bpf_preempt_disable()` around the body | 185 (3.08 %) | 211 (3.52 %) | 2,887 |
   | classic `tracepoint/`, every record wakes | **0** | **0** | 2,706 |
   | classic `tracepoint/`, no wake-ups | **0** | **0** | 2,371 |

   - In every run, our children's missed events equal the kernel's `recursion_misses` (EXIT is +1 in one run: a process that wasn't ours). So counting with `recursion_misses` is exact, and **every run's books closed.**
   - `bpf_preempt_disable()` doesn't help, as predicted: a held-back preemption happens at `bpf_preempt_enable()`, which is still inside the kernel's guard.
   - The burst times are a coarse total for the whole burst, not a measure of per-event CPU cost. They come from 3 rounds on a host known to stall (E-0088), so read them as a direction only.
3. **On the CI runner, every variant has 0 misses** (`runner-recur-probe.txt`). The INF: the azure kernel's preemption model doesn't preempt mid-program. The effect depends on the kernel's preemption model, so it has to be measured on the target.
