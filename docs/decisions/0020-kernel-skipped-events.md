---
status: proposed
date: —
owner: Ashish Rana
consulted: [VM runs of 2026-11-04 (E-0088, E-0089, E-0090), Linux v7.0 source, Falco libs modern_bpf, Tetragon, Tracee (source read, not run), the SRCU-fast tracepoint series (Rostedt, McKenney), maintainer review of 2026-11-04 ("do the recommended things")]
supersedes: ADR-0003 rule 1 and the exec, exit and comm-change rows of its hook table; ADR-0006 rule 3 (wake-ups). ADR-0006 rule 6 (the invariant) and every other rule of ADR-0003, 0006 and 0017 stand.
---

# 0020: Events the kernel skips: spine hooks on classic tracepoints, wake-ups only at a high-water mark, every skip counted and located

## Context and problem statement

On kernel 7.0, tracepoint callbacks run preemptible: tracepoints were moved from a preempt-disabled guard to SRCU-fast, and `__bpf_trace_run` only disables migration (SRC). Before each `tp_btf` or fentry/fexit program, the kernel takes a recursion guard that is **one counter per CPU per program**. If a task is preempted while inside our program, any other task that reaches the same hook on that CPU is skipped. The kernel counts the skip only in `bpf_prog_info.recursion_misses`. Our program never runs, so our own `seen` counter, and with it the accounting invariant of ADR-0006, can't see it.

On the VM (7.0.0-38, `PREEMPT(lazy)`, 3 vCPUs), a 200-exec burst under p15d lost 13–22 EXEC, 12–17 EXIT and 10–14 RENAME events per run, while the books still closed (E-0089). The same mechanism explains the end-to-end case 1 failure (173 of 200 EXEC) and the demo run's FORK-less PID 12224. The main trigger is our own drain. Every record wakes it, it runs at `SCHED_FIFO`, and so it preempts the task that is still inside the program.

That breaks ADR-0006 driver 1 (lifecycle records are never lost silently) and CLAUDE.md's "no drop without a counter". It is also an evasion route: a fork/exec flood raises the skip rate.

**Question:** how does the spine stop losing events to the kernel's recursion guard, and how is any remaining skip counted and located?

## Decision drivers

1. No silent spine loss (ADR-0006 driver 1), including loss before our first instruction.
2. Every loss counted by cause, and located in time (ADR-0006 rule 6, ADR-0017 layer 4).
3. Measured on the target kernel, because the effect depends on its preemption model (E-0090: 0 on the CI runner, 3–4 % on the VM).
4. Prefer a structural guarantee over a statistical one.
5. No new mechanism where an existing kernel interface will do; the smallest change to accepted ADRs.

## Considered options

1. **Count only:** read `recursion_misses` and report it (Tetragon's practice).
2. **Wake-ups only at a high-water mark:** records are written with `BPF_RB_NO_WAKEUP`, plus `BPF_RB_FORCE_WAKEUP` when the ring holds more than a quarter of its size; the drain polls on a 10 ms timer. This is ADR-0006 option 4, its documented fallback. Falco's modern probe never wakes on submit.
3. **Classic `tracepoint/` programs for exec, exit and rename:** the perf path runs them with preemption off (`include/trace/perf.h`, `guard(preempt_notrace)`), so the guard can't be held by a preempted task.
4. **`bpf_preempt_disable()` around each program body.**
5. **kprobes for fork and exit,** as Tetragon does (`kprobe/wake_up_new_task`, `kprobe/acct_process`).
6. **A different kernel preemption model** (boot with `preempt=none` or `voluntary`).

## Decision outcome

**Chosen:** options 1 + 2 + 3 together, with FORK staying on `tp_btf`. Option 3 is the only one with zero measured skips for EXEC and EXIT (driver 4). Option 2 removes our own drain as the trigger for the hooks that stay on fentry/fexit and `tp_btf`. Option 1 makes whatever remains counted and located (drivers 1 and 2).

### Rules

1. **Hook types:**

   | Event | Hook | Was (ADR-0003) |
   |---|---|---|
   | fork | `tp_btf/sched_process_fork` (unchanged: the classic tracepoint carries only the child's pid, and the child's start time is half its identity, ADR-0009) | same |
   | exec | `tracepoint/sched/sched_process_exec` | `tp_btf/sched_process_exec` |
   | exit | `tracepoint/sched/sched_process_exit` (the format carries `group_dead`) | `tp_btf/sched_process_exit` |
   | comm change | `tracepoint/task/task_rename` | `tp_btf/task_rename` |

   - **EXEC takes what it read from `bprm`** from the context instead: `filename` (`__data_loc`) and `old_pid`. The exec'd file's identity comes from `current->mm->exe_file`, which `begin_new_exec` set to `bprm->file` before the tracepoint (`fs/exec.c`, v7.0). Every other field is read by CO-RE from `bpf_get_current_task_btf()`, as before.
   - **RENAME's task is `current`'s thread group:** `/proc/PID/comm` may only be written within the same thread group (`fs/proc/base.c comm_write`, v7.0), and exec and prctl rename `current` itself. So the header's process key comes from `current`, and its tid from the context's `pid`.
   - Classic tracepoints need **tracefs mounted at `/sys/kernel/tracing`**. Without it the load fails loudly: exit LOAD (69), with the reason in the log. There is no fallback.
2. **Wake-ups** (supersedes ADR-0006 rule 3):
   - every record on both rings is written with `BPF_RB_NO_WAKEUP`;
   - when the ring holds more than a quarter of its size (`bpf_ringbuf_query(BPF_RB_AVAIL_DATA)`), the record is written with `BPF_RB_FORCE_WAKEUP` instead;
   - the drain polls with a 10 ms timeout, so its latency is bounded at about 10 ms;
   - ADR-0017's drain priority, queue, writer and GAP rules stand.
3. **Kernel skips are counted:**
   - at every STATS record, p15d reads `recursion_misses` for every attached program;
   - STATS v2 adds `fork_missed`, `exec_missed`, `exit_missed` and `rename_missed`; NET_STATS v2 adds `net_missed`; all cumulative from the run's start (a baseline is read after the self-tests);
   - GAP v2 adds the per-type skips in its window, so a skip is located like a ring loss (ADR-0017 layer 4);
   - **any spine skip makes the run INVALID; any network skip makes it DEGRADED.** The accounting invariant itself doesn't change, because a skipped event never reached `seen`. The skip is a separate cause, reported beside it;
   - the Prometheus textfile and p15-trace's Trust block show the counts.
4. **Not used:**
   - option 4, measured as no help (E-0090: 3.1 % / 3.5 %, against 3.3 % / 3.9 % today). A preemption held back by `bpf_preempt_enable()` lands inside the guard anyway;
   - option 5 for now: fork stays on `tp_btf`, with near-zero measured skips (0 in every rmcheck run; 1 in the demo), counted by rule 3. A kprobe would widen ADR-0003's hook policy to function hooks;
   - option 6: the host's scheduler is not ours to choose. A capture tool must work on the kernel it is given.
5. **Follow-up, under its own PR:** FORK, EXEC and EXIT records carry the kernel's `self_exec_id` and the parent's key (record v2s). Then a skipped EXEC is detected per process (a gap in `self_exec_id`), and a skipped FORK is repaired from the child's next record. That attribution closes the loop: skips located per process must sum to `recursion_misses`.

### Conformance with practice

| Practice | Where it is done | How this ADR relates |
|---|---|---|
| Read the kernel's per-program miss counter | Tetragon (`missed_prog_probes_total` = `RecursionMisses`) | same (rule 3), and we make it decide the run state |
| Don't wake the consumer on every record | Falco modern_bpf (`BPF_RB_NO_WAKEUP` on every submit); ADR-0006's documented option 4 | same, plus a forced wake-up at a high-water mark, so a flood is still drained at once (ADR-0017) |
| Hooks that run with preemption off | Tetragon (kprobes for fork and exit) | classic tracepoints: the same property, through a stable tracepoint format rather than a function hook |
| Typed, CO-RE-relocated reads | Falco and Tetragon (BTF + CO-RE) | kept: every task, mm and file read is CO-RE from `bpf_get_current_task_btf()`; the context structs come from vmlinux.h and are relocated too |
| Hooks checked at load, with a self-test | ADR-0003 | kept: the self-test runs on the new hook types; a hook that fails to attach stops the start |

**No departure from these practices was found.** The departures are from our own ADR-0003 (hook type) and ADR-0006 rule 3 (wake-ups), and this ADR supersedes exactly those.

### Consequences

- Good: zero measured EXEC/EXIT skips on the target (E-0090). Whatever still slips through is counted, located and fatal to the run's validity, never silent.
- Good: fewer wake-ups. The probe's bursts finished faster, though that comes from 3 rounds on a stalling host, so it is a direction, not a result.
- Bad: tracefs becomes a requirement (the dev container needs `mount -t tracefs nodev /sys/kernel/tracing`).
- Bad: the perf path fills the tracepoint's own record (the exec filename) before our program runs. Its cost is unmeasured (OPEN) and is measured under ADR-0018 before this ADR is accepted.
- Bad: up to about 10 ms of added latency between an event and the WAL, below the 1 s durability window of ADR-0007.

### Confirmation

1. `bpf/test/recur_probe` on the VM: the shipped combination shows 0 EXEC/EXIT skips over 3 rounds × 2,000 execs.
2. p15d on the VM with the same 200-exec bursts as E-0089: `exec_missed = exit_missed = rename_missed = 0`, and `fork_missed` reported.
3. `it_p15d.sh` case 1 counts exactly the 200 children's EXECs.
4. A unit test: any spine miss makes the run INVALID and emits a GAP v2.
5. The ADR-0018 cost comparison: the classic-tracepoint EXEC against the `tp_btf` one, paired, on the VM.

### Falsifier

Reopen if any of these is observed:
- the VM shows EXEC, EXIT or RENAME skips on the classic tracepoints;
- a future kernel makes the perf path preemptible;
- the forced-wake-up watermark lets the spine ring overflow under the ADR-0017 storm, where per-record wake-ups did not;
- the ADR-0018 cost run shows the classic tracepoint costing more than its benefit justifies (the maintainer decides).

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | Tracepoint callbacks run under `guard(srcu_fast_notrace)`; `__bpf_trace_run` only disables migration | SRC | Linux v7.0 `include/linux/tracepoint.h`, `kernel/trace/bpf_trace.c` |
| 2 | The recursion guard is one counter per CPU per program on x86, and a skip is counted only in the program's misses | SRC | v7.0 `include/linux/bpf.h` `bpf_prog_get_recursion_context` |
| 3 | The perf (classic tracepoint) handler runs with preemption off | SRC | v7.0 `include/trace/perf.h` `perf_trace_##call` |
| 4 | The change came from "tracing: Guard `__DECLARE_TRACE()` use of `__DO_TRACE_CALL()` with SRCU-fast", whose stated motive is that BPF tracepoint programs were non-preemptible | DOC | [the series](https://ratatoskr.run/bpf/2026/01/3387970/t) |
| 5 | p15d on the VM: 13–22 EXEC, 12–17 EXIT and 10–14 RENAME skips per 200-exec burst; EXEC + skips = forks | MEAS | [E-0089](../evidence/probes/2026-11-04-recursion-misses/README.md) |
| 6 | The design comparison: today 3.33 % / 3.85 %; no wake-ups 0.02 % / 0; classic tracepoint 0 / 0; preempt-disable 3.08 % / 3.52 % | MEAS | [E-0090](../evidence/probes/2026-11-04-recursion-misses/README.md) |
| 7 | `recursion_misses` equals our children's missed events in every run | MEAS | same |
| 8 | Zero skips on the CI runner in every variant: the effect depends on the preemption model | MEAS + INF | same, `runner-recur-probe.txt` |
| 9 | Falco submits every record with `BPF_RB_NO_WAKEUP`; Tetragon exports `RecursionMisses` and uses kprobes for fork and exit | SRC | falcosecurity/libs `driver/modern_bpf/helpers/store/ringbuf_store_params.h`; cilium/tetragon `pkg/metrics/kprobemetrics/collector.go`, `bpf/process/bpf_fork.c`, `bpf_exit.c` (read, not run) |
| 10 | `bpf_task_from_pid` is not offered to classic tracepoint programs on 7.0, so FORK on a classic tracepoint could not read the child's start time | SRC | v7.0 `kernel/bpf/helpers.c` (`generic_kfunc_set` registrations) |
| 11 | `current->mm->exe_file` is the exec'd file at the exec tracepoint | SRC | v7.0 `fs/exec.c` `begin_new_exec` → `set_mm_exe_file`, before `trace_sched_process_exec` in `exec_binprm` |
| 12 | `self_exec_id` increments once per successful exec and is inherited at fork | SRC | v7.0 `fs/exec.c:1243`, `kernel/fork.c:2381` |
| 13 | The perf path's per-event cost against `tp_btf` | OPEN | Confirmation 5 |

## Pros and cons of the options

### 1. Count only
- Good: exact (E-0090, row 7); no change to any hook.
- Bad: on its own, the VM's runs would be INVALID under any burst.

### 2. High-water wake-ups
- Good: removes our own drain as the trigger (0.02 % / 0); fewer wake-ups.
- Bad: not structural, since other preemption remains; adds about 10 ms of latency.

### 3. Classic tracepoints
- Good: 0 / 0 measured, structural by the kernel's own design; stable tracepoint format.
- Bad: needs tracefs; the perf path's cost is unmeasured; fork can't move (row 10).

### 4. `bpf_preempt_disable()`
- Bad: no measurable help, as predicted.

### 5. kprobes for fork and exit
- Good: preemption off; the child's task is available.
- Bad: function hooks are less stable than tracepoints; widens ADR-0003.

### 6. Kernel preemption model
- Bad: not ours to set on a user's host.
