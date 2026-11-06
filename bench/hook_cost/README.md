# What the classic-tracepoint hook path costs (ADR-0020 confirmation 5)

**Question.** ADR-0020 moves the spine's exec, exit and rename hooks from `tp_btf` to classic tracepoints, so that the kernel can't skip them (E-0089). The classic path costs something `tp_btf` doesn't: it fills the tracepoint's own record before the program runs (for exec, it copies the filename). ADR-0020 says it is accepted only once that cost is measured on the VM under ADR-0018.

**Design.** `hook_cost.bpf.c` puts the **same trivial body** behind both hook types, so any difference in cost comes from the hook path alone. The body counts one hit if the event is the harness's own, or its child's for exec. Per round, every arm runs once, in an order rotated each round, after one untimed warm-up of every arm:

| Event | Workload per arm | Metric (declared before the run) | Arms |
|---|---|---|---|
| rename | `prctl(PR_SET_NAME)` × RENAMES | the harness thread's CPU time (primary), wall time | none, none2 (A/A), tp, btf |
| exec | fork + exec `/bin/true` + wait × EXECS | the children's CPU time (primary; the hook runs in the child), wall time | none, none2, tp, btf, and `spine`: the shipped spine EXEC program |

- The process and its children are pinned to one CPU.
- Every arm's books are checked:
  - a traced arm's hits equal its events;
  - the untraced arms see none;
  - the `spine` arm's EXEC records of our children pass `p15_rec_check` and number exactly EXECS.
- Each round also times a null syscall (ADR-0018 rule 3.2).

**Report.** [`summarize.py`](summarize.py) uses [`bench/quant/paired.py`](../quant/paired.py). Per event and metric it gives:
- each arm's median per event, with its interval;
- `tp`, `btf` and `spine` each against `none`, as the paired Hodges–Lehmann effect with the exact interval and p-value, judged against the A/A floor (`none2` against `none`);
- **`tp` against `btf`**, the confirmation's actual question, against the same floor;
- the added cost per event in ns and in null syscalls.

An overhead is quoted only if ADR-0018 rule 2.4 allows it.

```
sudo mount -t tracefs nodev /sys/kernel/tracing   # if not mounted (containers)
sudo make bench-hook-cost ROUNDS=20               # raw lines in build/hook_cost.txt
```

**Limits.**
- The trivial body isolates the hook path. The shipped body's own cost was `bench-exec-cost`'s `bpf_stats` number (E-0076; that bench left with EXEC v2, ADR-0025 rule 8), and the `spine` arm gives the whole shipped EXEC end to end.
- At exec level the hook's nanoseconds sit far below an exec's run-to-run noise. That arm is expected to be "not resolved", and the rename arm is the one that resolves the hook path.
