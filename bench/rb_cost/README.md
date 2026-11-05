# EXEC record cost, three ways (ADR-0017 layer 1)

**Question:** ADR-0017 makes every variable-length spine record take only its own `len` in the ring. Two ways do that: `bpf_ringbuf_output()` from a per-CPU scratch record, or `bpf_ringbuf_reserve_dynptr()` of the exact length. ADR-0017 asks for their `bpf_stats` cost before choosing. This harness measures both, against the old fixed reservation as a baseline.

**The code measured is the code shipped.** [`bpf/progs/spine.bpf.c`](../../bpf/progs/spine.bpf.c) builds its EXEC program one of three ways, chosen by `-DP15_EXEC_WAY`:

| Way | How | Copies of argv |
|---|---|---|
| `fixed` (0) | `bpf_ringbuf_reserve()` of the maximum (1,344 B), filled in place; the first build | 1 (user → ring) |
| `output` (1, the default) | fill a per-CPU scratch record, then `bpf_ringbuf_output()` of exactly `len` | 2 (user → scratch → ring) |
| `dynptr` (2) | fixed part and filename in scratch; `bpf_ringbuf_reserve_dynptr()` of exactly `len`; argv read straight into the ring with the `bpf_probe_read_user_dynptr` kfunc; padding cleared with `bpf_dynptr_memset` | 1 (user → ring) |

`make` builds all three as `build/bench/spine-{fixed,output,dynptr}.bpf.o`.

## Method

[`exec_cost.c`](exec_cost.c), as root:

1. Enables `bpf_stats` (`BPF_STATS_RUN_TIME`) for the whole run.
2. For each way, loads the object with all four programs, attaches them and runs the **real load-time self-test** (ADR-0003). `fixed` must fail exactly one check, the new "every record takes exactly its len in the ring"; the other two must pass all.
3. Per round: times a null syscall (`getppid`, 10⁶ calls), the same-session baseline of ADR-0018 rule 3.2. Then for each argv size, measures every way once, in an order rotated each round: load the object with `spine_exec` only, attach, exec `/bin/true` N times with an argv of that many bytes, read `run_cnt` and `run_time_ns`.
4. Checks every record: `p15_rec_check` passes, argv is complete, and the ring size is `len` (`output`, `dynptr`) or the maximum (`fixed`). Execs by other processes are counted (`foreign`); their runs are inside `run_cnt`.

[`summarize.py`](summarize.py) reports per argv size and way the median, min and max of `run_time_ns / run_cnt` over rounds, the median as a multiple of the null syscall, and, paired by round, each way minus `output`. It refuses malformed result lines, and exits 1 if any measurement missed an exec or saw a wrong record.

```bash
make bench-exec-cost                      # root; 10 rounds x 1,000 execs x argv 20, 200, 1,000 bytes
make bench-exec-cost ROUNDS=3 EXECS=200   # quicker
```

**Limits.** These are raw per-run costs on one host, with `bpf_stats` on (about 20 ns per run, Kahle, R-016). They are not an ADR-0018 overhead estimate: that needs `bench/stats.py` (Hodges–Lehmann, Wilcoxon), which does not exist yet. They answer one question, which way costs less here, and the paired differences show whether that answer holds round by round.

## Tests

```bash
python3 -m unittest bench/rb_cost/test_summarize.py   # the summarizer on synthetic output
make mutate-py                                         # includes 13 planted bugs in summarize.py
```
