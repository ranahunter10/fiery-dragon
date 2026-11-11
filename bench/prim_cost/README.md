# Where a capture program's time can go (after E-0176)

**Question.** An open+close costs the program 1.4 µs more under capture (E-0176), of which the three hook paths are about 180 ns (E-0138). The rest is inside our programs. Two measurements say where:

1. **`prim_cost`**: what each building block costs on this host, alone in a loop: a ring record (reserved and submitted, reserved and discarded, copied in with `bpf_ringbuf_output`), a hash-map lookup, an entry inserted and deleted, an atomic counter, a 96-byte copy into a per-CPU buffer, a clock read. It runs as a `SEC("syscall")` program through `BPF_PROG_RUN`, so no hook path is in the numbers; the time is taken inside the program around a `bpf_loop`, and an empty loop is subtracted round by round.
2. **`prog_stats.py`**: what each of p15d's programs costs while a command runs, from the kernel's per-program statistics (`run_cnt`, `run_time_ns`).

The first says what a design could save (for example one ring record against one per-CPU copy: the two-level buffer of eAudit, R-042 §3.5). The second says which program to look at.

```
make build/prim_cost build/open_cost build/p15d      # as the user: never build under sudo
sudo build/prim_cost 20 20000 > build/prim_cost.txt
python3 bench/prim_cost/summarize.py build/prim_cost.txt --ref-nullsys-ns 87.5 | tee build/prim_cost.md
sudo python3 bench/prim_cost/prog_stats.py --p15d build/p15d --ops 220000 --rounds 7 --ref-nullsys-ns 89.1 \
     -- build/open_cost /var/tmp/p15-open-cost 200000 20000 > build/prog_stats.txt
```

**Host speed (declared before the run that uses it; E-0180, E-0181).** The first VM run was taken on a host four to five times slower than the open-cost run, and nothing in its output said so. Every round of both harnesses now records what a null syscall (`getppid`) costs: `prim_cost` times 100,000 of them after each round, `prog_stats.py` reads the `nullsys` row its command (`open_cost`) prints. The report states the median and the range, and marks the run **not quotable** when
- the dearest round's null syscall is more than **1.5** times the cheapest's (UNSTEADY), or
- the median is more than **1.5** times the reference given with `--ref-nullsys-ns` (SLOW). The references are E-0176's: 87.5 ns without capture (for `prim_cost`), 89.1 ns with p15d running (for `prog_stats.py`).

A run marked so is a valid result ("not resolved on this host"); its costs are not used. 1.5 is a judgement, not a measured limit: E-0176's 20 untraced rounds ran from 85.6 to 98.1 ns per null syscall (`open_cost.txt`), and the slow run's one figure was 355.2 ns.

`prog_stats.py` runs the command `--rounds` times under one p15d and reports each program's median ns per run with its cheapest and dearest round. After the first round the "distinct" files are objects p15d already knows.

**Limits.**
- `prim_cost` is one thread on one CPU: no contention on the ring's lock or on a hash bucket. Step 2b's ceiling gate measures those.
- Its ring has no reader during a run and is emptied between runs; a submit never wakes anyone. p15d's records don't wake the drain below the high-water mark either (ADR-0020 rule 2).
- `bpf_d_path` cannot be timed this way (it needs a file from a hook). Its cost is what remains of the open program's `run_time_ns` once the blocks it uses are taken off: an inference, labelled so.
- `prog_stats.py` runs with `kernel.bpf_stats_enabled=1`, which adds two clock reads to every program run (about 20 ns, ADR-0018 rule 3.2). It shows where the time goes. Overheads are quoted from `bench/open_cost`, with the statistics off.
- The dev container and CI's runner are not the target: only the VM's numbers count.
