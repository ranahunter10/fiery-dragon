# Where a capture program's time can go (after E-0176)

**Question.** An open+close costs the program 1.4 µs more under capture (E-0176), of which the three hook paths are about 180 ns (E-0138). The rest is inside our programs. Two measurements say where:

1. **`prim_cost`**: what each building block costs on this host, alone in a loop: a ring record (reserved and submitted, reserved and discarded, copied in with `bpf_ringbuf_output`), a hash-map lookup, an entry inserted and deleted, an atomic counter, a 96-byte copy into a per-CPU buffer, a clock read. It runs as a `SEC("syscall")` program through `BPF_PROG_RUN`, so no hook path is in the numbers; the time is taken inside the program around a `bpf_loop`, and an empty loop is subtracted round by round.
2. **`prog_stats.py`**: what each of p15d's programs costs while a command runs, from the kernel's per-program statistics (`run_cnt`, `run_time_ns`).

The first says what a design could save (for example one ring record against one per-CPU copy: the two-level buffer of eAudit, R-042 §3.5). The second says which program to look at.

```
sudo make bench-prim-cost ROUNDS=20                 # raw lines in build/prim_cost.txt, the report in build/prim_cost.md
sudo python3 bench/prim_cost/prog_stats.py --p15d build/p15d --ops 220000 -- build/open_cost /var/tmp/p15-open-cost 200000 20000
```

**Limits.**
- `prim_cost` is one thread on one CPU: no contention on the ring's lock or on a hash bucket. Step 2b's ceiling gate measures those.
- Its ring has no reader during a run and is emptied between runs; a submit never wakes anyone. p15d's records don't wake the drain below the high-water mark either (ADR-0020 rule 2).
- `bpf_d_path` cannot be timed this way (it needs a file from a hook). Its cost is what remains of the open program's `run_time_ns` once the blocks it uses are taken off: an inference, labelled so.
- `prog_stats.py` runs with `kernel.bpf_stats_enabled=1`, which adds two clock reads to every program run (about 20 ns, ADR-0018 rule 3.2). It shows where the time goes. Overheads are quoted from `bench/open_cost`, with the statistics off.
- The dev container and CI's runner are not the target: only the VM's numbers count.
