# p15d's CPU on an idle host (gate 3 of STATE decision 28)

**Question.** p15d burned 14.65 ms of CPU per second on the idle VM (E-0176), against a budget of 2 ms (STATE decision 29). Where does it go, and what brings it under the budget without weakening capture?

**What the code says (SRC).** The drain wakes on a 10 ms timer (ADR-0020 rule 2: records wake it only at a ring's high-water mark), so it runs 100 times a second with nothing to do. Each wake-up reads the rings, the mapped counters, and the kernel's skip counters with one `BPF_OBJ_GET_INFO_BY_FD` per program: 4 for the spine, plus the network programs and 4 for file identity. The writer woke every 100 ms. In the dev container (spine only, nearly no events; not the target): 95 wake-ups and 381 `bpf` calls per second (strace), 3.5 ms/s in the drain thread, of which a bare 10 ms `epoll_wait` loop alone costs 3.3 ms/s. Idle cost is a price per wake-up times the wake-up rate.

**What this gate changes.**
- `--poll-max-ms N` (10 to 1000): after a poll that took records, or left some for want of a batch, the drain waits 10 ms; after an empty poll, twice its last wait, up to N. Under load nothing changes. A burst still wakes the drain at a quarter-full ring, as before. What a longer maximum costs: a record can wait up to N ms before the WAL (inside ADR-0007's 1 s durability window); a GAP for an idle-time kernel skip spans up to N ms; the stop is seen up to N ms later. The default stays 10 ms (today's behaviour) until the VM's numbers pick one, by ADR.
- The writer waits until its next deadline (the next STATS, rotation or fdatasync; at most 500 ms) instead of 100 ms; a batch still wakes it at once.
- The writer thread is named `p15d-writer`, so its CPU is visible on its own.

**How.** `run.py` starts p15d once per arm and round (arms rotated each round), waits SETTLE seconds after its start line, reads each thread's on-CPU time over a WINDOW-second window, stops it, and reads its WAL: the records of each ring in the window (the background load, so arms are compared at the same load) and the drain's polls per second (the poll-gap histogram in STATS). A run counts only if p15d exited 0 with END state 0 and its invariant holding. `summarize.py` reports each arm's median CPU per second, the range over rounds, polls per second, load, the ratio to the first arm, and whether the median and the dearest round are under the budget.

```
make build/p15d                                             # as the user
sudo ~/p15venv/bin/python bench/idle_cost/run.py --p15d build/p15d --work /var/tmp/p15-idle --rounds 5 \
     --arm max10=--poll-max-ms=10 --arm max50=--poll-max-ms=50 --arm max100=--poll-max-ms=100 \
     --arm max200=--poll-max-ms=200 --arm max500=--poll-max-ms=500 > build/idle_cost.txt
python3 bench/idle_cost/summarize.py build/idle_cost.txt
```

**Limits.**
- "Idle" is the host's own background: the VM's services still open files and fork. Each arm's load is reported next to its CPU; arms with very different loads are not comparable.
- schedstat counts p15d's threads only, not the BPF programs' time, which runs on the threads of whoever opens files or forks. bench/open_cost measures that cost.
- A round's p15d is a fresh start: its first seconds include the opening snapshot, which SETTLE skips.
- The dev container's numbers above show the structure only; only the VM's numbers decide.
