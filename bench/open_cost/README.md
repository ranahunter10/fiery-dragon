# What capture adds to an open and a close (STATE decision 22a.4)

**Question.** With p15d running as it would in use (spine, NET and file identity), what does one `open` + `close` cost the program that makes it, what does it cost p15d, and what lands in the WAL? This is the first cost number of the whole pipeline: hooks, maps, ring, drain, queue, writer. The hook-type harnesses ([`rw_hook_cost`](../rw_hook_cost/README.md), [`hook_cost`](../hook_cost/README.md)) measured trivial bodies only.

**Design** (ADR-0018 rule 2).
- **Workload** ([`open_cost.c`](open_cost.c)): one thread pinned to one CPU does 10^6 `getppid` (the null-syscall baseline, rule 3.2), then SAME × open+close of one file, then DISTINCT × open+close of DISTINCT files, each once. The files exist before any arm runs.
  - `same` is the steady state: capture already knows the object, so the OPEN record has no facts.
  - `distinct` is the first sighting of every object: each OPEN carries the 40-byte facts and inserts an object entry. p15d is started fresh for every traced arm, so this holds in every round.
- **Arms** ([`run.py`](run.py)): `none`, `p15d`, `none2` (the A/A control), in an order rotated every round, after one untimed warm-up round. For the `p15d` arm the driver starts p15d, waits for `code=start`, gives the opening snapshot SETTLE seconds, reads p15d's CPU over IDLE seconds of nothing, runs the workload, reads p15d's CPU again, stops p15d and reads its WAL.
- **Primary metric (declared before the run):** the workload thread's CPU time per open+close. It holds the in-kernel cost of the hooks, which run on that thread. Secondary: wall time per open+close, which also holds contention with p15d's threads.
- **Books a traced arm must close**, or no timing is reported: p15d exits 0 with run state 0, its invariant holding and END written; every open the workload made is an OPEN record of its pid under DIR (or one of that pid's PATH_MISSING records); every one has its CLOSE; nothing was lost to the ring.

**Report** ([`summarize.py`](summarize.py), using [`bench/quant/paired.py`](../quant/paired.py)):
- per event and metric: each arm's median with its interval, the paired effect of p15d against none with its exact interval and p, the A/A floor, the verdict of rule 2.4, and the added ns per open+close, also in null syscalls;
- records and bytes per open+close in the WAL, the share of opens with facts, PATH_MISSING;
- p15d's CPU: per second when idle; per open+close of the workload, gross and after the idle rate is taken off;
- the agent overhead two ways: p15d's CPU above idle ÷ the open events' CPU without capture, and eAudit's definition (R-042 §4.3) over the whole workload.

```
sudo make bench-open-cost ROUNDS=20          # raw lines in build/open_cost.txt, the report in build/open_cost.md
```
`DIR=` moves the files (default `/var/tmp/p15-open-cost`; it must be a real filesystem), `SAME=` and `DISTINCT=` change the counts, `P15D_ARGS='--p15d-arg=--no-net'` passes options to p15d.

**Where p15d's time goes** (`--perf DIR`): each traced arm also runs `perf record` with DWARF call graphs on p15d's threads over the workload's window only. p15d and libbpf are built `-O2 -g` without frame pointers, hence DWARF. Sampling costs p15d CPU, so such a run is a profile, not a timing: its config line says `perf=DIR`, and `summarize.py` reports its books and refuses its timings.
```
sudo ~/p15venv/bin/python bench/open_cost/run.py --p15d build/p15d --workload build/open_cost \
     --dir /var/tmp/p15-open-cost --rounds 3 --perf /var/tmp/p15-perf > build/open_cost_perf.txt
sudo perf report -i /var/tmp/p15-perf/perf-0.data --no-children --sort comm,dso,sym --stdio --percent-limit 0.5 > build/p15d_profile.txt
```

**Limits.**
- An open+close with nothing between them is the cheapest thing a program does with a file, so the relative overhead here is an upper bound for programs that also read, compute or wait. The added ns per open+close is the number that transfers.
- One thread. Contention between cores on the maps and the ring is not measured here; that is step 2b's ceiling gate.
- p15d's CPU is read from `/proc/<pid>/task/*/schedstat` with the kernel's scheduler accounting, and its idle rate is measured for one second per round, just before the workload. BPF time on other tasks' threads (their own opens) is not in either number.
- The dev container cannot load the file programs (EPERM): there the traced arm's books fail, which is what the tests of the driver use. CI's runner runs every arm as a smoke test, not a measurement. Only the VM gives the numbers, on its charger in Best performance mode (E-0108).
