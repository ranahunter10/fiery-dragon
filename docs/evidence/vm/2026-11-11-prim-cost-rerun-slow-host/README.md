# The cost breakdown rerun with the host-speed control: the host was slow again (2026-11-11)

Evidence for E-0183. VM `p15-dev-2604`, 7.0.0-38-generic, 3 vCPU, tree at `d524097` (PR #69). Commands as in `bench/prim_cost/README.md`: `prim_cost 20 20000`, `summarize.py --ref-nullsys-ns 87.5`, `prog_stats.py --ops 220000 --rounds 7 --ref-nullsys-ns 89.1`.

`prim_cost.txt`, `prim_cost.md` and `prog_stats.txt` are the maintainer's files, rebuilt here from his paste, byte for byte: sha256 `8cc32f70...d850`, `1b3f2338...ec11` and `d062d83a...4ed4ed`, as the VM printed them. `summarize.py` at `d524097`, run here on `prim_cost.txt`, gives `prim_cost.md` byte for byte.

## What the files show (MEAS)

- **Both reports mark the run SLOW, not UNSTEADY.** A null syscall cost 380.6 ns in `prim_cost` (median of 20 rounds, 353.8 to 464.5) and 365.1 ns under `prog_stats.py` (7 rounds, 322.8 to 401.7): 4.35 and 4.10 times the references. The host was steadily slow, not stalling.
- **The workload itself was about as slow:** 200,000 open+close of the known file took 2,182,605,030 to 2,331,616,695 ns of thread CPU per round, where E-0176 measured 2,281.2 ns each.
- **Run counts (exact):** about 4.00 program runs per open+close in every round: the path program once, the session program twice, the free program once (1.001 to 1.003: a few frees of other files). The snapshot programs ran in rounds 1, 3 and 5 (the segment rotation), 715 FD rows and 175 tasks each time.
- One `spine_rename` run in round 2 took 514,688 ns for 2 runs (257,344 ns each), the others 3,000 to 6,000 ns: one long run, cause not known.

## What is not shown

No ns per run, per record or per map operation is quotable: the run is SLOW by the rule declared before it.

## The likely cause (INF)

E-0104 measured 374 ns per null syscall with the laptop on battery, and E-0108 92.5 ns on its charger in Best performance mode. The two slow runs' 355 to 381 ns sit on the battery figure. Not confirmed: the run records nothing about the Windows host's power state.
