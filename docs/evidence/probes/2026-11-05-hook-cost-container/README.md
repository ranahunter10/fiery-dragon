# The hook-cost harness, first run: dev container (2026-11-05)

**Where:** the cloud dev container: kernel 6.18.44, 2 vCPUs, pinned to CPU 1, root, tracefs mounted. **This is not the target.** On 6.18, tracepoint BPF still runs with preemption off, so `tp_btf` here doesn't take 7.0's preemptible path. ADR-0018 counts only VM numbers. This run shows that the harness works and what scale to expect.

**What:** `build/hook_cost build/spine.bpf.o 20 200000 300` on this PR's build: 20 rounds, 200,000 renames and 300 execs per arm. The summary is `python3 bench/hook_cost/summarize.py hook_cost.txt`.

**Files:**
- [`hook_cost.txt`](hook_cost.txt): the raw lines;
- [`summary.md`](summary.md): the ADR-0018 report.

## Findings (MEAS, dev container; not the target)

1. **Every arm's books closed.** In all 20 rounds plus the warm-up, each traced arm's hits equalled its events and the untraced arms saw none. The shipped spine EXEC's records of our children passed `p15_rec_check`, 0 failing.
2. **Rename, CPU time (primary):**
   - the classic path added **35.6 ns** per event (95 % interval 23.4–44.1 ns);
   - `tp_btf` added **22.1 ns** (18.4–25.2 ns);
   - classic against `tp_btf`: **+13.9 ns** per event (0.8–24.7 ns), or +9.85 % of a rename syscall, Wilcoxon p = 0.027, outside the A/A floor. That is 0.15 of this host's null syscall (91.8 ns, median).
   - On wall time (secondary), classic against `tp_btf` is not resolved (p = 0.053; A/A floor −10.6 % to +0.6 %).
3. **Exec: nothing resolves.**
   - An exec costs about 0.91 ms of the child's CPU here, with an A/A floor of ±4.5 %.
   - The classic path, `tp_btf` and the shipped spine EXEC are each "not resolved against none". So is classic against `tp_btf`.
   - A ~14 ns hook-path difference is about 0.002 % of an exec. No exec-level run on a host this noisy can show it, which is why the rename arm exists.

## What it means for ADR-0020 (INF until the VM run)

The classic path's extra cost is tens of nanoseconds per event, against an event (an exec) that costs about a millisecond. If the VM agrees, ADR-0020's "Bad: cost unmeasured" becomes a measured, negligible cost, and its confirmation 5 is met. The command is `sudo make bench-hook-cost ROUNDS=20` on the VM.
