# The hook-path cost on the VM, and the full check of #47–#49 (2026-11-05)

**Where:** the VM `p15-dev-2604` (7.0.0-38-generic, `PREEMPT(lazy)`, 3 vCPUs), `vm_verify.sh` run `20261105T025005Z` at commit `e1ddd83`, the head of #47–#49.

**Files:**
- [`vm-verify-summary.txt`](vm-verify-summary.txt): the run's SUMMARY, as pasted by the maintainer;
- [`hook_cost.txt`](hook_cost.txt): step 18's raw lines, all 20 rounds plus the warm-up;
- [`summary.md`](summary.md): `python3 bench/hook_cost/summarize.py hook_cost.txt`, made here from the raw file;
- [`vm-summary-paste.txt`](vm-summary-paste.txt): the maintainer's paste of the same report, made on the VM (CRLF line ends, from Windows). Once the CRs are removed it is identical to `summary.md`, line for line;
- [`verify.log`](verify.log): the run's full log, all 18 steps.

## Findings (MEAS, VM)

1. **All 18 steps pass, and no host stall was marked.** They cover:
   - the atomic counters of #47: the network hooks load (step 12), and the end-to-end test with network capture passes (step 14);
   - the p15d planted-bug sweep (step 15);
   - the statistics module and harness of #48–#49 (steps 5, 8, 18).
2. **Rename, CPU time per event** (primary, 20 rounds):
   - the classic tracepoint path added **107.6 ns** (95 % interval 82.4–131.9 ns);
   - `tp_btf` added **65.4 ns** (40.8–88.8 ns);
   - **classic against `tp_btf`: +49.4 ns per event** (9.8–72.4 ns), +18.2 %, Wilcoxon p = 0.017, outside the A/A floor. That is 0.30 of this host's null syscall (163.6 ns, median).
   - Wall time agrees: +53.6 ns (10.9–78.4 ns), p = 0.017.
3. **Exec: nothing resolves.**
   - An exec costs about 4.85 ms of the child's CPU on the VM (median of the untraced arm).
   - The A/A floor is −9.2 % to +0.8 %.
   - Classic against none, `tp_btf` against none, the shipped spine EXEC against none, and classic against `tp_btf` are all "not resolved on this host", on CPU and on wall time.
4. **The container run was the right size, about 3.5× smaller.** It measured +13.9 ns for classic against `tp_btf` (E-0099); the VM's +49.4 ns is in the same range of tens of ns.

## What it means for ADR-0020 (INF, from the measured numbers)

- The three classic spine hooks (exec, exit, rename), each at the upper bound of finding 2 (72.4 ns), cost at most about 217 ns per process lifetime. That is about 0.004 % of one exec's 4.85 ms of CPU.
- The exec hook also copies its filename into the tracepoint's record. That is a bounded string copy and isn't measured separately; it falls inside the exec arm's "not resolved".
- In return, it removes the 3–10 % of exec and exit events the kernel skipped (E-0089, E-0090).

Confirmation 5 is met, and ADR-0020 is accepted, as the maintainer decided on 2026-11-05.

## Reproduce

```
python3 bench/hook_cost/summarize.py docs/evidence/probes/2026-11-05-hook-cost-vm/hook_cost.txt
```
