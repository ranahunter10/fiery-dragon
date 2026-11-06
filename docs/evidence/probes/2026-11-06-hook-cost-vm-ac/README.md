# The hook-path cost on the VM, third run, the first on AC power (2026-11-06)

**Where:** the VM `p15-dev-2604` (7.0.0-38-generic, `PREEMPT(lazy)`, 3 vCPUs). This is step 18 of `vm_verify.sh` run `20261106T074939Z`, at commit `6905850`, the head of #53. That run's full log is [`../../build/2026-11-05-snapshot-4c/vm-verify-20261106T074939Z.log`](../../build/2026-11-05-snapshot-4c/vm-verify-20261106T074939Z.log).

**Power:** the Windows host was on its charger, in the Best performance mode. The maintainer set this before the run, after E-0104's run on battery.

**Files:**
- [`hook_cost.txt`](hook_cost.txt): step 18's raw lines, all 20 rounds plus the warm-up. Its sha256 (`50e0ecea…`) matches the one the maintainer printed on the VM.
- [`summary.md`](summary.md): `python3 bench/hook_cost/summarize.py hook_cost.txt`, made here from the raw file.

## Findings (MEAS, VM)
1. **The host was fast and steady.** The null syscall (median) took **92.5 ns**, against 163.6 ns in E-0101 and 374 ns in E-0104 (on battery). No step of the run was marked with a host stall.
2. **Rename, CPU time per event** (primary, 20 rounds):
   - classic tracepoint against `tp_btf`: **+36.3 ns per event** (95 % interval 24.6–46.1 ns), +21.9 %, Wilcoxon p = 1.9 × 10⁻⁶, outside the A/A floor. That is 0.39 of this host's null syscall.
   - Classic against no hook: +56.1 ns (45.6–66.9). `tp_btf` against no hook: +21.1 ns (15.6–26.6).
   - Wall time agrees (+36.3 ns, p = 1.9 × 10⁻⁶).
3. **Exec: nothing resolves.** An exec cost about 2.4 ms (median of the untraced arm), against about 4.85 ms in E-0101 and about 16 ms in E-0104. Every exec comparison is "not resolved on this host", inside an A/A floor of about −3 % to +6 %.

## What it means (INF, from the measured numbers)
- The three runs agree on the cost of ADR-0020's choice: **tens of ns per event**. They measured +49.4 ns (E-0101), +92.7 ns (E-0104, battery) and +36.3 ns (this run).
- The figure scales with how fast the host is that day, so a single number in ns is a per-run figure, not a constant. The ratio to the null syscall is steadier: 0.30, 0.25 and 0.39.
- ADR-0020 stays as accepted.
