# The BPF counters: atomic adds (2026-11-05)

**Where:** the dev container (kernel 6.18), on `main` at `9e8162d` plus this change. The source facts are from Linux v7.0.

**Files:**
- [`container.txt`](container.txt): `make smoke`, `make check`, `make it-p15d` and `make mutate-spine` on the change;
- [`objdump.txt`](objdump.txt): the atomic instructions in both objects.

## Findings

1. **fexit and tp_btf programs run with preemption on (SRC).**
   - v7.0's `kernel/bpf/trampoline.c` `__bpf_prog_enter_recur()` takes `rcu_read_lock_dont_migrate()`: migration is off, preemption is not. Tracepoint BPF got the same treatment in 7.0 (the SRCU-fast series, ADR-0020).
   - The recursion guard, `bpf_prog_get_recursion_context(prog)`, is **per program**. It stops the same program from running twice on a CPU, not two different programs.
2. **The network counters could lose counts (SRC; no failure observed).**
   - All six fexit programs in `net.bpf.c` (`inet_stream_connect`, `inet_dgram_connect`, `inet_accept`, `inet_listen`, `inet_bind`, `inet6_bind`) bump the same per-CPU slots of `bulk_counters`, with a plain `*v += 1`.
   - That is a load, an add and a store. If a connect is preempted between the load and the store, and an accept on the same CPU bumps the same slot, the connect's store overwrites the accept's count.
   - A lost SEEN or EMITTED count breaks the identity seen = emitted + failures without any counter saying why. The run state would then be wrong.
   - It needs a preemption inside a window of a few instructions, so it is rare. It is still a silent loss, which CLAUDE.md rules out.
3. **The spine counters were safe, but only by an unstated rule (SRC).** Each spine slot has exactly one writer program (fork writes FORK's slots, and so on), so no two writers can interleave. The comment said "per-CPU slot: no atomics needed". A future hook that shares a slot would have broken that silently.
4. **The fix.** Both `count()` functions use `__sync_fetch_and_add(v, 1)`, which BPF compiles to one `lock add` on the CPU's own slot. `objdump.txt` shows 13 in `spine.bpf.o` and 24 in `net.bpf.o`.
5. **Checks (MEAS, container).**
   - The spine loads and passes its self-test.
   - `make check` and the end-to-end test pass. Case 5 is skipped here: fexit doesn't load in this container.
   - The spine EXEC planted bugs are 7/7 caught.
   - CI loads the network programs on 7.0. The VM runs the full `vm_verify.sh`.

## Not shown

- A lost update caught in the act. On the CI runner's kernel the race can't occur: it needs preemption inside a BPF program, which PREEMPT_VOLUNTARY doesn't give. On the VM (`PREEMPT(lazy)`) it can occur, but its window is a few instructions. A demonstrator would widen that window on purpose. Not built: the fix doesn't depend on the measured rate.
- The cost of the atomic add. It is one uncontended locked add on a per-CPU cache line per counter bump, so it isn't measured separately. It falls under the ADR-0018 hook-cost run.
