---
status: accepted
date: 2026-11-06
accepted: 2026-11-08
owner: Ashish Rana
consulted: [kernel v7.0 include/linux/bpf.h, kernel/bpf/syscall.c, kernel/bpf/arraymap.c, kernel/trace/bpf_trace.c, kernel/bpf/trampoline.c; research note 2026-11-06-dataflow-slice-b (kernel-v7.0.md §1.3); ADR-0006 rule 6; ADR-0020; E-0089, E-0090, E-0097]
supersedes: the sentence of ADR-0006 rule 6 "Counters live in a per-CPU array map" (where they live and how p15d reads them). The rest of rule 6, the accounting invariant and its stats records, is unchanged.
---

# 0026: The BPF counters are an mmapable array, and p15d makes no map syscall once a program is attached

## Context and problem statement

p15d read its BPF loss counters with `bpf_map_lookup_batch` on per-CPU arrays, after every poll. On 7.0 a map lookup or update from userspace runs `bpf_disable_instrumentation()`, which is `migrate_disable(); this_cpu_inc(bpf_prog_active)`, and so stays preemptible (`include/linux/bpf.h` L2547–2551; taken in `bpf_map_copy_value`, `kernel/bpf/syscall.c` L317, and the update path, L270; a batch lookup takes it once per element, L2099). kprobe and classic-tracepoint programs enter through `trace_call_bpf()`, which skips the program when `bpf_prog_active` is already non-zero on that CPU and counts the skip in the program's miss counter (`kernel/trace/bpf_trace.c` L109–127). So while p15d is preempted inside such a call, the spine's exec, exit and rename programs, which ADR-0020 put on classic tracepoints exactly so that no other task can make the kernel skip them, are skipped for other tasks on that CPU.

The skips are counted (STATS v2 and GAP carry them, and the run turns INVALID), and no VM run so far shows one. But every hot-path hook slice B adds (kprobes on the VFS read and write paths, research note §1) would be exposed the same way, and the window grows with every map call. The same holds for libbpf's write of a skeleton's `.bss` at load: p15d loaded the snapshot object after the spine was attached.

## Decision drivers

- ADR-0020's guarantee, that the kernel skips no spine event for another task, should hold by construction, not only "rarely broken and counted".
- No silent fallbacks and no new loss: a counter must never be dropped by the new storage.
- The read must stay cheap and must not need privileges p15d does not already have.

## Considered options

1. **Keep the per-CPU arrays and the batch lookup** (today). Counted, but the skip window exists on every poll.
2. **An mmapable array read through mmap** (chosen). `BPF_F_MMAPABLE` is allowed on `BPF_MAP_TYPE_ARRAY` only (`kernel/bpf/arraymap.c` L66–68); the kernel maps whole pages of the value area (L583–590). Reading it is a plain memory load: no syscall, no guard.
3. **Counters in the ring as records.** Every count would cost ring space and could itself be lost to a full ring, which is the loss it reports.

## Decision outcome

Option 2.

### Rules

1. **Layout** (`bpf/include/p15_counters.h`). Each counter map is a `BPF_MAP_TYPE_ARRAY` of `u64` with `BPF_F_MMAPABLE`: `ncpu + 1` rows of `P15_CTR_MAX` counters (512 bytes, whole cache lines). A program counts into row `cpu` for `cpu < ncpu`, and into the last row, row `ncpu`, otherwise. `ncpu` is a rodata constant. A counter's value is its slot summed over every row.
2. **A loader that sets nothing still counts everything.** `ncpu` defaults to 0 and the map's default size is one row (`P15_CTR_ENTRIES(0)`), so an unconfigured program (a bench or test loader) counts every event into row 0.
3. **The size and the row count are set together and checked.** `p15_counters_configure()` sets the map's `max_entries` to `P15_CTR_ENTRIES(ncpu)` and the program's `ncpu` before load, for `ncpu = libbpf_num_possible_cpus()`; `p15_counters_verify()` checks type, flag, value size and size after load, and p15d refuses to start on a mismatch. That makes an out-of-range lookup, the only way a count could be dropped (`if (v)` in `count()`), impossible for a running daemon.
4. **The add stays atomic** (E-0097): fentry and fexit programs run preemptible on 7.0, so two may interleave on one CPU's row.
5. **p15d reads the counters only through a read-only shared mapping** (`daemon/counters.c`), each value with a relaxed atomic load.
6. **No map syscall once any program is attached.** p15d loads every object, including the snapshot iterator (whose `.bss` libbpf writes with a map update), before it attaches the spine. Reading the kernel's skip counters by `BPF_OBJ_GET_INFO_BY_FD` stays: that call takes no `bpf_prog_active`.

### Consequences

- Good: ADR-0020's no-skip property for the classic-tracepoint spine no longer has a p15d-made exception, and slice B's kprobes start from the same footing.
- Good: a counter read is a memory scan; the batch lookup's allocation and error paths are gone.
- Bad: the counter map is `(ncpu + 1) × 512` bytes instead of `ncpu × 512`, page-rounded.
- Bad: counters are now readable by anything that can map the map fd (only p15d holds it).
- Neutral: which row an event lands in affects cache-line sharing only, never a total, so that choice cannot be tested for correctness (stated in the mutation sweep).

### Confirmation

1. `daemon/tests/test_counters.c`: the layout, the sum over every row including the last, and configure / verify against the spine's real map definition (opened, not loaded: no root).
2. `it_p15d.sh` case 7: p15d runs under `strace -e trace=bpf`; after the first non-iterator attach there are 0 map lookups, updates or deletes, while the info calls that read the skip counters are present (the trace saw the run). With the snapshot loaded after the attach (the old order), the case fails with "got: 1".
3. The other end-to-end cases close their books through the mapped read, and case 3 still finds its forced loss.
4. `daemon/tests/mutate_p15d.py` kills the new planted bugs: in the row sum, configure, verify, the drain's read, the loader, and the startup order.
5. The same on the VM and in CI. **Held (E-0123, E-0124):** CI on 7.0.0-1017-azure with network on, and the VM at `d5cd6cd`: end-to-end every case, case 7 with 0 map syscalls after attach; the sweep 30/30.

### Falsifier

Reopen if a VM or CI run shows a map syscall after attach in case 7, or if a counter total read through the mapping disagrees with the records the drain saw (the books stop closing).

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | `bpf_disable_instrumentation()` = `migrate_disable(); this_cpu_inc(bpf_prog_active)` | SRC | v7.0 include/linux/bpf.h L2547–2551 |
| 2 | Map lookups (incl. per element of a batch) and updates from userspace take it | SRC | v7.0 kernel/bpf/syscall.c L270, L317, L2099 |
| 3 | kprobe and classic-tracepoint programs skip while `bpf_prog_active` is set, counting a miss | SRC | v7.0 kernel/trace/bpf_trace.c L109–127 |
| 4 | `BPF_F_MMAPABLE` only on `BPF_MAP_TYPE_ARRAY`; whole pages mapped | SRC | v7.0 kernel/bpf/arraymap.c L66–68, L583–590 |
| 5 | Before the change, p15d's only map syscalls after attach were the counter reads and the snapshot object's `.bss` write | MEAS | strace in the dev container, this PR's evidence |
