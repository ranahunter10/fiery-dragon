# Slice B research: file and socket data flow (2026-11-06)

Input for ADR-0015 (file identity) and ADR-0005 (filtering and aggregation), and for slice B's hook choice. It extends the October notes (the project doc `research_capture_rebuild_2026-10-21/dataflow_hooks.md`, Q1–Q8: every I/O path and the hook that sees it, at v7.3) and [`../2026-11-06-fileless-and-dataflow-capture.md`](../2026-11-06-fileless-and-dataflow-capture.md) §5.

Three reports, each written by a research agent with read-only access, every claim graded (SRC / PDF / DOC / BLOG / INF / OPEN). They are inputs to decisions, not decisions.

| File | Question |
|---|---|
| [`kernel-v7.0.md`](kernel-v7.0.md) | At the v7.0 tag: which BPF attach types can be skipped for other tasks under preemption, and which counter records it; file identity (i_generation, inode reuse, overlayfs, btrfs, pipes and sockets); path resolution from BPF; open, close and mmap hooks; classic tracepoints for data flow |
| [`provenance-and-pids.md`](provenance-and-pids.md) | What the provenance graph and the detectors need: causality-preserving reduction (Xu et al. CCS'16, Hossain et al. USENIX Sec'18, LogGC, NodeMerge), object versioning (CamFlow, SPADE), the DARPA TC CDM schema, what PIDSMaker and its detectors consume |
| [`tools.md`](tools.md) | How Kunai, Datadog's runtime security, Tetragon, Tracee, Falco, Elastic, auditd and Sysmon for Linux bound volume, identify files, resolve paths, count loss and handle lifecycle; known pitfalls |

## Checked against the source in this session

From a blobless clone of torvalds/linux at `v7.0` (`028ef9c96e96`), the files read, not run:
- **kprobes and classic tracepoints run non-preemptible and skip only when another BPF program is active on the same CPU**, counting the skip: `trace_call_bpf()`, `kernel/trace/bpf_trace.c` L109–127 (`cant_sleep()`, `__this_cpu_inc_return(bpf_prog_active) != 1` → `bpf_prog_inc_misses_counters`).
- **fentry/fexit take a per-program guard with migration, not preemption, disabled:** `__bpf_prog_enter_recur()`, `kernel/bpf/trampoline.c` L1143–1157 (`rcu_read_lock_dont_migrate()`, `bpf_prog_get_recursion_context()` → `bpf_prog_inc_misses_counter`). This is the E-0089 mechanism.
- **A map lookup or update from userspace holds `bpf_prog_active` while preemptible:** `bpf_disable_instrumentation()` = `migrate_disable(); this_cpu_inc(bpf_prog_active);` (`include/linux/bpf.h` L2547–2551), taken by `bpf_map_copy_value()` (`kernel/bpf/syscall.c` L317) and the update path (L270). So while p15d is preempted inside such a call, kprobe and classic-tracepoint programs of other tasks on that CPU are skipped, and counted in their miss counters. This concerns the spine today (p15d reads its per-CPU counters by map lookup for every STATS record), not only slice B. Every VM run so far shows 0 spine skips.

Not yet checked: the provenance report's paper claims come from summaries of the PDFs (its author says so). Xu et al.'s merge rule must be read in the paper itself before ADR-0005 states it.
