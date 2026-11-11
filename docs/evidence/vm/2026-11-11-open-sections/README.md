# Section timing of the file programs, and the path program's skips under contention (VM, 2026-11-11)

Evidence for E-0187 to E-0189. VM `p15-dev-2604`, 7.0.0-38-generic, 3 vCPU, tree at `8438404` (PR #70), host on its charger in Best performance. Host check before the run: 96,493,519 ns for 10^6 null syscalls (limit 131,250,000). Commands: the one script in the session, `open_sections single 20 200000` and `open_sections contend 12 200000` on `/var/tmp/p15-open-cost/same`.

`open_sections.txt` and `open_contend.txt` are the maintainer's files, rebuilt here from his paste, byte for byte: sha256 `a6963f41...66a6` and `e82d0b63...fff2`, as the VM printed them. The two `.md` reports are `summarize.py` at `8438404` run here on them; they are the reports the VM printed.

## Single thread: where each program's time goes (MEAS, `open_sections.md`)

Host speed: a null syscall cost 93.4 ns (20 rounds, 83.7 to 106.9); not SLOW, not UNSTEADY. Books: 4,200,001 OPEN and 4,200,001 CLOSE read, nothing lost.

| section | samples per open | ns per sample (median) | cheapest to dearest round | net of the bracket |
|---|---|---|---|---|
| empty | 1.000 | 15.7 | 14.8 to 16.4 |  |
| open_all | 1.000 | 640.0 | 609.2 to 677.4 | 624.3 |
| open_claim | 1.000 | 23.1 | 22.1 to 24.4 | 7.6 |
| open_hdr | 1.000 | 69.6 | 66.0 to 73.1 | 54.0 |
| open_facts | 1.000 | 80.9 | 76.8 to 84.0 | 65.1 |
| open_obj | 1.000 | 29.9 | 28.3 to 31.3 | 14.1 |
| open_file | 1.000 | 28.5 | 27.3 to 30.1 | 13.0 |
| open_dpath | 1.000 | 102.5 | 97.3 to 106.4 | 86.7 |
| open_output | 1.000 | 52.5 | 50.0 to 68.2 | 36.7 |
| sess_entry | 1.000 | 265.6 | 251.3 to 286.9 | 250.2 |
| sess_file | 1.000 | 109.3 | 101.7 to 118.0 | 93.9 |
| sess_return | 1.000 | 38.0 | 35.5 to 39.8 | 22.1 |
| free_all | 1.000 | 320.3 | 306.2 to 335.2 | 304.7 |
| free_lookup | 1.000 | 28.3 | 27.1 to 29.7 | 12.7 |
| free_ring | 1.000 | 131.3 | 125.6 to 139.6 | 115.6 |
| free_delete | 1.000 | 62.0 | 59.1 to 66.2 | 46.2 |

- open_all: 640.0 ns, of which its 7 timed sections 387.1; the rest, 252.9 ns, is untimed code and the inner brackets' own cost.
- sess_entry: 265.6 ns, of which its 1 timed sections 109.3; the rest, 156.4 ns, is untimed code and the inner brackets' own cost.
- free_all: 320.3 ns, of which its 3 timed sections 221.6; the rest, 98.7 ns, is untimed code and the inner brackets' own cost.

Read with the harness's limits: each inner bracket adds its own cost (two clock reads, a task check, two atomic adds) to the whole-program figure that contains it, so "the rest" mixes untimed code with the brackets' cost, and the profiled programs are longer than p15d's.

## Under contention: the path program is skipped for one open in ten (MEAS, `open_contend.md`)

12 processes, not pinned, 200,000 open+close each, on 3 vCPUs:

- the session program saw 2,400,018 opens and was skipped for none (`recursion_misses` 0, `kprobe_multi.missed` 0);
- **the path program (fentry) ran for 2,156,161 and was skipped for 243,857 (10.2 %)**; the kernel's `recursion_misses` for it is the same 243,857;
- each skipped open got an OPEN with `PATH_MISSING` from the session's return: 2,400,018 OPEN read, 2,400,018 CLOSE, nothing lost to the ring.

So the loss is counted and located exactly as ADR-0015 rule 6 designed, but one open in ten carries no path in this workload.

## Why (SRC, Linux v7.0)

- `bpf_d_path` is offered only to tracing programs (`kernel/trace/bpf_trace.c` L1742-1743, `tracing_prog_func_proto`) attached to allowlisted functions, `security_file_open` among them (L931-945, L947-958). A kprobe program cannot call it; this is why the path is taken by a fentry.
- A fentry runs through a trampoline that takes `rcu_read_lock_dont_migrate()` and a per-CPU, per-program recursion context (`kernel/bpf/trampoline.c` L1146-1153): it can be preempted while it holds that context, and another task entering the same program on that CPU is then skipped and counted in `recursion_misses` (E-0089).
- A kprobe.multi or kprobe.session program runs with `cant_sleep()` under the graph tracer, guarded by the per-CPU `bpf_prog_active` (`kernel/trace/bpf_trace.c` L2548-2585): it cannot be preempted mid-run, so another task is never skipped because of it.

## What is not shown

- The skip rate of p15d's own (unprofiled, shorter) path program: the profiled program runs longer, so it is preempted inside more often. Not measured.
- The rate on a real workload: this one does nothing but open and close with four times more tasks than CPUs, an extreme.
- The network fexit programs (ADR-0004) run through the same trampolines and are exposed the same way; their skip rate under contention is not measured.
