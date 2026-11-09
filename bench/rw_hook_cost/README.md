# What each read-path hook type costs (ADR-0015 decision 1a, N5)

**Question.** Slice B hooks the read and write paths with kprobe.multi, which runs with preemption off and so cannot be skipped for another task (STATE decision 17). ADR-0015 decision 1a asks whether to use kprobe.session (one link, entry and return skipped together, a per-call cookie) instead of two links (kprobe.multi + kretprobe.multi, with a per-thread stash from entry to return). The only cost figures we have are from a 2024 bare-metal kernel benchmark (DOC). This harness measures our own, on the VM, against fentry and fexit, which can be skipped (E-0089) but are the cheap reference. It also checks design check O2: whether a kprobe.session and a fentry can share one function, as ADR-0015 rule 6 needs on `security_file_open`.

**Design.** `rw_hook_cost.bpf.c` puts the **same trivial body** behind each hook type on `vfs_read`, so a difference in cost is the hook path's alone. The body counts one hit per call made by the harness. The pair and session arms count at the return, where slice B would write its record. They also count any return whose entry left nothing (no stash, an empty cookie).

| Arm | Hook | Link(s) | Skippable for another task |
|---|---|---|---|
| none, none2 | nothing (untraced, and its A/A control) | — | — |
| fentry | trampoline at entry | 1 | yes (E-0089) |
| fexit | trampoline at return | 1 | yes |
| kpm | kprobe.multi, entry only | 1 | no |
| pair | kprobe.multi entry + kretprobe.multi return, per-thread hash stash | 2 | no |
| session | kprobe.session, per-call cookie | 1 | no |

- **Workload:** per round, each arm does READS × `read(/dev/zero, 1 byte)` on the harness's own thread, in an order rotated each round, after one untimed warm-up of every arm. The process is pinned to one CPU.
- **Primary metric (declared before the run):** the thread's CPU time per read. Secondary: wall time per read.
- **Books per arm:** a traced arm's hits equal READS; the untraced arms see none; no return without its entry.
- **Skip counters:** after each arm, its programs' `recursion_misses` and, for kprobe.multi links, the link's `kprobe_multi.missed`, as deltas.
- **Baseline:** each round also times a null syscall (`getppid`, 10^6 calls), ADR-0018 rule 3.2.
- **O2:** before the rounds, a kprobe.session and a fentry are attached together on `security_file_open`; OPENS × `open("/dev/null")` must give OPENS hits to each (the `coexist` line).

**Report.** [`summarize.py`](summarize.py) uses [`bench/quant/paired.py`](../quant/paired.py). Timings are reported only if every book closes. It gives:
- each arm's median per read, with its interval;
- every traced arm against none: the paired Hodges–Lehmann effect, its exact interval and p, against the A/A floor (none2 against none);
- the three questions: **session against pair**, **session against fexit**, **session against kpm**, each with the floor carried onto the second arm;
- the added cost per read in ns and in null syscalls;
- the skip counters over all rounds, and the coexistence result.

An overhead is quoted only if ADR-0018 rule 2.4 allows it.

```
sudo mount -t tracefs nodev /sys/kernel/tracing   # if not mounted (containers)
sudo make bench-rw-hook-cost ROUNDS=20            # raw lines in build/rw_hook_cost.txt
```

**Limits.**
- The trivial body isolates the hook path. Slice B's own bodies (map lookups, marks, the ring) add their cost on top; that is measured with slice B itself.
- A 1-byte read of `/dev/zero` is about the cheapest `vfs_read` there is, so the relative overheads here are upper bounds for real reads; the absolute ns per call are the transferable number.
- The dev container (6.18) can load neither trampolines nor kprobe.multi links, and its session kfuncs take no `ctx`: there the harness runs only its untraced arms (`NOTRAMP=1 NOSESSION=1`) and fails the traced ones loudly. The CI runner's 7.0 kernel runs every arm as a smoke test, not a measurement. Only the VM gives the numbers.
