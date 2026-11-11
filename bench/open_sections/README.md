# Where the file programs' time goes, section by section (after E-0184)

**Question 1 (STATE decision waiting 1).** The path program (`file_open_path`) costs 561 ns per open on the VM, and the blocks it is known to use explain about 100 to 150 ns (E-0184). The rest is thought to be `bpf_d_path`, which `bench/prim_cost` cannot time alone. Which section is it?

**Question 2 (decision waiting 2).** The session program (289 ns per open+close) exists to write an OPEN with `PATH_MISSING` when the kernel skips the path program for another task (ADR-0015 rule 6, E-0089). That happened 0 times in 4.4 M opens on one thread (E-0175). How often does it happen when more tasks than CPUs open files?

**How.** `bpf/progs/file.bpf.c` carries brackets (`bpf/include/p15_prof.h`) around each section: claiming a scratch slot, the header, the facts, the object map, the open-file map, `bpf_d_path`, the ring copy; the session's entry, its open-file insert and its return; the close's lookup, ring record and delete. They compile to nothing unless `-DP15_PROFILE`: `build/file.bpf.o` is unchanged, instruction for instruction (checked with `llvm-objdump -d` before and after this change). `build/file_prof.bpf.o` is the profiled build; only this harness loads it, attached as p15d attaches the programs, with this harness reading the ring.

```
make build/open_sections build/open_cost          # as the user
build/open_cost /var/tmp/p15-open-cost 1 1 | grep nullsys     # the host check: under 131,250,000 ns
sudo build/open_sections single 20 200000 /var/tmp/p15-open-cost > build/open_sections.txt
python3 bench/open_sections/summarize.py build/open_sections.txt --ref-nullsys-ns 87.5
sudo build/open_sections contend 12 200000 /var/tmp/p15-open-cost > build/open_contend.txt
python3 bench/open_sections/summarize.py build/open_contend.txt
```

**single** times N open+close of one file per round, pinned, and reports each section's ns per sample (this process's runs only) with the cheapest and dearest round, net of an empty bracket. Every round must have exactly N samples of each whole program, or no time is reported. The host-speed rule is `bench/prim_cost`'s (SLOW or UNSTEADY: not quotable).

**contend** runs WORKERS processes, not pinned, each N open+close, and reports how many opens got an OPEN with `PATH_MISSING` (the path program did not run), against every open the programs saw, with the kernel's `recursion_misses` and `kprobe_multi.missed`. Zero skips is reported with its 95 % bound (3 / opens).

**Limits.**
- Each bracket costs two clock reads (about 13 ns each on the VM, E-0184) and two atomic adds; the whole-program figures contain their inner brackets, so they are larger than the program without them. The sections are compared with each other and with the empty bracket, not with `prog_stats.py`.
- A section during which the task was preempted keeps the time the CPU spent elsewhere; single mode runs pinned on an idle VM and reports medians over rounds.
- One file, one path of three components (`/var/tmp/p15-open-cost/same`): `bpf_d_path`'s cost grows with the path's depth and mounts; this measures one case.
- contend counts every task's opens while the workers run, not only the workers'.
- The dev container cannot load the file programs (EPERM): CI's runner proves the harness loads and its books close; only the VM's numbers count.
