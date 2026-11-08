# Guest kernel oops on the VM during the p15d mutation sweep (2026-11-08)

**Where:** `p15-dev-2604` (7.0.0-38-generic, VirtualBox on a Windows host with Hyper-V on), during `make mutate-p15d` for PR #57, with mutant 8 planted (the loader no longer sizes the counter maps).

**Files**, as the maintainer pasted or attached them from `/var/crash/202611080558/dmesg.202611080558` (kdump; the 72 MB `vmcore` stays on the VM):
- [`dmesg-tail-120.txt`](dmesg-tail-120.txt): the last 120 lines (attached; its sha256 matches the one printed on the VM, `c58659…464d`).
- [`dmesg-660-684.txt`](dmesg-660-684.txt): lines 660-684, with the oops header (pasted in chat).

## What the log shows (MEAS: these lines)
- At uptime 250.9 s: `BUG: ENTRY_TRAMPOLINE stack guard page was hit`, `Oops: stack guard page`, on CPU 1, `PID: 4211 Comm: sleep`, UID 0, **`Not tainted`**.
- The innermost frame is a page fault at `asm_sysvec_apic_timer_interrupt+0x0`: the first instruction of the timer-interrupt entry, taken while CPU 1 ran user code (user addresses in RDI, RBP, R12). Then a general protection fault in `irqentry_enter+0x15`, where a `%gs`-relative load of the current task returned `RAX = cccccccccccccccc`, repeated until the entry stack's guard page was hit.
- `kernel.panic_on_oops = 1`, so the oops panicked the kernel; kdump saved the dump and the VM rebooted (boots -2, -1, 0 in `journalctl --list-boots`: 05:54-05:56, the kdump kernel 05:58:36-05:58:45, then the current boot).
- No BPF program, BPF trampoline or `bpf()` frame is in the trace.

## Reading (INF, not a result)
- The fault is in the CPU's interrupt entry path with a garbage per-CPU value, on a process (`sleep`) that was not running any p15 code, on an untainted kernel. That is the signature of broken virtual-CPU state from the hypervisor, not of a BPF program or of p15d.
- With mutant 8 planted, every p15d of the end-to-end test fails `p15_counters_verify` after load and before attach (that is how the mutant is killed), so very likely no p15 program was attached at the time. Not proven: the dmesg does not list attached programs.
- One crash cannot separate "the host's virtualisation failed while our test happened to run" from "something the test does (ptrace via strace, fork/exec bursts) makes the host failure likelier". Open until a control run (the unmutated test in a loop for as long) or a recurrence tells them apart.

## Since
- 2026-11-08, about 20 minutes later: the whole sweep rerun on the same VM, mutant 8 included, finished 30/30 with no crash ([`../../build/2026-11-07-counters-mmap/vm-mutate-p15d.txt`](../../build/2026-11-07-counters-mmap/vm-mutate-p15d.txt)). One clean pass: the crash did not recur at the same point. Still OPEN.
