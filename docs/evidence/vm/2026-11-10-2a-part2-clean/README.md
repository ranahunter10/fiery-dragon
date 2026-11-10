# Step 2a part 2 on the target VM, clean tree (2026-11-10)

Evidence for E-0156 and E-0157. Supersedes [`2026-11-10-2a-part2-it`](../2026-11-10-2a-part2-it/README.md), whose build had a leftover mutant in `daemon/queue.c` (E-0155). Every file's sha256 matches the line the VM printed.

| File | What | Where it ran |
|---|---|---|
| `it-p15d-2a.txt` | `make it-p15d` at `c85b652` (the binary reports the clean commit): every case passed, case 8 with the facts-epoch checks | VM p15-dev-2604, 7.0.0-38-generic, 2026-11-10 12:02 UTC |
| `p15d-2a-stats.txt` | a 30 s run of p15d on the idle VM: its FILE_STATS records, the record counts and END | same, about 12:05 UTC |
| `mutate-p15d-2a.txt` | `make mutate-p15d` at `c85b652`: baseline passed, 40 of 42 mutants killed, 2 did not build | same, ended before 18:45 UTC |
| `mutate-p15d-2a-rest.txt` | `mutate_p15d.py 40 41` at `294a49e`: the unmutated end-to-end test ran out of its 300 s in case 3, so no mutant ran | same, 18:48 UTC |

What they show (MEAS, target kernel):
- **Idle VM, 30 s:** 101 OPEN and 91 CLOSE records (FILE_STATS since the drain began: 97 opens, 88 closes; the other 4 and 3 were written between the self-tests and the drain's first counter read, and the books, kept on absolute counters, include them). At the end 11 open-file entries and 48 object entries were live; the maps' sizes are 65,536 and 131,072. No OPEN, CLOSE or session record lost, `fentry_missed` 0, `kprobe_missed` 0, no map full.
- **200 runs of `/bin/true` in 8 s (case 1):** 1,047 OPEN and 1,054 CLOSE against 810 spine records; about 5.2 opens per exec.
- **Mutation sweep:** the mutant that removes the facts-epoch step is killed (E-0151's bug is real on the target and the test catches it); all eight mutants of the file books are killed.
- **The hang:** in `mutate-p15d-2a-rest.txt` the unmutated end-to-end test ran past 300 s and was stopped in case 3 (forced spine overflow), which takes about 9 s in the dev container. Whether the guest stalled or p15d hung is not known yet (E-0157).
- **A flaw in the sweep this exposes:** a mutant's test was stopped after 180 s and a stop counted as killed. If the VM stalls during a mutant, that mutant is "killed" by the clock. The 40 kills above cannot be told apart from timeouts after the fact; the sweep is re-run with timeouts reported separately.

`SHA256SUMS` covers every file here (`sha256sum -c SHA256SUMS`).

## The hang explained (added 2026-11-10, E-0158)

| File | What |
|---|---|
| `kern-rcu-stall-head.txt` | The first 30 kernel log lines from 18:40 to 18:54 UTC (pasted in chat by the maintainer from `journalctl -k`) |
| `kern-1840-tail40.txt` | The last 40 lines of the same window (attached) |

At 18:53:07 the kernel reported `rcu_preempt self-detected stall on CPU` 1, with `t=279737 jiffies` and the grace-period kthread `starved for 279737 jiffies` while runnable (`state:R`). CPU 1 had `1 ticks this GP` and was idle (`swapper/1`, in `pv_native_safe_halt`); CPU 0 was in `systemd-journal`. Neither trace holds a p15d, BPF, kprobe or fprobe frame.

Reading (INF, strong): a CPU that spins in the kernel collects timer ticks; one tick in about 280 s (279,737 jiffies at `CONFIG_HZ=1000`, read from `/boot/config-7.0.0-38-generic` on the VM and pasted in chat) means the guest's timer did not run, so the whole guest stood still for about 280 s and resumed at 18:53:07. The end-to-end test began at 18:48:17 and was stopped at about 18:53:17: the freeze covers it. This is the host stall recorded in E-0088 again, not a p15d hang. The five runs that followed passed, in 55-60 s each, with a watcher that found no p15d alive past 60 s.

## The full sweep at `356422e` (added 2026-11-10, E-0159)

| File | What |
|---|---|
| `mutate-p15d-2a-356422e.txt` | `make mutate-p15d` at `356422e`, as the maintainer's `tail -f` showed it (attached; the VM's file has sha256 `8335204d...92f5`, this copy is the terminal view and differs by the command line and `^C`) |

Baseline: unit tests in 0 s, end-to-end test in 59 s (a mutant got 120 s and 234 s). 41 of 42 killed, each by a failed check, in 1-158 s. Mutant 11 (`p15q_publish` no longer advances `head`) is TIMEOUT: the consumer of the two-thread queue test waits for an item that never comes, so the unit test hangs instead of failing. Not a guest freeze (it hung for the full 120 s while every other mutant ran normally) and not a survivor: the mutant breaks the queue and the test never passes. `test_queue` now has a 30 s deadline that fails the test; with the mutant planted it fails in 31 s in the dev container, and on the VM `mutate_p15d.py 11` at `27c4f66` gave `killed 11 ... (32 s)`, `1/1 killed` (pasted in chat).
