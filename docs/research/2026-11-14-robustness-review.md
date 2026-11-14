# Robustness review after the VM runs of 2026-11-14: what was wrong, what is fixed, what is still open

The maintainer asked for a review that does not trust the session's own work: read the code against the kernel and libbpf, find the assumptions, and say what still threatens robustness. This note covers the session's changes (the disk guard, the flow ring, the canary, the tests) and the VM's behaviour that broke them. Grades as in `CONTRIBUTING.md` §5.

## 1. The finding that explains most of today's failures: the VM's timers

| Measurement | Result | Grade | Evidence |
|---|---|---|---|
| p15d's timed-out `epoll_wait`, how long after its timeout it returned (bpftrace, one 5 s run) | 13 of 36 at 32 ms or more; 4 at 256 ms to 1 s | MEAS | E-0317 |
| p15d's `fork()` for the canary | 64 us to 1 ms | MEAS | E-0317 |
| a plain 10 ms sleep loop beside p15d | one 945 ms oversleep | MEAS | E-0317 |
| the kernel's own stall reports in that window | none (it logs about 1 s or more: three at boot, one 76 s stall at 16:02:59) | MEAS | E-0317 |

So on this VM (VirtualBox on a Windows host with Hyper-V, E-0088) a thread can wake up to about a second after its timer, often, and below what the kernel reports (INF that the host is the cause; the measurements are MEAS). Every check that assumed "this finishes within N seconds" was exposed to it. The fixes below make the checks wait for events instead of time, and make the canary not blame the pipeline for time it was not run.

## 2. Defects found, and their fixes

| # | Defect | How it showed | Root cause | Fix | Grade |
|---|---|---|---|---|---|
| D1 | Case 30 could pass or fail on timing | first sweep's baseline: no overflow (ring peaked at 52,832 of 65,536 bytes) | the overflow was left to a race that p15d, at SCHED_FIFO, often wins | the drain pauses 20 ms a poll and the writer takes 100 ms a batch, so the overflow and the reserve are forced | MEAS (E-0316) |
| D2 | The canary saw two of its seven signals one poll late | case 23 no verdict before the run ended | `p15_drain_poll` ticked the canary before `after_poll` read the file counters | tick after `after_poll` | SRC; MEAS (case 23 3 of 3 after) |
| D3 | Case 21's canaries late by 26-232 ms with every signal seen | 6 of 30 manual runs | the VM's late wake-ups (§1) counted against the pipeline | `p15_canary_oversleep`: a wait's overshoot beyond 20 ms moves the LATE deadline, counted in `canary_stalled` | MEAS (E-0317) |
| D4 | My fix for D3 hid misses | case 22 and 25 on the VM: no verdict | the overshoot moved the MISS deadline too; a VM that always overslept pushed it past a 4 s run | MISS uses its own, unmoved deadline; unit test with chronic oversleep; planted bug 128 | SRC; unit test |
| D5 | Six end-to-end cases stopped p15d at a fixed time while a workload ran | case 28 "0 of the last 100", case 30's victim incomplete | a workload on the VM can outlive `--duration` (§1) | cases 13, 14, 27, 28, 29, 30 run with a 120 s cap and are stopped with SIGINT after the workload (`stopwait`); case 28 waits for each level in p15d's log instead of sleeping | SRC |
| D6 | Case 23's margin | the excuse (D3) could, rarely, cancel its 0.5 s lateness | a 1.5 s pause was less than the 1 s overshoot plus jitter | a 3 s pause, 12 s run | SRC |
| D7 | Planted-bug kills were not evidence by themselves | a kill by a flaky check looked like a kill by the bug | the sweep printed only "killed" | each kill prints its first failed checks and keeps all of them (`build/mutate-kills.txt`); a failed baseline keeps its whole output | SRC |
| D8 | Harness anchors moved silently | mutants 9, 65, 119 and WAL mutants 4/5/8 did not match after this session's edits | edits to anchored lines | every harness's anchors checked before delivery (a one-line script; recorded in the session's bootstrap) | SRC |

## 3. The session's new code, re-read against its dependencies

| Code | What it relies on | Checked against | Result |
|---|---|---|---|
| `wal.c` ENOSPC branch | ext4 refuses a delayed-allocation write that cannot be reserved at `write()` time, not at writeback | Linux v7.0 `fs/ext4/inode.c` `ext4_da_reserve_space` (L1636-1644: `dquot_reserve_block`, then `-ENOSPC` when `ext4_claim_free_clusters` fails) | holds for ext4 (and tmpfs, which fails the write). fsync(2) (man-pages 6.19, pasted by the maintainer) lists ENOSPC and EDQUOT at sync time for "NFS or another filesystem which does not allocate space at the time of a write(2)", and says that since Linux 4.13 a write-back error is reported to every descriptor that might have written the data. On such a filesystem the writer still fails at `p15w_tick` (exit 4): correct, because after the error is reported once a second sync can succeed without the data, so the WAL cannot know what reached the disk. fsync(2) also lists EINTR: the WAL now retries EINTR only, and the writer thread blocks SIGTERM and SIGINT so a stop signal never interrupts its calls (the handler has no SA_RESTART) |
| `space.c` free space | `fstatvfs` `f_bavail * f_frsize` (blocks for an unprivileged user; root's reserved blocks excluded) | POSIX `statvfs` | conservative for a root p15d: it starts shedding before the reserved blocks are touched |
| `drain.c` `take()` with a reserve | `ring__consume_n` stops at a record not yet committed (BUSY bit) or after n records | `third_party/libbpf/src/ringbuf.c` `ringbuf_process_ring` (L234-280) | `got < room` means "empty or the next record is still being written", as `take()` assumes; discarded records do not count toward n |
| flow ring at one page without `--flow` | a ring map's size is a power of 2 and a multiple of the page size | libbpf `bpf_map__set_max_entries` on RINGBUF | 4096 on x86-64 |
| the canary's MISS | everything the child writes is committed before it can be reaped | Linux v7.0 `kernel/exit.c` `do_exit`: `trace_sched_process_exit` (the spine's EXIT), then `exit_files` and `exit_task_work` (the open file's last `fput`, so its free), then `exit_notify`, after which the parent can reap | a MISS after reap and an empty poll is real |
| writer shedding at SHED_ALL | — | — | a canary's records are seen by the drain even when the writer then sheds them: the canary checks the hooks and the drain, the books and WAL_SPACE account for the shed. Stated, not changed |

## 4. Still open (ranked by what they risk)

1. **Under heavy load the canary judges late or not at all.** Its MISS needs a poll that took nothing; a host that never goes idle gives none, and the 11 s guard then decides. Better: decide a miss when every ring has been drained past the point it held at the reap (track bytes consumed per ring). Not built.
2. **A flooder still costs other processes their FLOWs** (decision 135). Isolation of identity from FLOW is built and proven; fairness between processes is not.
3. **Errors reported at `fdatasync` end the run** (§3). Correct, but a supervisor (decision 133) is what keeps capture going.
4. **Cases 1, 5, 6, 8, 9, 16-19 still use fixed durations** with short workloads. Cases 1 and 9 need elapsed time (STATS cadence, time rotation); the others have not flaked. Convert them if they do.
5. **Every latency figure from this VM is bounded by its timer behaviour (§1).** Timings for the report should come from medians of many rounds (as `open_cost` does), never from a single run's maximum.
6. The design review's other findings (F-03 to F-15 not yet closed), the threat model (ADR-0013), the object map (127), folding, the graph's build time: unchanged by this session.

## 5. How to judge the next VM run

One session: setup, build, three `it` runs, `flood`, `disk`, the canary run, the demo, then the planted bugs 111-129 plus 93-94 with their kill reasons. Accept ADR-0051 (decision 134) when all three `it` runs pass and every end-to-end kill names a check of its own case.
