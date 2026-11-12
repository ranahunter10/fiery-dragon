---
status: accepted
date: 2026-11-12
owner: Ashish Rana
consulted: [daemon/drain.c, daemon/writer.c, daemon/wal.c at bd58c3f; strace -c of an idle p15d in the dev container; bench/idle_cost on the VM (E-0200) and on CI's runner; maintainer 2026-11-12 (STATE decisions 22a, 29: recommended decisions accepted, the 2 ms idle budget)]
supersedes: ADR-0020 rule 2, its last clause only ("the drain polls on a 10 ms timer"), and the latency it states (about 10 ms). The high-water wake-ups of rule 2 and every other rule of ADR-0020 are unchanged.
---

# 0030: The drain's timer adapts: 10 ms after work, doubling to 200 ms when idle

## Context and problem statement

ADR-0020 rule 2 writes records without waking the drain, except when a ring is more than a quarter full, and has the drain poll on a 10 ms timer. The timer bounds how long a record waits, and costs a wake-up 100 times a second whether or not anything arrived. Each wake-up also reads the kernel's skip counter of every program with `BPF_OBJ_GET_INFO_BY_FD` (daemon/drain.c `read_misses`, `read_file_misses`). On the VM, with spine, network and file identity, an idle p15d spends 10.4 ms of CPU per second this way, against a budget of 2 ms (STATE decision 29), about 100 us per wake-up (E-0200).

**Question:** how long should the drain wait when there is nothing to read?

## Decision drivers

1. No record lost or reordered, and no change to what a burst gets (driver 1 of ADR-0020).
2. Idle CPU under 2 ms per second (decision 29).
3. A bounded wait for a record, well inside ADR-0007's 1 s durability window.
4. Kernel skips and losses still located in time (ADR-0020 rule 3's GAP records).

## Considered options

1. Keep 10 ms.
2. A fixed longer timer (50, 100, 200 or 500 ms).
3. **Adaptive:** 10 ms after a poll that took records or left some for want of a batch; after an empty poll, twice the last wait, up to a maximum.
4. Fewer counter reads per wake-up (every Nth poll), with the 10 ms timer kept.

## Decision outcome

**Chosen option: 3, adaptive, with a maximum of 200 ms (`--poll-max-ms`, 10 to 1000)**, because it is the only option that meets driver 2 without touching the loaded path. A fixed timer (2) would make every record wait longer under load. Option 4 leaves the wake-ups themselves, which are most of the cost (a bare 10 ms `epoll_wait` loop: 3.3 of 3.5 ms/s in the dev container, E-0199). On the VM, 200 ms is the smallest maximum whose median (1.14 ms/s) and dearest round (1.37 ms/s) are both under the budget; 100 ms had a median of 1.97 and a dearest round of 3.35 (E-0200). The rule (the smallest maximum under the budget in its median and dearest round) was stated before the run (PR #74).

Rules:
1. The drain waits 10 ms (`P15_POLL_MIN_MS`) after any poll that took records or found a batch missing, and after an empty poll twice its last wait, up to `--poll-max-ms` (default 200). High-water wake-ups are unchanged: a ring more than a quarter full wakes the drain at once.
2. The writer waits until its next deadline (the next STATS, segment rotation or fdatasync, from `p15w_due_ns`), at most 500 ms, instead of 100 ms; a batch or a stop wakes it at once through the queue.
3. The poll gaps stay observable: STATS's poll-gap histogram and its maximum per interval.

### Consequences

- Good: idle CPU 10.4 to 1.14 ms/s on the VM (9.1 times less); nothing changes under load.
- Bad: when the host is idle, a record waits up to 200 ms before the drain reads it (it was 10 ms); the 1 s fdatasync interval still bounds what a crash can lose.
- Bad: a kernel skip during an idle stretch is located within up to 200 ms by its GAP record (it was 10 ms). A ring or build loss needs a full ring, so the drain is then polling at 10 ms.
- Bad: a stop request is seen up to 200 ms later.

### Confirmation

1. `daemon/tests/test_run.c` (`p15_poll_next`, `p15_writer_wait_ms`), `test_wal.c` (`p15w_due_ns`), `test_config.c` (the default and range); their mutants in `mutate_p15d.py` (7) and `mutate_wal.py` (3).
2. `bench/idle_cost` on the VM: the default's arm under 2 ms/s in its median and dearest round.
3. `it_p15d.sh` passes with the default on CI and the VM, every case's books closed (the end-to-end cases include bursts, forced loss and a full queue).

### Falsifier

Reopen if:
- a run shows a record lost, or a ring fuller than at 10 ms, under a load that ramps slower than the high-water wake-up (a ramp the timer would have caught first);
- p15d's idle CPU exceeds 2 ms/s on the VM at the default;
- a consumer of the WAL needs records sooner than 200 ms after the event when the host is idle (none does today: the reader works on closed segments).

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | The drain polls on a 10 ms timer and reads each program's skip counter by syscall after every wake-up | SRC | daemon/p15d.c, daemon/drain.c at bd58c3f |
| 2 | Idle p15d on the VM: 10.4 ms/s at 10 ms, 1.97 at 100, 1.14 at 200, 0.82 at 500; drain thread about 100 to 120 us per poll | MEAS | [idle-cost](../evidence/vm/2026-11-12-idle-cost/README.md), E-0200 |
| 3 | Most of the per-wake-up cost is the wake-up itself (a bare epoll_wait loop) | MEAS (dev container, not the target) | E-0199 |
| 4 | Under load the drain returns to 10 ms after the first poll that takes records | SRC | daemon/drain.c `p15_poll_next`; test_run.c |
| 5 | A burst wakes the drain at a quarter-full ring, whatever the timer | SRC | bpf/progs/spine.bpf.c `wake()`, file.bpf.c `wake()`; ADR-0020 rule 2 |

## Pros and cons of the options

### Keep 10 ms
- Good: the shortest wait for a record.
- Bad: 10.4 ms/s idle, five times the budget.

### A fixed longer timer
- Good: simple.
- Bad: every record waits longer under load too, unless the high-water mark is reached.

### Adaptive (chosen)
- Good: loaded behaviour unchanged; idle cost cut nine-fold at 200 ms.
- Bad: up to 200 ms of wait and GAP span when idle.

### Fewer counter reads per wake-up
- Good: no added wait.
- Bad: the wake-ups remain, and they are most of the cost.
