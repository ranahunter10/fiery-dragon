# Idle cost on the VM, five poll maxima (2026-11-12)

Evidence for E-0200 and ADR-0030. VM `p15-dev-2604`, 7.0.0-38-generic, PR #74 at `bd58c3f`, p15d with spine, network and file identity. Host check: 87.6 ns per null syscall (reference 87.5). `sudo ~/p15venv/bin/python bench/idle_cost/run.py --p15d build/p15d --work /var/tmp/p15-idle --rounds 5` with arms `--poll-max-ms` 10, 50, 100, 200, 500; every one of the 25 runs ended clean (summarize.py reports no failed check). `idle_cost.md` is the summary as the maintainer pasted it; the raw output stayed on the VM (`build/idle_cost.txt`, sha256 `21038e72...f437`).

## What it shows (MEAS)

- Today's setting (10 ms) costs **10.4 ms of CPU per second** (9.6 to 10.9 over rounds), 95.3 polls per second, at a background load of 2.1 records per second. E-0176 measured 14.65 ms/s for an earlier p15d (1 s windows, a writer that woke every 100 ms).
- The drain's cost follows the poll rate: 9.82 ms/s at 95.3 polls/s, 0.61 at 5.2, 0.30 at 2.5, about 100 to 120 us per poll (the epoll wake-up, the ring reads and one `BPF_OBJ_GET_INFO_BY_FD` per program). The writer's 0.53 ms/s is the same in every arm (its waits are now deadline-driven).
- **200 ms is the smallest maximum under the 2 ms budget in its median (1.14 ms/s) and its dearest round (1.37):** 9.1 times less than 10 ms. 100 ms has a median under the budget but a dearest round of 3.35. 500 ms saves 0.32 ms/s more.

## Not shown

- The load in every arm is the VM's own background (2 to 3 records per second). Under load the drain polls every 10 ms in every arm (it returns to the minimum after any poll that took records), so the setting changes nothing there; bench/open_cost measures that path.
- The BPF programs' time on other tasks' threads is not in these numbers (bench/open_cost).
