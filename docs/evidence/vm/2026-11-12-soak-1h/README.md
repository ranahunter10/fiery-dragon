# The one-hour soak on the VM (2026-11-12)

Evidence for E-0202. VM `p15-dev-2604`, 7.0.0-38-generic, PR #75 at `0f8a67d`, p15d with its defaults (spine, network and file identity; the 200 ms poll maximum of ADR-0030). `sudo ~/p15venv/bin/python bench/soak/soak.py --p15d build/p15d --work /var/tmp/p15-soak --duration 3600`. `soak.md` is the report as the VM printed it; `vm-session.txt` is the whole terminal. Raw output on the VM: `build/soak.txt` (sha256 `d00529b4...5c25e`); the WAL and the graph file stay in `/var/tmp/p15-soak`. Before it, `it_p15d.sh` passed on the VM with the new default (`~/it-v4.txt`, `a384e966...da278`): ADR-0030 confirmation 3.

## Capture under real programs for an hour (MEAS)

- **Every operation the workload logged is in the WAL: 38,363 of 38,363 (100 % for each of the 7 step kinds)** over 3,158 steps. That covers 12,656 compile items (objects and programs written, sources read, every `cc` and every built program executed), 11,726 archive items, 5,863 git, 5,412 Python files, 1,353 http (accepts and connects on each step's own port), 902 shell (50 executions of a copied binary per step) and 451 memfd executions.
- The end is clean: exit 0, RUNNING, the invariant closed, 1,919,817 records read without an error or a torn stop. Nothing was lost: kernel skips of the spine and network programs 0, queue full 0, GAP records 0, OPEN and CLOSE lost 0. The path fentry was skipped 3 times, and all 3 opens were walked (ADR-0029).
- p15d's own CPU under this load (about 530 records per second): median 4.32 ms/s, max 5.36 (drain thread 2.50, writer 1.81). Resident memory 23.8 MiB at the first sample and 27.0 at the last, max 27.0. The longest poll gap was 0.219 s. WAL: 184.0 MiB, 51.4 KiB/s.

## The graph of the hour (MEAS)

- Built in 782 s (147.5 MiB): 55,247 process nodes, 90,981 file nodes, 7,686 socket nodes; 805,939 OPEN edges, 55,101 EXECUTE, 55,108 CLONE, 3,627 CONNECT, 3,608 ACCEPT. Its must-be-zero books are 0.
- **The dropper chain of every compiled program: 452 of 452** (one file node opened for writing by the linker and executed into the next process). **Every memfd execution: 451 of 451.**
- Connections paired by ISN: 3,608, which is exactly the 451 http steps times 8. The report said FAIL ("3,608 of 3,552") because the check was wrong, not the graph: it kept one expectation per port, and 7 ports were reused over the hour. The check now counts per step, on the step's port and inside its window (E-0202). A recheck on the same files is in the next VM run.

## What the hour raises

- 782 s to build the graph of one hour is too slow to keep up for long. `python -m p15.graph --profile` now times each phase and statement; its first run is on this WAL.
- Memory grew 3.2 MiB over the hour (13 %). That is under the report's rule (half again and 10 MiB) but needs the samples' trend and a longer run to call a leak or not.
