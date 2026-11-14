# The disk guard (F-02) and the flow ring (F-01) on the VM, 2026-11-14

The maintainer ran Dragon's kit (fd-vm-test2, then fd-vm-test3 for its fixed flood check) on VM `p15-dev`, kernel 7.0.0-38-generic, 3 vCPU. Tree: local `vm/integration-2`, commit `58f7c0e`, tree `a09ded51…` (`manifest.txt`): `dragon/demo-v2` with `dragon/flow-ring` (which holds `dragon/disk-space`) merged in. Not for merging. Journal: E-0315. The demo's HTML reports are left out (the text forms are in `demo/`).

| File | Stage | Result |
|---|---|---|
| `build.txt`, `test-c.txt`, `test-python.txt` | build | pass; 30 Python test files |
| `it_p15d.txt` | `it_p15d.sh` with `P15_IT_NET=1` | **PASS, 0 failed, none skipped**. Case 28: levels 2,3,1, 1,220 spine records shed (306 FORK, 306 EXIT), tree check `repaired`. Case 29: 355 batches refused and taken back, exit 3. Case 30: 13,424 FLOWs lost, identity and NET lost 0, the victim's 300 OPENs, 300 CLOSEs and 30 connects all written, ring full (65,520 bytes), 1,280 deferrals |
| `flood.txt`, `flood_victim.txt`, `flood_p15d.err` | the design review's V-1, default sizes | 14,583,975 FLOWs in 20 s, none lost; open_lost, close_lost, net_reserve_failed 0; the victim's 2,000 OPENs, 2,000 CLOSEs, 100 connects all written; 7,263 deferrals while the queue was full (14,500); exit 0 |
| `disk.txt`, `disk_inspect.txt`, `disk_p15d.err` | the design review's V-2: 8 MiB tmpfs, `--flow`, a flood | exit 3 (was 4): SHED_BULK from the start (low = the whole 8 MiB), 25,824,525 bulk records shed and counted, spine 0, nospace 0; the WAL valid; END names the low disk |
| `p15d_path.txt`, `p15d_path_64k.txt` | `bench/p15d_path` | per record: check 6.8-6.9 ns, copy 5.1-6.1, CRC 8.1-8.2, append 28.1-30.2, two-thread pipeline 74.4 (64 KiB) to 86.5 ns (1 MiB) |
| `perf_none.txt`, `perf_p15d.txt` | H1 | **not measurable here**: every hardware counter `<not supported>` (VirtualBox gives the guest no PMU) |
| `canary_run.txt`, `canary_inspect.txt` | 10 s, `--flow --canary-s 1` | 8 canaries, missed 0, late 0, want 0x7f, 23 links, 230 checks |
| `demo*.txt`, `demo/` | the demo with `--flow` | the four rules fire; the attack path as before |
| `mutants.txt` | planted bugs 111-128 | **not run**: the sweep's baseline `it_p15d` failed 6 checks: case 30's overflow (fill max 52,832 of 65,536: p15d drained in time) and canary cases 21 and 23 (cause not visible in the sweep's output) |

The flooder's rate followed how busy p15d's writer was: about 365,000 read+write pairs a second in `flood` (writing about 70 MB/s), about 645,000 in `disk` (shedding, nothing written). p15d runs at SCHED_FIFO 1; that its threads take the CPU first on 3 vCPUs is the likeliest reason the default ring never overflowed (INF, not measured).
