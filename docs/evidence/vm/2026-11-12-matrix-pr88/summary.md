# Capture measurement matrix, 20261112T201612Z

    stamp 20261112T201612Z
    commit 5a5fe4bc2d38342c9dce1bed543f8694e52ff697 clean
    kernel 7.0.0-38-generic cpus 3
    python /home/ashu/p15venv/bin/python
    p15d_options (defaults)
    quick 0 soak_seconds 600
    70cb1dc238fb8f7d00db72185fdbaa578390aada19f7122dc77ac78df80982de  build/p15d
    1761f576a7020878c5f84eb4403880609d3d5926edee39c70a6b53d70ce3e2bf  build/p15w-inspect
    48e7727bbf4cf27e0b20a7e4825d99c08b696c765facd25d190651a60e044f25  build/open_cost
    b02fa35cead785d9c98b8c67b9dbb96545a0d35d1cb9a055aa59fc150b5c7c6a  build/prim_cost
    afa8c259570b390133a745798b7d8561405484fd52f0b2626889c2d5dcdce7dd  build/crc32c_bench

## Steps

- it_p15d rc=0 seconds=117.4
- crc32c rc=0 seconds=3.0
- prog_stats rc=0 seconds=9.2
- open_cost rc=0 seconds=285.6
- open_cost_report rc=0 seconds=0.0
- profile_run rc=0 seconds=53.9
- profile rc=0 seconds=0.4
- profile_callers rc=0 seconds=0.4
- idle rc=0 seconds=142.6
- idle_report rc=0 seconds=0.0
- soak rc=0 seconds=692.8
- soak_report rc=0 seconds=0.0

## Figures (each from its step's own report)

- it_p15d:   queue_full 558, spine reserve failures 0; EXEC of /bin/true: 2000; END: exit 0, state 0, invariant 1, signal 15, reason 
- it_p15d:   with file identity and NET: queue_full 193, spine reserve failures 0, bulk records lost to the ring 0; END: exit 0, state 0, invariant 1, signal 15, reason 
- it_p15d: it_p15d: PASS (0 failed checks)
- crc32c: table   2.0583 ns per byte (median; 2.0044 to 2.1238)
- crc32c: sse4.2  0.0939 ns per byte (median; 0.0922 to 0.0968)
- crc32c: speed-up 21.9x; same crc: yes
- crc32c: table   2.6267 ns per byte (median; 2.4715 to 2.8478)
- crc32c: sse4.2  0.1271 ns per byte (median; 0.1073 to 0.1423)
- crc32c: speed-up 20.7x; same crc: yes
- prog_stats: | file_free | kprobe | 7 | 1,540,933 | 540.3 | 481.1 to 573.5 | 1.001 | 540.6 |
- prog_stats: | file_open_path | tracing | 7 | 1,540,332 | 303.0 | 298.5 to 332.1 | 1.000 | 303.0 |
- prog_stats: | file_open_session | kprobe | 7 | 3,080,664 | 96.1 | 93.1 to 107.4 | 2.000 | 192.3 |
- prog_stats: | file_fd_iter | tracing | 3 | 2,186 | 678.3 | 671.8 to 750.6 | 0.003 | 2.2 |
- prog_stats: | file_inode_free | kprobe | 7 | 56 | 657.2 | 459.8 to 781.2 | 0.000 | 0.0 |
- open_cost: added per open+close 1,153.3 ns (95 % interval 1,105.4 ns to 1,201.6 ns), 12.30 null syscalls; ratio of medians 2.1669; effect p = 1.91e-06
- open_cost: added per open+close 1,199.8 ns (95 % interval 1,137.7 ns to 1,256.0 ns), 12.79 null syscalls; ratio of medians 2.2148; effect p = 1.91e-06
- open_cost: added per open+close 1,377.0 ns (95 % interval 1,262.2 ns to 1,482.4 ns), 14.68 null syscalls; ratio of medians 2.0351; effect p = 1.91e-06
- open_cost: added per open+close 1,433.2 ns (95 % interval 1,326.8 ns to 1,518.2 ns), 15.28 null syscalls; ratio of medians 2.0747; effect p = 1.91e-06
- open_cost: opens expected 4,400,000; OPEN records with their path 4,400,000; PATH_MISSING records of the workload 0; CLOSE records 4,400,000; lost to the ring 0
- open_cost: p15d idle: 1.74 ms of CPU per second (mean; median 1.71)
- open_cost: p15d per open+close of the workload: 230.3 ns of CPU in the window (mean), 224.0 ns after the idle rate is taken off (median 224.4 ns)
- open_cost: p15d's thread switches: 0.4 per 1,000 open+close in the window (median), 14.0 per second idle (median)
- profile: 22.83%  [kernel.kallsyms]  [k] finish_task_switch.isra.0
- profile: 8.70%  [kernel.kallsyms]  [k] _raw_spin_unlock_irqrestore
- profile: 7.61%  p15d               [.] after_poll
- profile: 7.61%  p15d               [.] tiles
- profile: 4.35%  [kernel.kallsyms]  [k] _raw_spin_unlock_irq
- profile: 4.35%  [kernel.kallsyms]  [k] fdget
- profile: 4.35%  p15d               [.] on_bulk
- profile: 4.35%  p15d               [.] p15_rec_check
- idle: | default | 1.407 | 1.107 .. 1.474 | 5.5 | 2.5 | 1.00x | yes |
- idle: Per thread, median ms/s over rounds:
- idle: | default | 0.776 | 0.568 |
- soak: | over the run | median | max | first | last |
- soak: | p15d CPU, ms/s | 4.71 | 5.16 | 4.71 | 2.01 |
- soak: | drain thread, ms/s | 2.84 | 3.07 | | |
- soak: | writer thread, ms/s | 1.86 | 2.09 | | |
- soak: | resident memory, MiB | 23.3 | 23.4 | 22.8 | 23.4 |
- soak: | longest poll gap, s | 0.201 | 0.204 | | |
- soak: WAL: 31.6 MiB, 48.3 KiB/s. Spine records drained: 39,332; bulk-ring records written (NET and file identity): 272,571; kernel skips: spine 0, NET 0; queue full 0; GAP records 0.
- soak: | archive | 76 | 1,976 | 1,976 | 100.00% |
- soak: | compile | 76 | 2,128 | 2,128 | 100.00% |
- soak: | git | 76 | 988 | 988 | 100.00% |
- soak: | http | 76 | 228 | 228 | 100.00% |
- soak: | memfd | 75 | 75 | 75 | 100.00% |
- soak: | pyfiles | 76 | 912 | 912 | 100.00% |
- soak: | shell | 75 | 150 | 150 | 100.00% |
- soak: | dropper_chain | 76 | 76 |
- soak: | sock_pairs | 608 | 608 |
- soak: | memfd_exec | 75 | 75 |
- soak: - PASS
