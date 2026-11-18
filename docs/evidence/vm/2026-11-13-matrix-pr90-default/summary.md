# Capture measurement matrix, 20261113T023330Z

    stamp 20261113T023330Z
    commit 99dc5bccd2651d99814cbf99e83117e92ac74179 clean
    kernel 7.0.0-38-generic cpus 3
    python /home/ashu/p15venv/bin/python
    p15d_options (defaults)
    quick 0 soak_seconds 600
    bdf131def4fb08f2de4c80d2a4e34b42c104e09d5b6b3f64bf272d5d78a43026  build/p15d
    a6c2552606b1fc75efbdbafb68e26f0eed028cd2e1220dda6fae047f6591f684  build/p15w-inspect
    48e7727bbf4cf27e0b20a7e4825d99c08b696c765facd25d190651a60e044f25  build/open_cost
    b02fa35cead785d9c98b8c67b9dbb96545a0d35d1cb9a055aa59fc150b5c7c6a  build/prim_cost
    afa8c259570b390133a745798b7d8561405484fd52f0b2626889c2d5dcdce7dd  build/crc32c_bench

## Steps

- it_p15d rc=0 seconds=132.6
- crc32c rc=0 seconds=2.5
- prog_stats rc=0 seconds=7.2
- open_cost rc=0 seconds=273.6
- open_cost_report rc=0 seconds=0.0
- profile_run rc=0 seconds=53.1
- profile rc=0 seconds=0.4
- profile_callers rc=0 seconds=0.4
- idle rc=0 seconds=148.0
- idle_report rc=0 seconds=0.0
- soak rc=0 seconds=654.6
- soak_report rc=0 seconds=0.0

## Figures (each from its step's own report)

- it_p15d:   queue_full 504, spine reserve failures 0; EXEC of /bin/true: 2000; END: exit 0, state 0, invariant 1, signal 15, reason 
- it_p15d:   with file identity and NET: queue_full 152, spine reserve failures 0, bulk records lost to the ring 0; END: exit 0, state 0, invariant 1, signal 15, reason 
- it_p15d: it_p15d: PASS (0 failed checks)
- crc32c: table   1.9584 ns per byte (median; 1.9490 to 2.0498)
- crc32c: sse4.2  0.0923 ns per byte (median; 0.0906 to 0.0938)
- crc32c: speed-up 21.2x; same crc: yes
- crc32c: table   2.0110 ns per byte (median; 1.9801 to 2.0561)
- crc32c: sse4.2  0.1000 ns per byte (median; 0.0986 to 0.1158)
- crc32c: speed-up 20.1x; same crc: yes
- prog_stats: | file_open_path | tracing | 7 | 1,540,374 | 262.3 | 253.0 to 292.2 | 1.000 | 262.3 |
- prog_stats: | file_free | kprobe | 7 | 1,541,101 | 192.1 | 175.2 to 196.7 | 1.001 | 192.2 |
- prog_stats: | file_open_session | kprobe | 7 | 3,080,748 | 83.2 | 80.6 to 86.2 | 2.000 | 166.4 |
- prog_stats: | file_fd_iter | tracing | 3 | 2,151 | 443.7 | 369.4 to 602.2 | 0.003 | 1.4 |
- prog_stats: | file_inode_free | kprobe | 7 | 56 | 474.5 | 416.6 to 2467.5 | 0.000 | 0.0 |
- open_cost: added per open+close 1,029.7 ns (95 % interval 988.1 ns to 1,061.5 ns), 11.67 null syscalls; ratio of medians 2.1251; effect p = 1.91e-06
- open_cost: added per open+close 1,103.4 ns (95 % interval 1,060.0 ns to 1,147.2 ns), 12.50 null syscalls; ratio of medians 2.1845; effect p = 1.91e-06
- open_cost: added per open+close 1,300.1 ns (95 % interval 1,175.4 ns to 1,394.0 ns), 14.74 null syscalls; ratio of medians 2.0443; effect p = 1.91e-06
- open_cost: added per open+close 1,376.5 ns (95 % interval 1,260.6 ns to 1,466.4 ns), 15.60 null syscalls; ratio of medians 2.0980; effect p = 1.91e-06
- open_cost: opens expected 4,400,000; OPEN records with their path 4,400,000; PATH_MISSING records of the workload 0; CLOSE records 4,400,000; lost to the ring 0
- open_cost: p15d idle: 1.17 ms of CPU per second (mean; median 0.96)
- open_cost: p15d per open+close of the workload: 237.2 ns of CPU in the window (mean), 231.9 ns after the idle rate is taken off (median 221.2 ns)
- open_cost: p15d's thread switches: 0.4 per 1,000 open+close in the window (median), 9.8 per second idle (median)
- profile: 18.00%  p15d               [.] tiles
- profile: 13.00%  p15d               [.] on_bulk
- profile: 9.00%  [kernel.kallsyms]  [k] finish_task_switch.isra.0
- profile: 8.00%  p15d               [.] p15_rec_check
- profile: 7.00%  p15d               [.] crc_hw
- profile: 4.00%  [kernel.kallsyms]  [k] do_syscall_64
- profile: 4.00%  p15d               [.] after_poll
- profile: 3.00%  [kernel.kallsyms]  [k] kernel_init_pages
- idle: | default | 0.837 | 0.636 .. 1.024 | 2.8 | 2.3 | 1.00x | yes |
- idle: Per thread, median ms/s over rounds:
- idle: | default | 0.382 | 0.384 |
- soak: | over the run | median | max | first | last |
- soak: | p15d CPU, ms/s | 2.54 | 3.32 | 0.39 | 2.76 |
- soak: | drain thread, ms/s | 1.46 | 1.95 | | |
- soak: | writer thread, ms/s | 1.09 | 1.37 | | |
- soak: | resident memory, MiB | 24.2 | 24.3 | 23.6 | 24.3 |
- soak: | longest poll gap, s | 0.247 | 0.652 | | |
- soak: WAL: 8.6 MiB, 35.7 KiB/s. Spine records drained: 8,862; bulk-ring records written (NET and file identity): 74,887; kernel skips: spine 0, NET 0; queue full 0; GAP records 0.
- soak: | archive | 16 | 416 | 416 | 100.00% |
- soak: | compile | 17 | 476 | 476 | 100.00% |
- soak: | git | 16 | 208 | 208 | 100.00% |
- soak: | http | 16 | 48 | 48 | 100.00% |
- soak: | memfd | 16 | 16 | 16 | 100.00% |
- soak: | pyfiles | 16 | 192 | 192 | 100.00% |
- soak: | shell | 16 | 32 | 32 | 100.00% |
- soak: | dropper_chain | 17 | 17 |
- soak: | sock_pairs | 128 | 128 |
- soak: | memfd_exec | 16 | 16 |
- soak: - PASS
