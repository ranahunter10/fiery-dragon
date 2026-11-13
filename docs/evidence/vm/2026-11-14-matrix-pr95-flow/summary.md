# Capture measurement matrix, 20261113T184233Z

    stamp 20261113T184233Z
    commit 4e923ba5d0406a53dd0fcfb8e45b27e7b93262da clean
    kernel 7.0.0-38-generic cpus 3
    python /home/ashu/p15venv/bin/python
    p15d_options --flow
    quick 0 soak_seconds 600
    6361bc7af1f837455dd97b65acb7ea80e5df4ac1327f2dad1d7fc3d941ff4f6e  build/p15d
    816c5ec9cc6c65ae714a09aedb499e57519f3b8bbb125617ba0a8f9185e86f55  build/p15w-inspect
    48e7727bbf4cf27e0b20a7e4825d99c08b696c765facd25d190651a60e044f25  build/open_cost
    b02fa35cead785d9c98b8c67b9dbb96545a0d35d1cb9a055aa59fc150b5c7c6a  build/prim_cost
    afa8c259570b390133a745798b7d8561405484fd52f0b2626889c2d5dcdce7dd  build/crc32c_bench

## Steps

- it_p15d rc=0 seconds=154.5 start=1794595353.387 end=1794595507.869
- crc32c rc=0 seconds=2.8 start=1794595507.882 end=1794595510.724
- prog_stats rc=0 seconds=8.6 start=1794595510.736 end=1794595519.304
- open_cost rc=0 seconds=274.5 start=1794595519.318 end=1794595793.798
- open_cost_report rc=0 seconds=0.1 start=1794595793.808 end=1794595793.869
- profile_run rc=0 seconds=60.4 start=1794595793.883 end=1794595854.323
- profile rc=0 seconds=0.4 start=1794595854.334 end=1794595854.726
- profile_callers rc=0 seconds=0.4 start=1794595854.736 end=1794595855.175
- idle rc=0 seconds=143.8 start=1794595855.187 end=1794595998.954
- idle_report rc=0 seconds=0.0 start=1794595998.964 end=1794595999.004
- soak rc=0 seconds=1146.8 start=1794595999.015 end=1794597145.783
- soak_report rc=0 seconds=0.0 start=1794597145.795 end=1794597145.840

## Stalls (tools/vm/stalls.py on the guest's kernel log)

- stall end=1794595369.898 gap_s=1.5 signs=clocksource
- stall end=1794595548.570 gap_s=5.7 signs=clocksource
- stall end=1794597106.857 gap_s=490.3 signs=soft_lockup,clocksource
- touched it_p15d gap_s=1.5
- touched open_cost gap_s=5.7
- touched soak gap_s=490.3
- stalls 3

## Figures (each from its step's own report)

- it_p15d:   queue_full 517, spine reserve failures 0; EXEC of /bin/true: 2000; END: exit 0, state 0, invariant 1, signal 15, reason 
- it_p15d:   with file identity and NET: queue_full 157, spine reserve failures 0, bulk records lost to the ring 0; END: exit 0, state 0, invariant 1, signal 15, reason 
- it_p15d: it_p15d: PASS (0 failed checks)
- crc32c: table   1.9791 ns per byte (median; 1.9645 to 2.3108)
- crc32c: sse4.2  0.0926 ns per byte (median; 0.0902 to 0.1013)
- crc32c: speed-up 21.4x; same crc: yes
- crc32c: table   2.3507 ns per byte (median; 2.3325 to 2.6266)
- crc32c: sse4.2  0.1201 ns per byte (median; 0.1123 to 0.1484)
- crc32c: speed-up 19.6x; same crc: yes
- prog_stats: | file_open_path | tracing | 7 | 1,540,359 | 333.1 | 283.3 to 459.2 | 1.000 | 333.2 |
- prog_stats: | file_free | kprobe | 7 | 1,541,094 | 311.8 | 280.3 to 373.8 | 1.001 | 312.0 |
- prog_stats: | file_open_session | kprobe | 7 | 3,080,720 | 87.8 | 85.6 to 90.6 | 2.000 | 175.6 |
- prog_stats: | file_fd_iter | tracing | 3 | 1,983 | 373.6 | 351.6 to 453.9 | 0.003 | 1.1 |
- prog_stats: | file_inode_free | kprobe | 7 | 56 | 446.6 | 387.8 to 702.8 | 0.000 | 0.0 |
- open_cost: added per open+close 1,112.1 ns (95 % interval 1,079.7 ns to 1,167.1 ns), 12.16 null syscalls; ratio of medians 2.1482; effect p = 1.91e-06
- open_cost: added per open+close 1,163.0 ns (95 % interval 1,111.6 ns to 1,209.2 ns), 12.71 null syscalls; ratio of medians 2.1854; effect p = 1.91e-06
- open_cost: added per open+close 1,425.0 ns (95 % interval 1,357.7 ns to 1,492.1 ns), 15.58 null syscalls; ratio of medians 2.1606; effect p = 1.91e-06
- open_cost: added per open+close 1,488.7 ns (95 % interval 1,417.5 ns to 1,559.1 ns), 16.27 null syscalls; ratio of medians 2.1744; effect p = 1.91e-06
- open_cost: opens expected 4,400,000; OPEN records with their path 4,400,000; PATH_MISSING records of the workload 0; CLOSE records 4,400,000; lost to the ring 0
- open_cost: p15d idle: 2.70 ms of CPU per second (mean; median 2.55)
- open_cost: p15d per open+close of the workload: 264.1 ns of CPU in the window (mean), 254.7 ns after the idle rate is taken off (median 234.6 ns)
- open_cost: p15d's thread switches: 0.4 per 1,000 open+close in the window (median), 19.0 per second idle (median)
- profile: 23.71%  [kernel.kallsyms]  [k] finish_task_switch.isra.0
- profile: 10.31%  p15d               [.] on_bulk
- profile: 8.25%  p15d               [.] tiles
- profile: 7.22%  [kernel.kallsyms]  [k] _raw_spin_unlock_irqrestore
- profile: 6.19%  [kernel.kallsyms]  [k] bpf_prog_get_info_by_fd
- profile: 6.19%  [kernel.kallsyms]  [k] fdget
- profile: 5.15%  [kernel.kallsyms]  [k] bpf_prog_get_target_btf
- profile: 5.15%  p15d               [.] p15_rec_check
- idle: | default | 1.997 | 1.656 .. 2.240 | 8.6 | 1.7 | 1.00x | no |
- idle: Per thread, median ms/s over rounds:
- idle: | default | 1.441 | 0.652 |
- soak: | over the run | median | max | first | last |
- soak: | p15d CPU, ms/s | 4.93 | 5.68 | 4.97 | 0.04 |
- soak: | drain thread, ms/s | 3.22 | 3.70 | | |
- soak: | writer thread, ms/s | 1.76 | 1.98 | | |
- soak: | resident memory, MiB | 26.2 | 26.4 | 25.7 | 26.4 |
- soak: | longest poll gap, s | 0.204 | 0.205 | | |
- soak: WAL: 47.0 MiB, 41.7 KiB/s. Spine records drained: 39,343; bulk-ring records written (NET and file identity): 442,609; kernel skips: spine 0, NET 0; queue full 0; GAP records 0.
- soak: STALL: the sample at t=1096 s came 496 s after the one before it (planned every 60 s): about 436 s of the run lost to a stall. The rates above are not quotable (E-0249).
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
