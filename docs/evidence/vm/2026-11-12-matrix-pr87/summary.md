# Capture measurement matrix, 20261112T192615Z

    stamp 20261112T192615Z
    commit 5c6f1e3110595b1c07756a6a7eaa468975d6665d clean
    kernel 7.0.0-38-generic cpus 3
    python /home/ashu/p15venv/bin/python
    p15d_options (defaults)
    quick 0 soak_seconds 600
    71052e655849f3f81770fdc9f6df255832dbbfb81fb9028d66d702c786f44d3f  build/p15d
    bae6b6206cd154a7a1479f0215e9f0f9f002b5c8d41a7ee6ea06300d37dc7da8  build/p15w-inspect
    48e7727bbf4cf27e0b20a7e4825d99c08b696c765facd25d190651a60e044f25  build/open_cost
    b02fa35cead785d9c98b8c67b9dbb96545a0d35d1cb9a055aa59fc150b5c7c6a  build/prim_cost
    afa8c259570b390133a745798b7d8561405484fd52f0b2626889c2d5dcdce7dd  build/crc32c_bench

## Steps

- it_p15d rc=0 seconds=113.6
- crc32c rc=0 seconds=2.9
- prog_stats rc=0 seconds=8.2
- open_cost rc=0 seconds=295.5
- open_cost_report rc=0 seconds=0.1
- profile_run rc=0 seconds=63.1
- profile rc=0 seconds=0.5
- profile_callers rc=0 seconds=0.4
- idle rc=0 seconds=144.2
- idle_report rc=0 seconds=0.0
- soak rc=0 seconds=697.1
- soak_report rc=0 seconds=0.1

## Figures (each from its step's own report)

- it_p15d:   queue_full 535, spine reserve failures 0; EXEC of /bin/true: 2000; END: exit 0, state 0, invariant 1, signal 15, reason 
- it_p15d:   with file identity and NET: queue_full 164, spine reserve failures 0, bulk records lost to the ring 0; END: exit 0, state 0, invariant 1, signal 15, reason 
- it_p15d: it_p15d: PASS (0 failed checks)
- crc32c: table   2.4297 ns per byte (median; 2.3866 to 2.5514)
- crc32c: sse4.2  0.1093 ns per byte (median; 0.1041 to 0.1254)
- crc32c: speed-up 22.2x; same crc: yes
- crc32c: table   2.0026 ns per byte (median; 1.9902 to 2.1182)
- crc32c: sse4.2  0.1003 ns per byte (median; 0.0984 to 0.1044)
- crc32c: speed-up 20.0x; same crc: yes
- prog_stats: | file_free | kprobe | 7 | 1,540,895 | 456.5 | 377.2 to 468.3 | 1.001 | 456.8 |
- prog_stats: | file_open_path | tracing | 7 | 1,540,311 | 278.6 | 272.1 to 286.2 | 1.000 | 278.6 |
- prog_stats: | file_open_session | kprobe | 7 | 3,080,622 | 94.6 | 88.7 to 95.9 | 2.000 | 189.2 |
- prog_stats: | file_fd_iter | tracing | 3 | 2,044 | 619.7 | 419.8 to 699.0 | 0.003 | 1.9 |
- prog_stats: | file_inode_free | kprobe | 7 | 60 | 724.0 | 596.2 to 827.0 | 0.000 | 0.0 |
- open_cost: added per open+close 1,140.8 ns (95 % interval 999.8 ns to 1,224.9 ns), 11.42 null syscalls; ratio of medians 2.1386; effect p = 1.91e-06
- open_cost: added per open+close 1,171.5 ns (95 % interval 1,060.3 ns to 1,266.2 ns), 11.72 null syscalls; ratio of medians 2.1813; effect p = 1.91e-06
- open_cost: added per open+close 1,408.5 ns (95 % interval 1,328.0 ns to 1,504.1 ns), 14.10 null syscalls; ratio of medians 1.9853; effect p = 1.91e-06
- open_cost: added per open+close 1,475.2 ns (95 % interval 1,384.7 ns to 1,564.0 ns), 14.76 null syscalls; ratio of medians 2.0068; effect p = 1.91e-06
- open_cost: opens expected 4,400,000; OPEN records with their path 4,400,000; PATH_MISSING records of the workload 0; CLOSE records 4,400,000; lost to the ring 0
- open_cost: p15d idle: 1.98 ms of CPU per second (mean; median 1.88)
- open_cost: p15d per open+close of the workload: 258.6 ns of CPU in the window (mean), 251.4 ns after the idle rate is taken off (median 234.1 ns)
- open_cost: p15d's thread switches: 0.4 per 1,000 open+close in the window (median), 14.0 per second idle (median)
- profile: 25.77%  p15d               [.] tiles
- profile: 9.28%  p15d               [.] on_bulk
- profile: 8.25%  [kernel.kallsyms]  [k] finish_task_switch.isra.0
- profile: 6.19%  [kernel.kallsyms]  [k] _raw_spin_unlock_irqrestore
- profile: 4.12%  p15d               [.] after_poll
- profile: 4.12%  p15d               [.] p15_rec_check
- profile: 2.06%  [kernel.kallsyms]  [k] bpf_prog_get_info_by_fd
- profile: 2.06%  [kernel.kallsyms]  [k] bpf_prog_get_target_btf
- idle: | default | 1.337 | 1.114 .. 1.505 | 5.1 | 0.5 | 1.00x | yes |
- idle: Per thread, median ms/s over rounds:
- idle: | default | 0.662 | 0.556 |
- soak: | over the run | median | max | first | last |
- soak: | p15d CPU, ms/s | 5.34 | 5.80 | 4.82 | 2.93 |
- soak: | drain thread, ms/s | 3.07 | 3.53 | | |
- soak: | writer thread, ms/s | 2.25 | 2.48 | | |
- soak: | resident memory, MiB | 23.4 | 23.6 | 23.1 | 23.6 |
- soak: | longest poll gap, s | 0.201 | 0.203 | | |
- soak: WAL: 31.2 MiB, 47.8 KiB/s. Spine records drained: 38,823; bulk-ring records written (NET and file identity): 270,044; kernel skips: spine 0, NET 0; queue full 0; GAP records 0.
- soak: | archive | 75 | 1,950 | 1,950 | 100.00% |
- soak: | compile | 75 | 2,100 | 2,100 | 100.00% |
- soak: | git | 75 | 975 | 975 | 100.00% |
- soak: | http | 75 | 225 | 225 | 100.00% |
- soak: | memfd | 74 | 74 | 74 | 100.00% |
- soak: | pyfiles | 75 | 900 | 900 | 100.00% |
- soak: | shell | 74 | 148 | 148 | 100.00% |
- soak: | dropper_chain | 75 | 75 |
- soak: | sock_pairs | 600 | 600 |
- soak: | memfd_exec | 74 | 74 |
- soak: - PASS
