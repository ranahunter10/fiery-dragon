# Capture measurement matrix, 20261113T020318Z

    stamp 20261113T020318Z
    commit 99dc5bccd2651d99814cbf99e83117e92ac74179 clean
    kernel 7.0.0-38-generic cpus 3
    python /home/ashu/p15venv/bin/python
    p15d_options --flow
    quick 0 soak_seconds 600
    bdf131def4fb08f2de4c80d2a4e34b42c104e09d5b6b3f64bf272d5d78a43026  build/p15d
    a6c2552606b1fc75efbdbafb68e26f0eed028cd2e1220dda6fae047f6591f684  build/p15w-inspect
    48e7727bbf4cf27e0b20a7e4825d99c08b696c765facd25d190651a60e044f25  build/open_cost
    b02fa35cead785d9c98b8c67b9dbb96545a0d35d1cb9a055aa59fc150b5c7c6a  build/prim_cost
    afa8c259570b390133a745798b7d8561405484fd52f0b2626889c2d5dcdce7dd  build/crc32c_bench

## Steps

- it_p15d rc=0 seconds=136.9
- crc32c rc=0 seconds=2.5
- prog_stats rc=0 seconds=9.1
- open_cost rc=1 seconds=264.2
- open_cost_report rc=1 seconds=0.0
- profile_run rc=0 seconds=62.3
- profile rc=0 seconds=0.3
- profile_callers rc=0 seconds=0.3
- idle rc=0 seconds=162.9
- idle_report rc=0 seconds=0.0
- soak rc=0 seconds=639.0
- soak_report rc=0 seconds=0.0

## Figures (each from its step's own report)

- it_p15d:   queue_full 750, spine reserve failures 0; EXEC of /bin/true: 2000; END: exit 0, state 0, invariant 1, signal 15, reason 
- it_p15d:   with file identity and NET: queue_full 164, spine reserve failures 0, bulk records lost to the ring 0; END: exit 0, state 0, invariant 1, signal 15, reason 
- it_p15d: it_p15d: PASS (0 failed checks)
- crc32c: table   1.9743 ns per byte (median; 1.9553 to 1.9901)
- crc32c: sse4.2  0.0909 ns per byte (median; 0.0902 to 0.0939)
- crc32c: speed-up 21.7x; same crc: yes
- crc32c: table   1.9897 ns per byte (median; 1.9672 to 2.0919)
- crc32c: sse4.2  0.0998 ns per byte (median; 0.0982 to 0.1036)
- crc32c: speed-up 19.9x; same crc: yes
- prog_stats: | file_open_path | tracing | 7 | 1,540,365 | 270.6 | 262.1 to 295.2 | 1.000 | 270.6 |
- prog_stats: | file_free | kprobe | 7 | 1,541,075 | 179.3 | 169.7 to 186.6 | 1.001 | 179.5 |
- prog_stats: | file_open_session | kprobe | 7 | 3,080,730 | 82.7 | 79.8 to 84.5 | 2.000 | 165.5 |
- prog_stats: | file_fd_iter | tracing | 3 | 2,093 | 394.8 | 363.1 to 680.4 | 0.003 | 1.3 |
- prog_stats: | file_inode_free | kprobe | 7 | 60 | 422.1 | 319.6 to 664.2 | 0.000 | 0.0 |
- profile: 40.98%  [kernel.kallsyms]  [k] _raw_spin_unlock_irq
- profile: 26.23%  [kernel.kallsyms]  [k] finish_task_switch.isra.0
- profile: 16.39%  p15d               [.] tiles
- profile: 4.92%  p15d               [.] on_bulk
- profile: 1.64%  [kernel.kallsyms]  [k] __memcg_slab_post_alloc_hook
- profile: 1.64%  [kernel.kallsyms]  [k] _raw_spin_unlock_irqrestore
- profile: 1.64%  [kernel.kallsyms]  [k] folio_wait_bit_common
- profile: 1.64%  [kernel.kallsyms]  [k] handle_softirqs
- idle: | default | 1.511 | 1.218 .. 1.713 | 5.7 | 1.6 | 1.00x | yes |
- idle: Per thread, median ms/s over rounds:
- idle: | default | 0.759 | 0.781 |
- soak: | over the run | median | max | first | last |
- soak: | p15d CPU, ms/s | 3.10 | 4.34 | 4.34 | 2.28 |
- soak: | drain thread, ms/s | 1.73 | 2.36 | | |
- soak: | writer thread, ms/s | 1.37 | 1.98 | | |
- soak: | resident memory, MiB | 24.4 | 24.6 | 23.8 | 24.6 |
- soak: | longest poll gap, s | 0.232 | 0.413 | | |
- soak: WAL: 28.3 MiB, 45.8 KiB/s. Spine records drained: 23,169; bulk-ring records written (NET and file identity): 259,976; kernel skips: spine 0, NET 0; queue full 0; GAP records 0.
- soak: | archive | 45 | 1,170 | 1,170 | 100.00% |
- soak: | compile | 45 | 1,260 | 1,260 | 100.00% |
- soak: | git | 45 | 585 | 585 | 100.00% |
- soak: | http | 44 | 132 | 132 | 100.00% |
- soak: | memfd | 44 | 44 | 44 | 100.00% |
- soak: | pyfiles | 45 | 540 | 540 | 100.00% |
- soak: | shell | 44 | 88 | 88 | 100.00% |
- soak: | dropper_chain | 45 | 45 |
- soak: | sock_pairs | 352 | 352 |
- soak: | memfd_exec | 44 | 44 |
- soak: - PASS
