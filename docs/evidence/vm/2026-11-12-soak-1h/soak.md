# soak: p15d under real programs (gate 4)

Planned 60.0 min of workload, sampled every 60 s; p15d options: -; 3 CPUs.
End: exit 0, state 0, invariant 1; 1,919,817 records read in 30 s.

| over the run | median | max | first | last |
|---|---|---|---|---|
| p15d CPU, ms/s | 4.32 | 5.36 | 4.75 | 2.00 |
| drain thread, ms/s | 2.50 | 3.29 | | |
| writer thread, ms/s | 1.81 | 2.28 | | |
| resident memory, MiB | 26.6 | 27.0 | 23.8 | 27.0 |
| longest poll gap, s | 0.201 | 0.219 | | |

WAL: 184.0 MiB, 51.4 KiB/s. Spine records drained: 234,944; NET records written: 1,620,034; kernel skips: spine 0, NET 0; queue full 0; GAP records 0.

| step | steps | items expected | found | recall |
|---|---|---|---|---|
| archive | 451 | 11,726 | 11,726 | 100.00% |
| compile | 452 | 12,656 | 12,656 | 100.00% |
| git | 451 | 5,863 | 5,863 | 100.00% |
| http | 451 | 1,353 | 1,353 | 100.00% |
| memfd | 451 | 451 | 451 | 100.00% |
| pyfiles | 451 | 5,412 | 5,412 | 100.00% |
| shell | 451 | 902 | 902 | 100.00% |

File identity: 805,932 OPEN from the path program, 3 from the session return (3 walked, 0 raced, 0 without a path); fentry skips 3; lost: OPEN 0, CLOSE 0; most open files 603, objects 843.

Graph: built in 782 s, 147.5 MiB; edge_ACCEPT 3,608, edge_BIND 451, edge_CLONE 55,108, edge_CONNECT 3,627, edge_EXECUTE 55,101, edge_HELD 729, edge_LISTEN 451, edge_OPEN 805,939, edge_without_node 0, node_file 90,981, node_proc 55,247, node_sock 7,686.

| graph check | found | expected |
|---|---|---|
| dropper_chain | 452 | 452 |
| sock_pairs | 3,608 | 3,552 |
| memfd_exec | 451 | 451 |

## Verdict

- FAIL: graph check sock_pairs: 3608 of 3552
