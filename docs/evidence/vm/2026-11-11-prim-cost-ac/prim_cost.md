# prim_cost: what a capture program's building blocks cost on this host

Run: cpu=2 rounds=20 iters=20000.

Host speed: a null syscall cost 84.5 ns (median of 20 rounds; 82.6 to 94.3).

20 rounds. The empty loop: 2.2 ns per iteration (subtracted below, round by round).

| primitive | ns per iteration (median) | 95 % interval | what it is |
|---|---|---|---|
| ring_reserve_submit | 35.9 | 35.3 to 36.9 | a 96-byte record reserved, filled and submitted to the ring (no wake-up) |
| ring_reserve_discard | 22.7 | 22.2 to 23.1 | the same reservation, discarded |
| ring_output | 25.3 | 24.1 to 26.9 | a 96-byte record copied into the ring (bpf_ringbuf_output) |
| hash_lookup | 16.2 | 15.7 to 16.8 | a lookup in a 65,536-entry hash map (hit) |
| hash_update_delete | 94.2 | 91.9 to 98.9 | an entry inserted into that map and deleted |
| counter | 4.3 | 4.3 to 4.5 | an atomic add to a global |
| percpu_copy | 12.3 | 12.1 to 12.6 | a 96-byte record copied into a per-CPU buffer |
| ktime | 13.2 | 13.1 to 15.3 | bpf_ktime_get_boot_ns |

