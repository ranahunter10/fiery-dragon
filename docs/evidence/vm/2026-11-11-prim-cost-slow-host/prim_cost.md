# prim_cost: what a capture program's building blocks cost on this host

Run: cpu=2 rounds=20 iters=20000.

20 rounds. The empty loop: 9.3 ns per iteration (subtracted below, round by round).

| primitive | ns per iteration (median) | 95 % interval | what it is |
|---|---|---|---|
| ring_reserve_submit | 155.0 | 151.7 to 182.5 | a 96-byte record reserved, filled and submitted to the ring (no wake-up) |
| ring_reserve_discard | 100.9 | 93.7 to 106.2 | the same reservation, discarded |
| ring_output | 126.0 | 108.3 to 143.4 | a 96-byte record copied into the ring (bpf_ringbuf_output) |
| hash_lookup | 57.7 | 48.9 to 76.6 | a lookup in a 65,536-entry hash map (hit) |
| hash_update_delete | 416.7 | 391.9 to 453.0 | an entry inserted into that map and deleted |
| counter | 20.3 | 16.6 to 23.4 | an atomic add to a global |
| percpu_copy | 68.3 | 60.5 to 83.8 | a 96-byte record copied into a per-CPU buffer |
| ktime | 58.4 | 56.7 to 61.4 | bpf_ktime_get_boot_ns |

