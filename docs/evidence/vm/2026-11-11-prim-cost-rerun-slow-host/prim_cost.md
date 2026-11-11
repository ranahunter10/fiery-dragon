# prim_cost: what a capture program's building blocks cost on this host

Run: cpu=2 rounds=20 iters=20000.

Host speed: a null syscall cost 380.6 ns (median of 20 rounds; 353.8 to 464.5).
**SLOW: 4.35 times the reference of 87.5 ns (limit 1.5). Not quotable.**

20 rounds. The empty loop: 9.0 ns per iteration (subtracted below, round by round).

| primitive | ns per iteration (median) | 95 % interval | what it is |
|---|---|---|---|
| ring_reserve_submit | 158.0 | 154.6 to 164.7 | a 96-byte record reserved, filled and submitted to the ring (no wake-up) |
| ring_reserve_discard | 98.6 | 94.4 to 108.6 | the same reservation, discarded |
| ring_output | 117.0 | 109.5 to 134.3 | a 96-byte record copied into the ring (bpf_ringbuf_output) |
| hash_lookup | 52.3 | 46.8 to 59.5 | a lookup in a 65,536-entry hash map (hit) |
| hash_update_delete | 420.4 | 397.9 to 457.4 | an entry inserted into that map and deleted |
| counter | 18.0 | 15.0 to 19.9 | an atomic add to a global |
| percpu_copy | 61.2 | 58.1 to 65.3 | a 96-byte record copied into a per-CPU buffer |
| ktime | 60.1 | 55.7 to 67.7 | bpf_ktime_get_boot_ns |

