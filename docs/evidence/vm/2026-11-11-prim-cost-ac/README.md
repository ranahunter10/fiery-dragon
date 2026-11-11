# Where a capture program's time goes: the first clean cost breakdown (VM, 2026-11-11)

Evidence for E-0184. VM `p15-dev-2604`, 7.0.0-38-generic, 3 vCPU, tree at `d524097` (PR #69). **Host on its charger, Windows power mode Best performance** (the maintainer, for this run). Before the run, `open_cost` alone: 10^6 null syscalls in 84,972,570 ns of thread CPU (85.0 ns each). Commands as in `bench/prim_cost/README.md`.

`prim_cost.txt`, `prim_cost.md` and `prog_stats.txt` are the maintainer's files, rebuilt here from his paste, byte for byte: sha256 `13318357...68c0`, `417bb027...20b0` and `a7acd57e...16e0`, as the VM printed them. `summarize.py` at `d524097` on `prim_cost.txt` gives `prim_cost.md` byte for byte.

**Host check passed in both:** a null syscall cost 84.5 ns (`prim_cost`, 20 rounds, 82.6 to 94.3) and 89.7 ns (`prog_stats.py`, 7 rounds, 85.8 to 95.4); neither report says SLOW or UNSTEADY.

## The building blocks, alone (MEAS, `prim_cost.md`; one CPU, no contention, no reader during a run)

| block | ns (median, 20 rounds) | 95 % interval |
|---|---|---|
| ring record, 96 bytes, reserved and submitted | 35.9 | 35.3 to 36.9 |
| the same, copied in (`bpf_ringbuf_output`) | 25.3 | 24.1 to 26.9 |
| hash lookup (hit, 65,536 entries) | 16.2 | 15.7 to 16.8 |
| hash insert + delete | 94.2 | 91.9 to 98.9 |
| atomic add | 4.3 | 4.3 to 4.5 |
| 96-byte copy into a per-CPU buffer | 12.3 | 12.1 to 12.6 |
| `bpf_ktime_get_boot_ns` | 13.2 | 13.1 to 15.3 |

## Our programs while 220,000 open+close run (MEAS, `prog_stats.txt`; 7 rounds; `bpf_stats` on)

| program | runs per open+close | ns per run (median) | cheapest to dearest round | ns per open+close |
|---|---|---|---|---|
| `file_open_path` (fentry, `security_file_open`) | 1.000 | 561.2 | 418.6 to 630.9 | 561.3 |
| `file_open_session` (kprobe.session, entry and return) | 2.000 | 144.4 | 137.4 to 157.4 | 288.9 |
| `file_free` (kprobe.multi, `security_file_free`) | 1.001 | 288.7 | 281.4 to 313.6 | 288.9 |
| all programs | 4.004 | | | 1,139.2 |

With `bpf_stats` on, every run also pays for the kernel's two clock reads around it; this is where the time goes, not the overhead (that is E-0176, with the statistics off).

## What it says (INF unless marked)

- **The program bodies hold about 1.1 µs per open+close** (1,139.2 ns MEAS, with the statistics' own cost inside). E-0176's subtraction said about 1.2 µs: they agree.
- **The ring is not where the time goes.** Two records per open+close at 25 to 36 ns each is about 60 to 70 ns, about 6 % of the bodies. Batching per CPU (eAudit, R-042) would save at most about 25 ns per record on one thread. Under contention this is not known: step 2b's ceiling gate measures it.
- **The path program is half of the bodies,** and its known blocks do not explain it. It reads one clock, does two hash lookups, copies one record of about 120 bytes into the ring and bumps a few counters: about 100 to 150 ns by the table. The rest, about 400 ns, is most likely `bpf_d_path`, which this harness cannot time alone (it needs a file from a hook). **Unmeasured.**
- **The session program is a quarter** (288.9 ns per open+close MEAS). It holds the open-file map's insert and exists to cover a skipped path program, which happened 0 times in 4.4 M single-thread opens (E-0175).
- **The close program is a quarter** (288.9 ns MEAS): a lookup, a ring record, a delete.
- **The open-file map's insert and delete** cost about 94 ns per open+close, about 8 %.

## What is not shown

- `bpf_d_path`'s own cost; the cost of anything under contention on several CPUs; p15d's own CPU (552 ns per open+close and 14.65 ms/s idle in E-0176) is outside these programs and not explained here.
