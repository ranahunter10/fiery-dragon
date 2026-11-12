# What p15d's CRC32C costs per byte (after E-0215)

**Question.** p15d's profile under an open+close workload gave `p15_crc32c` 32.6 % of p15d's samples (E-0215). Each WAL batch is checksummed twice: its payload and its header (`daemon/wal.c` `p15w_append`). The function went one byte per table step. How much faster is the x86-64 SSE4.2 `crc32` instruction, 8 bytes per step, which `daemon/crc32c.c` now uses when the CPU has it?

**How.** `crc32c_bench.c` checksums the same SIZE-byte buffer about 64 MiB worth per round, by the table (`p15_crc32c_table`) and by what p15d uses (`p15_crc32c`). It prints the median ns per byte of each over ROUNDS rounds, with the speed-up. It exits 1 unless both give the same CRC.

```
make build/crc32c_bench                 # as the user
build/crc32c_bench 4096 9               # a full batch
build/crc32c_bench 120 9                # about one OPEN record
```

The end-to-end effect is what `bench/open_cost` reports as p15d's CPU per open+close; this harness only times the function.

**Limits.** One thread, a hot cache, one buffer. The dev container's figures do not count: only the VM's do.
