# Daemon (C)

Phase-1 steps 3–4: the spine loader, record checks, the load-time self-test, and the write-ahead log writer. The drain daemon (`p15d`, ADR-0006) comes in step 4b and uses these parts.

| File | What |
|---|---|
| [`records.c`](records.c) | `p15_rec_check`: a record is used only if its header, `len` and variable fields are all inside the bytes received (ADR-0008 rule 5). For EXEC, also: `len` is exactly the fields' padded size (unless `READ_FAILED`) and the bytes after the fields are zero, since EXEC is built in a reused scratch buffer (ADR-0017). Also `p15_rec_format`: one line per record |
| [`selftest.c`](selftest.c) | The load-time self-test (ADR-0003). A test child renames itself, forks a grandchild that exits 7, and execs `/bin/true fd-selftest`. **Only records attributed to the child, the grandchild and the daemon's fork of the child are judged, with exact counts and field values.** 22 checks, including that every record takes exactly its `len` in the ring (ADR-0017 layer 1) |
| [`p15_spine.c`](p15_spine.c) | `p15-spine selftest` / `p15-spine dump SECONDS`: attach the spine, run the self-test, optionally print records, then detach and print the per-cause counters. Fails if any record was lost or a type's books do not close (`seen = emitted + reserve_failed + build_failed`) |
| [`tests/test_records.c`](tests/test_records.c), [`tests/mutate_records.py`](tests/mutate_records.py) | The record checks on every type: exact sizes, END's reason, EXEC's slack rules, buffers of exactly `len` under ASan; and the formatter. The sweep plants 39 bugs in `records.c` and runs these tests and `test_snapshot.c` under ASan |
| [`tests/test_selftest.c`](tests/test_selftest.c) | Unit tests on synthetic records: each failure the self-test must catch, injected one at a time |
| [`wal.c`](wal.c), [`wal.h`](wal.h) | The P15W v1.0 writer (ADR-0007, format in [`docs/formats/p15w-v1.md`](../docs/formats/p15w-v1.md)): segments with a self-describing header, one `writev` per batch with CRC32C, per-ring sequence numbers, rotation by size and age, `fdatasync` every interval. Also the batch builder (copies each record at its own `len`), the scanner (the reader's rules) and torn-tail recovery. Time and writes go through injectable functions, so tests drive them exactly |
| [`crc32c.c`](crc32c.c) | CRC32C (Castagnoli), table-driven |
| [`compiler.h`](compiler.h) | `P15_MUST_CHECK` (ADR-0019 G2.1): every fallible function returns 0 or `-errno` and carries it, so an ignored result is a build error under `-Werror` |
| [`exitcodes.h`](exitcodes.h) | The only exit codes the daemon may use (ADR-0019 G2.2), one table with a meaning per code; [`tests/test_exitcodes.c`](tests/test_exitcodes.c) checks it |
| [`tests/test_wal.c`](tests/test_wal.c) | Round trip; a cut at every byte offset of the last batch (torn tail, recovered exactly); corruption that must **not** be truncated (payload, header, tiling, sequence gap); a zero-filled tail; rotation by size and age; sync interval; snapshot callback; `/dev/full`; short writes and `EINTR`; bad batches |
| [`tests/mutate_wal.py`](tests/mutate_wal.py) | Mutation sweep of the writer: 27 planted bugs, each must fail the tests |

```bash
make test-c                    # unit tests, no root
make test-c-asan               # the same under ASan and UBSan
make mutate-wal                # mutation sweep of the WAL writer
make mutate-records            # mutation sweep of the record checks, under ASan
make exit-check                # no exit()/_exit()/abort() outside sites marked "exit-ok: <reason>"
make hardening-check           # the binaries really are PIE, full RELRO, NX, canaries, FORTIFY, CET
sudo build/p15-spine selftest  # the real self-test (root)
sudo build/p15-spine dump 10   # self-test, then 10 s of spine records
```

The C unit tests caught 12 of 12 deliberate bugs in the evaluation and the record checks, and 27 of 27 in the WAL writer (`make mutate-wal`).

**Engineering gates (ADR-0019 G2, G3).** Every userspace binary is built with `-D_FORTIFY_SOURCE=3 -fstack-protector-strong -fstack-clash-protection -fcf-protection -fPIE -pie -Wl,-z,relro,-z,now` and `-Wall -Wextra -Wshadow -Wformat=2 -Wvla -Wstrict-prototypes -Wmissing-prototypes -Werror`, under gcc and clang. `make must-check-test` proves that ignoring a `P15_MUST_CHECK` result fails the build.

## p15d (step 4b)

| File | What |
|---|---|
| [`p15d.c`](p15d.c) | `main`: wiring only. Load and self-test, the snapshot iterator, run directory and WAL header (the first segment opens with a snapshot), writer thread, drain loop, the closing snapshot, orderly stop |
| [`config.c`](config.c) | strict command line; the effective config is echoed into the WAL header |
| [`loader.c`](loader.c) | open, size, load and attach the spine, then the self-test; the hook manifest |
| [`drain.c`](drain.c) | poll the ring, check each record, batch it at its own `len`, publish; counter reads and GAP records. Never touches the disk |
| [`queue.c`](queue.c) | the bounded SPSC queue between the drain and the writer |
| [`writer.c`](writer.c) | the only code that writes the WAL: batches, STATS, CLOCK_SYNC, the textfile, the invariant, the closing snapshot when main asks for it (ADR-0023 rule 1), END |
| [`snapshot.c`](snapshot.c), [`snapshot_frame.c`](snapshot_frame.c) | the process snapshot (ADR-0007 rule 3, ADR-0024): run the task iterator of [`bpf/progs/snap.bpf.c`](../bpf/progs/snap.bpf.c), check every PROC record, append them and SNAP_DONE to the daemon ring. The opening one runs at every segment open (`p15w_opts.on_open`), the closing one at an orderly stop. `snapshot_frame.c` is the part with no BPF and no I/O: framing across reads, the checks, the books; [`tests/test_snapshot.c`](tests/test_snapshot.c) tests it |
| [`run.c`](run.c) | the run state machine and `p15_fail`, the single fatal path |
| [`p15w_inspect.c`](p15w_inspect.c) | `p15w-inspect RUN_DIR`: validate every segment and record, count by type, print the END verdict |

```bash
sudo build/p15d --wal-dir /var/lib/p15 --textfile /run/p15d.prom   # until SIGTERM
build/p15w-inspect /var/lib/p15/<run-id>
sudo make it-p15d                  # the end-to-end test
sudo make mutate-p15d              # the mutation sweep (17 bugs)
```
