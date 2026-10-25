# Daemon (C)

Phase-1 step 3: the spine loader, record checks and the load-time self-test. The drain and the write-ahead log (`p15d`, ADR-0006/0007) come in step 4 and reuse these parts.

| File | What |
|---|---|
| [`records.c`](records.c) | `p15_rec_check`: a record is used only if its header, `len` and variable fields are all inside the bytes received (ADR-0008 rule 5). Also `p15_rec_format`: one line per record |
| [`selftest.c`](selftest.c) | The load-time self-test (ADR-0003). A test child renames itself, forks a grandchild that exits 7, and execs `/bin/true fd-selftest`. **Only records attributed to the child, the grandchild and the daemon's fork of the child are judged, with exact counts and field values** |
| [`p15_spine.c`](p15_spine.c) | `p15-spine selftest` / `p15-spine dump SECONDS`: attach the spine, run the self-test, optionally print records, then print the per-cause counters |
| [`tests/test_selftest.c`](tests/test_selftest.c) | Unit tests on synthetic records: each failure the self-test must catch, injected one at a time |

```bash
make test-c                    # unit tests, no root
sudo build/p15-spine selftest  # the real self-test (root)
sudo build/p15-spine dump 10   # self-test, then 10 s of spine records
```

The C unit tests caught 12 of 12 deliberate bugs in the evaluation and the record checks.
