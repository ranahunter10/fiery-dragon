# Daemon records in the schema, dev container (2026-10-25)

**Where:** the cloud dev container (kernel 6.18.44, gcc 13.3.0, clang 18.1.3, root). **Not the target**; the VM repeats it with `make check` and `sudo make smoke`. No BPF program changes in this step.

**What:** CLOCK_SYNC, STATS, GAP and END added to `schema/records.toml` at version 1 (branch `feat/schema-daemon-records`); the generator emits the schema hash; `p15_rec_check` and `p15_rec_format` know the new types; fixed-size records must have `len` equal to their size. [`run.txt`](run.txt), from a clean tree, with the same command loop and filter as the [exact-size run](../2026-10-25-exec-exact-container/README.md), over `make clean`, `make -j8`, `make check`, `make test-c-asan`, `make CC=clang OUT=build-clang -j8 all test-c`, `make mutate-records`, `make mutate-wal`, `make mutate-py`, `make smoke`.

## Findings (MEAS, dev container)

1. **The schema check passes with 8 records and the lock grown by four new entries;** no existing layout changed. The three-way layout check agrees on all 9 structs (generator, BTF of the compiled probe, numpy).
2. **The record checks pass their tests under gcc, clang and ASan/UBSan.** `make mutate-records` kills 20 of 20 planted bugs in `daemon/records.c`, the tests running under ASan. Its first run killed 13 of 21. Seven of the eight survivors showed that the new exact-`len` rules masked older checks in the tests, now tested on their own. The last one is equivalent, kept out and explained in the script.
3. The spine's self-test still passes.
