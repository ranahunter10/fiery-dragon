# The Python WAL reader (2026-11-02)

**Where:** the cloud dev container (kernel 6.18, Python 3.13, numpy 2.5.4, google-crc32c 1.9.0 with its C implementation). These checks don't need the target kernel: they are about the file format. CI repeats them on Python 3.14, the VM's version.

**Files:**
- [`container.txt`](container.txt): the cross-check against the C writer, the unit tests and the mutation sweep;
- [`container-it-p15d.txt`](container-it-p15d.txt): the end-to-end test, where both readers read every run.

## Findings (MEAS, dev container)

1. **The Python reader decodes, field by field, what the C writer wrote** (`make it-pyreader`, 6 tests).
   - `daemon/tests/wal_fixture.c` writes a run through `daemon/wal.c`, with 1 KiB segments so it rotates into 4.
   - The run has records of all 10 types, including IPv4 and IPv6 NET records and an IPv4 address with trailing zero bytes (10.0.0.0), which a numpy `S16` field would have cut.
   - Every value matches, the sequence carries across segments, and the rings merge by time.
2. **Both readers agree on real p15d runs.** In the end-to-end test, the Python reader's record counts equal p15w-inspect's, line for line, for all three runs the container can make. That includes the forced-overflow run (INVALID, with GAP records). Case 5, the network case, runs only in CI and on the VM. A planted counting bug in the Python reader fails this check (done by hand, not recorded here).
3. **Unit tests: 31, all pass:**
   - every segment-header check;
   - each of the 9 stop causes of §4, with its torn or corrupt verdict;
   - the run rules (contiguous segments, one run.id, boot_id and schema hash, the sequence carried across segments);
   - every record refusal, worded as `p15_rec_check` words it;
   - no defaults: a missing field is a KeyError;
   - 3,000 random damages to a valid segment: each one ends as a reported stop, a refused header or a refused record, and never as any other error.
4. **Mutation sweep: 71/71 planted bugs caught** (`make mutate-py`). That is 37 new ones in the reader and 34 already in the sweep. One guard is not tested here, and that is declared: the import-time refusal of google-crc32c's pure-Python fallback, because the pinned wheel always brings the C implementation.
