# The drain dropped a record whenever the queue was full: found by the open-cost run on the VM (2026-11-11)

Evidence for E-0173 (the finding) and E-0174 (the fix).

## The finding (MEAS, VM `p15-dev-2604`, 7.0.0-38-generic, PR #67 at `bench/open-cost`)

`open_cost.txt` and `open_cost.md` are the maintainer's files, byte for byte (sha256 `da9fa883...0631` and `c68063f1...4edd`, as the VM printed them). 20 rounds plus the warm-up, 220,000 open+close per traced arm at about 400,000 opens a second.

- **19 of 21 traced arms ended INVALID** (`exit=4 state=2 invariant=2`): 10 to 23 of the 220,000 OPEN records were missing from the WAL and a few more CLOSE records, with `lost=0` (no ring reservation failed) and no PATH_MISSING. Two arms (rounds 18 and 19) were complete.
- The harness refused to report timings, as its books demand.
- p15d's own invariant caught it: `emitted != drained + invalid` is what a record taken from the ring and then dropped looks like.

## The cause (SRC)

`third_party/libbpf/src/ringbuf.c`, `ringbuf_process_ring` (libbpf v1.7.0, lines 256-265): the consumer position is advanced **before** the callback runs, and stored even when the callback returns an error. `daemon/drain.c` returned an error from its callbacks when no queue batch was free, with the comment "left in the ring: libbpf does not advance past it". It does. So every moment of "queue full" dropped one record, of the bulk ring or of the spine ring, uncounted. The path needs a writer that falls behind, which no earlier run produced.

## The reproduction and the fix (MEAS, dev container, kernel 6.18.44, spine only)

`it_p15d.sh` case 11 (new): 4 batches of 16 KiB, a writer slowed to 100 ms a batch by the new test hook, 2,000 short processes.

| | queue full | EXEC of /bin/true in the WAL | END |
|---|---|---|---|
| `drain.c` of main (`container-case11-before-the-fix.txt`) | 398 times | 1,899 of 2,000 | exit 4, state 2, invariant 2 |
| this PR (`container-case11-fixed.txt`) | 576 times | 2,000 of 2,000 | exit 0, state 0, invariant 1 |

The fix: the drain asks how many records are certain to fit in its batch (`p15_drain_room`), reads no more than that (`ring__consume_n`), and waits with `epoll_wait` instead of `ring_buffer__poll`, which reads on its own. What does not fit stays in the ring.

`container-mutants-49-54.txt`: the six new mutants of `mutate_p15d.py`, all killed.

## The fix on the VM (MEAS, `vm-fix-pasted.txt`: the lines pasted in chat, with the sha256 of the full files)

- `it_p15d.sh` passes every check with file identity and NET. Case 11, spine only: the queue was full 523 times, 2,000 of 2,000 EXEC records, exit 0, invariant closed. Case 11 with file identity: full 172 times, nothing lost to either ring, exit 0, invariant closed.
- Mutants 52, 53 and 54 (the three that undo the fix and need the real kernel) are killed.
- The open-cost run repeated: all 20 rounds valid, 4,400,000 of 4,400,000 opens in the WAL with their CLOSE records, none lost. At about 400,000 opens a second the default 4 MiB ring was enough.

## What is not shown

- Hosted CI's BPF job for this PR: the runner could not install its Ubuntu packages (a DNS failure on its mirror, three times on 2026-11-11), so it never reached our code. It is re-run before the merge.
- One unexplained failed check: of 14 runs of `it_p15d.sh` in the container during this work, one had a single failed check whose line was not captured (the mutation sweep printed only the end of the output; it now prints every FAIL line). The 13 others, and every run since, passed.
