# Dragon's handoff (kept current in Dragon's open PR)

Dragon is the reviewing and implementing session the maintainer set up on 2026-11-13 (Claude Fable 5.2). Its access may end without warning. This file is what the other session needs to continue.

**How Dragon works, as it turned out.** It runs in a cloud sandbox linked to the maintainer's PC, not on the PC itself. It has its own clone there (so it never touches the maintainer's checkout), can build the daemon and run the Python tests and the spine cases of `it_p15d.sh` (kernel 6.18: no kprobe.session), and cannot push or call the GitHub API. Its PRs leave as `git format-patch` files with a `PR.md` in `dragon-out/<branch>/` inside the maintainer's clone (git-excluded), which the maintainer or the other session applies and pushes; its reviews as `dragon-out/review-PR<N>.md`.

## Done

| What | Where |
|---|---|
| Phase 1, first pass: the design review, findings F-01 to F-15 | `docs/audits/2026-11-13-design-review-dragon.md` (#92, merged). The other session's verdict on each finding is #92's comment: ten confirmed, F-06 corrected, F-11 fixed in #90 |
| The detach fault's design note, with a first pass of the same fault in the other programs | `docs/research/2026-11-13-detach-fault-design.md` |
| The detach fix (decisions 110 to 112, accepted E-0304): the gate, the per-task count, the claim, p15d's stop with `membarrier`, the spine detached last, B1's new terms, FLOW_STATS' fields, `it_p15d` cases 15 to 17, 14 planted bugs, the `flow_cost` arm `count` | branch `dragon/detach-fix`, four commits on #90 at 7984a97 (the note, the bench arm, the fix, STATE and journal) |

## Proven, and not

Proven in the dev container (kernel 6.18): both compilers' builds, the C unit tests (also under ASan and UBSan), the layout check, `it_p15d` with case 15, planted bugs 66 to 73 of `mutate_p15d.py`.

**Not proven anywhere yet**, because no session program loads in the dev container:
- that the 7.0 verifier accepts the new atomics on the task slot and the `iter/task` program;
- `it_p15d` cases 16 and 17;
- planted bugs 74 to 79;
- the `flow_cost` arm `count`, and so the cost per call (decision waiting 116).
CI's 7.0 runner shows the first three when the PR is opened; the VM shows the fourth.

## If CI fails on this PR, where to look first

1. **The verifier refuses `flow_open_iter`:** `bpf_task_storage_get` on the iterator's task, then a compare-and-exchange on the value. If the helper is refused there, the fallback is the same claim from a `iter/task` program in `snap.bpf.c`'s style (sleepable), sharing `rw_starts` by fd.
2. **The verifier refuses the bounded loop in `rw_release`:** unroll it by hand (four copies); the logic does not change.
3. **Case 16 fails with B1 broken:** read END's reason: it prints every term. `open` above the three held calls is normal (other tasks block too); `relfail` above 0 is a bug in `rw_release`.
4. **Case 17's `returned_after_count` is 0:** the read was released before the count (the helper signals on p15d's `code=test_pause phase=flow_cut` line), or the pause ended first.
5. **Reconciliation changes** (`python/p15/reconcile.py`, ADR-0023, ADR-0024): the spine now runs for the whole of the stop, up to `--flow-stop-wait-ms` longer after the closing snapshot than before. If a reconciliation check counts events after the closing snapshot, it will see more of them.

## Waiting on the maintainer

116 (accept the fix on the `count` arm's number, or fall back to option B) and 117 (the daemon sweep's five stale anchors at #90's head).

## Next, in the accepted order (robustness before folding)

1. Whatever CI and the VM show on this PR.
2. 113: the same term for the open path's session, after this fix has passed the VM matrix.
3. 103: the open-file map sized from the host, and `file_map_full` as a DEGRADED state (small).
4. 104: the canary of ADR-0019 G4.4, extended to an open and a transfer.
5. 101 and 102: design notes first (FLOW on its own ring with a per-process loss count; a free-space reserve and a supervisor), after runs V-1 and V-2.
6. 105, 107, 108, 114, 115: the coverage table and the limits, in an ADR; FORK version 2; ADR-0013.
7. What phase 1 owes; then work queue items 4 to 9.

## Findings not yet fixed

From the review: F-01 to F-05, F-07 to F-10, F-12 to F-15 (F-06 corrected, F-11 fixed). Runs V-1, V-2 and V-3 are the maintainer's; V-1 and V-3 need `sudo` to read the WAL.
From the note: the attach-side silence (114), ftrace's uncounted skips (115).

## Owed from phase 1 (the review's §7)

1. Read every ADR end to end.
2. Check each book term by term, and every early return in `spine.bpf.c`, `net.bpf.c`, `snap.bpf.c` and the open path of `file.bpf.c`.
3. The WAL format against a crash at each offset; the reader's reconciliation.
The note's §6 covered the attach and detach behaviour of every program, which was part of item 2 of that list.

## Things that cost time

- A second session pushes to the same PRs: fetch before building on any branch. Dragon built a duplicate of the V2/V3 fix because it had not fetched.
- A mask, a bound or a length is checked by working one value through it, not by reading it.
- The journal's ids must ascend in file order: rows E-0300 and up go after every row below E-0300, whatever order the PRs merge in.
