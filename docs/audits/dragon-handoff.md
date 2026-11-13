# Dragon's handoff (kept current in Dragon's open PR)

Dragon is the reviewing and implementing session the maintainer set up on 2026-11-13 (Claude Fable 5.2). Its access may end without warning. This file is what the other session needs to continue.

**How Dragon works, as it turned out.** It runs in a cloud sandbox linked to the maintainer's PC, not on the PC itself. It has its own clone there (so it never touches the maintainer's checkout), can build the daemon and run the Python tests and the spine cases of `it_p15d.sh` (kernel 6.18: no kprobe.session), and cannot push or call the GitHub API. Its PRs leave as `git format-patch` files with a `PR.md` in `dragon-out/<branch>/` inside the maintainer's clone (git-excluded), which the maintainer or the other session applies and pushes; its reviews as `dragon-out/review-PR<N>.md`.

## Done

| What | Where |
|---|---|
| Phase 1, first pass: the design review, findings F-01 to F-15 | `docs/audits/2026-11-13-design-review-dragon.md`, branch `dragon/design-review` |
| Earlier the same day, before this role: the review of #90's programs (V1 to V6) and the graph's FLOW edges | #90 (fixed by the other session in 3c3adc5), #91 |

## In progress

Nothing is half-built. No code was changed in this PR.

## Findings not yet fixed

All of F-01 to F-15 (the review's §1). None is confirmed by a run. The maintainer's runs V-1, V-2 and V-3 (the review's §6) confirm or refute F-01, F-02 and F-04.

## Owed from phase 1 (the review's §7)

1. Read every ADR end to end.
2. Check each book term by term, and every early return in `spine.bpf.c`, `net.bpf.c`, `snap.bpf.c` and the open path of `file.bpf.c`.
3. Re-read the flow programs as of 3c3adc5 (the review read the version before it).
4. The WAL format against a crash at each offset; the reader's reconciliation.

## Next, in the maintainer's order

1. **The detach fault's design note** (decision waiting 23). Start from `kernel/trace/fprobe.c` at v7.0: `unregister_fprobe()` and `fprobe_return()`. Questions the note must answer for option A (gate, wait, a task iterator claiming each open `rw_starts` slot): the memory ordering between the gate and an entry already past it; a task that exits or execs between the cut and the detach (its task storage is freed: is the open call then counted or lost?); a failed storage creation (no slot to claim: the entry must be counted another way); nested calls (one slot per task holds one call); migration (none of the state is per-CPU, so INF: no effect). Alternatives to compare: an fsession (trampoline) in place of the kprobe.session, whose detach semantics for calls in flight must be read in `kernel/bpf/trampoline.c`; keeping the programs attached and closing the books on a gate alone; a per-task counter of open calls in task storage, summed by the iterator.
2. The table of the same fault in every other program (F-03's three OPEN points, F-15).
3. Fixes for the findings the maintainer accepts, one PR each.
4. The independent review of #90 as a whole.

## Things that cost time

- A second session pushes to the same PRs: fetch before building on any branch. Dragon built a duplicate of the V2/V3 fix because it had not fetched.
- A mask, a bound or a length is checked by working one value through it, not by reading it.
- The journal's ids must ascend in file order: rows E-0300 and up go after every row below E-0300, whatever order the PRs merge in.
