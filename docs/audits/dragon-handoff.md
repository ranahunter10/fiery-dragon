# Dragon's handoff (kept current in Dragon's open PR)

Dragon is the reviewing and implementing session the maintainer set up on 2026-11-13 (Claude Fable 5.2). Its access may end without warning. This file is what the other session needs to continue.

**How Dragon works, as it turned out.** It runs in a cloud sandbox linked to the maintainer's PC, not on the PC itself. It has its own clone there (so it never touches the maintainer's checkout), can build the daemon and run the Python tests and the spine cases of `it_p15d.sh` (kernel 6.18: no kprobe.session), and cannot push or call the GitHub API. Its PRs leave as `git format-patch` files with a `PR.md` in `dragon-out/<branch>/` inside the maintainer's clone (git-excluded), which the maintainer or the other session applies and pushes; its reviews as `dragon-out/review-PR<N>.md`.

## Done

| What | Where |
|---|---|
| Phase 1, first pass: the design review, findings F-01 to F-15 | `docs/audits/2026-11-13-design-review-dragon.md` (#92, merged). The other session's verdict on each finding is #92's comment: ten confirmed, F-06 corrected (AIO, reflink and fallocate reach `security_file_permission`), F-11 fixed in #90 |
| The detach fault's design note (work queue item 1, the note only) | `docs/research/2026-11-13-detach-fault-design.md`, branch `dragon/detach-fault-note`, stacked on #90 at 7984a97 |
| The same fault in the other programs, first pass (work queue item 2) | §6 of that note |

## In progress

Nothing is half-built. No code has been changed by Dragon since #91.

## Waiting on the maintainer

Decisions waiting 110 to 115 (the note's §8). The fix is not written: 110 decides between option A in the note's form and option B.

## If the maintainer chooses A: what to build, in this order

1. `bench/flow_cost`: an arm `count` (the count word at every entry and return). Its number against `ts` is the cost per call; the choice between A and B rests on it.
2. `file.bpf.c`: a gate in `.bss`; the slot's word (low half open calls, high half claimed); the cookie's low bit for a slot-less entry; the return's compare-and-exchange, three tries; a task iterator that claims. New counters: `V_GATED`, `OPEN_AT_END`, `RETURNED_AFTER_COUNT`, `V_NO_SLOT_ENTRY`, `V_NO_SLOT_RETURN`, `V_CLAIM_RACE`, `V_ENTRY_WHILE_OPEN` (reported, not a book term).
3. p15d's stop: the closing snapshot; the gate; `membarrier`; the bounded wait on B1's residual; the iterator; detach, flow sessions before the socket tracepoints, the spine last; `membarrier` again; the books.
4. B1 as the note's §3.7, every book's message printing all its terms; FLOW_STATS gains the fields (its v1 is unmerged, so in place).
5. The tests of the note's §7, the planted bugs, the VM matrix commands.

## Findings not yet fixed

From the review: F-01 to F-05, F-07 to F-10, F-12 to F-15 (F-06 corrected, F-11 fixed). Runs V-1, V-2 and V-3 are the maintainer's; V-1 and V-3 need `sudo` to read the WAL.
From the note: the attach-side silence (114), ftrace's uncounted skips (115).

## Owed from phase 1 (the review's §7)

1. Read every ADR end to end.
2. Check each book term by term, and every early return in `spine.bpf.c`, `net.bpf.c`, `snap.bpf.c` and the open path of `file.bpf.c`.
3. The WAL format against a crash at each offset; the reader's reconciliation.
The note's §6 covered the attach and detach behaviour of every program, which was part of item 2 of that list.

## Next, in the maintainer's order

1. The detach fix, once 110 is decided (above).
2. Work queue item 2 in full: §6's table has OPEN cells (whether a task iterator can tell that a task is inside a hooked function; whether `bpf_link__destroy` returns only after every running handler has finished, for each link type).
3. What phase 1 owes.
4. The independent review of #90 as a whole.

## Things that cost time

- A second session pushes to the same PRs: fetch before building on any branch. Dragon built a duplicate of the V2/V3 fix because it had not fetched.
- A mask, a bound or a length is checked by working one value through it, not by reading it.
- The journal's ids must ascend in file order: rows E-0300 and up go after every row below E-0300, whatever order the PRs merge in.
