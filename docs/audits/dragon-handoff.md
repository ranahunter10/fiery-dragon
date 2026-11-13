# Dragon's handoff (kept current in Dragon's open PR)

Dragon is the reviewing and implementing session the maintainer set up on 2026-11-13 (Claude Fable 5.2). Its access may end without warning. This file is what the other session needs to continue.

**How Dragon works, as it turned out.** It runs in a cloud sandbox linked to the maintainer's PC, not on the PC itself. It has its own clone there (so it never touches the maintainer's checkout), can build the daemon and run the Python tests and the spine cases of `it_p15d.sh` (kernel 6.18: no kprobe.session), and cannot push or call the GitHub API. Its PRs leave as `git format-patch` files with a `PR.md` in `dragon-out/<branch>/` inside the maintainer's clone (git-excluded), which the maintainer or the other session applies and pushes; its reviews as `dragon-out/review-PR<N>.md`.

## Done

| What | Where |
|---|---|
| Phase 1, first pass: the design review, findings F-01 to F-15 | `docs/audits/2026-11-13-design-review-dragon.md` (#92, merged). The other session's verdict on each finding is #92's comment |
| The detach fault's design note | `docs/research/2026-11-13-detach-fault-design.md` |
| The detach fix (decisions 110 to 112) | PR #95, `dragon/detach-fix`. Passed CI's 7.0 runner and the VM (E-0255) |
| #95's follow-up: `V_RELEASE_NONE`, planted bug 77 made to build, planted bug 80 | one commit on `dragon/detach-fix` (E-0306) |
| The open path's session at the end (decision 113) | branch `dragon/open-detach`, stacked on #95 (E-0307); note `docs/research/2026-11-14-open-session-end-count.md` |
| The canary and the link check (decision 104, the research note's I4) | branch `dragon/canary`, stacked on `dragon/open-detach` (E-0308); note `docs/research/2026-11-14-canary-and-self-check.md` |
| The open-file map's size from the host, and its full state (decision 103) | branch `dragon/file-map-size`, stacked on `dragon/canary` (E-0309) |

The four pieces of 2026-11-14 left as four zips, each with its patches, `PR.md`, `README.md` and an `apply.sh` that checks the base by its tree (a stacked base applied with `git am` has other commit ids). They apply in the order of the table.

## Proven, and not

Proven in the dev container (kernel 6.18; the spine loads, no `kprobe.session` does): both compilers' builds; the C unit tests, also under ASan and UBSan; the layout check; `it_p15d` cases 1 to 4, 6, 7, 10, 11, 15, 20 to 26; planted bugs 69, 81 to 85 and 90 to 107 of `mutate_p15d.py`, all killed.

**Not proven anywhere yet:**
- #95's follow-up: case 13's `v_release_none` check, planted bugs 77 and 80.
- The open path: that the 7.0 verifier accepts the session's new atomic OR and AND on the open-file entry; cases 18 and 19; planted bugs 86 to 89; the cost per open (decision waiting 119).
- The canary with file identity and with `--flow`: its OPEN, its FLOW, and the two run counters (bits 32 and 64). Case 21 on CI and the VM is the first run of them.
- The map: case 27, which is also the first real run of the open session's no-slot path.
- Every matrix: none has run on these four branches.

## If CI fails, where to look first

1. **The verifier refuses `file_open_session`:** the new instructions are `__sync_fetch_and_or` and `__sync_fetch_and_and` on `fe->state` (32-bit, a map value). If 32-bit fetch forms are refused, make `state` and `pad` one `__u64` and use the 64-bit forms; the logic does not change.
2. **The verifier refuses `file_open_iter` on 7.0** (6.18 accepts it, case 20): it copies the key and looks the entry up again so the compare-and-exchange is on a map value. There is no other pointer in it to object to.
3. **Case 18 fails with the entry book broken:** END's reason prints every term. `open` short of the helper's three files means the helper process opened and closed some other file under mode 1 (a lost return on a freed file is in no count, by design). Look at what Python opened after SIGUSR1.
4. **Case 21 reports a miss with file identity on:** the CANARY_MISS masks are in the check's line (`R:<want>:<seen>`). Bit 8 unseen: the canary's OPEN did not carry its tgid, or the path program did not run for `/dev/null`. Bits 32 or 64 unseen: the drain's copy of `SESSION_ENTRY` or `FREE_RUN` did not move within the second.
5. **Case 27 ends INVALID instead of DEGRADED:** a book does not close when the open-file map is full. The no-slot path of `file_open_session` is the new code there; the reason names the book.
6. **A stats-counting test or bench is off by a few records** on a run with `--canary-s`: the canary's processes are named `fd-canary` (argv[0]) and run `/bin/true`.
7. **Reconciliation** (`python/p15/reconcile.py`): the spine detaches last, and with file identity on every run now does the end's gate, grace period and bounded wait, `--flow` or not.

## Waiting on the maintainer

Decisions 118 to 127 (STATE lists each with its recommendation), and the VM runs each `PR.md` gives. Runs V-1, V-2 and V-3 of the design review are still not run; V-1 and V-3 need `sudo` to read the WAL.

## Next, in the accepted order

1. Whatever CI and the VM show on the four pieces.
2. The canary on by default (123), after a matrix with `-- --canary-s 10`; then a read and a rename added to it (122).
3. The object map: sized with the open-file map, DEGRADED when full (127).
4. Design notes: ADR-0013, the threat model (108), as a draft numbered from 0050; the flood and the disk (F-01, F-02; 101, 102), options now, recommendations after V-1 and V-2. Not started.
5. 105, 107, 114, 115: the coverage table and the limits in an ADR; FORK version 2.
6. What phase 1 owes (below); then the work queue's items 4 to 9.

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
- A stacked zip must check its base by tree, not by commit id: `git am` on the maintainer's side makes new ids.
- A planted bug that removes a function's only call does not build under `-Werror`: leave `(void)name;` in its place. Build each new mutant once before delivering it.
- `daemon/p15d.c`'s loader-options block is inside planted bug 9's anchor: a line added there breaks the sweep. Test switches reach the loader by `p15_loader_test_open_end()` for that reason.
- The dev container loses its tracefs mount when it restarts, and then every `it_p15d` check fails at once: `mount -t tracefs nodev /sys/kernel/tracing`.
- A header that includes `p15_records.h` must include `exitcodes.h` first: the generated header aliases `p15_exit`, which `exitcodes.h` names as an enum.
- Any record or struct named like a generated record (`p15_canary`) collides with the generated alias.
