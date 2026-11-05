---
status: accepted
date: 2026-11-05
owner: Ashish Rana
consulted: [ADR-0007 (snapshot per segment), ADR-0020 rule 5 (self_exec_id), Houssel et al. 2026 (R-027), the end-to-end argument (R-030), double-entry bookkeeping, research note 2026-11-05 §5, maintainer's acceptance of 2026-11-05]
supersedes: none (adds to ADR-0007 rule 3 and ADR-0020 rule 5)
---

# 0023: Reconcile the process tree against a closing snapshot

## Context and problem statement

Today a run's counters close: every event the kernel showed us is written or counted lost (ADR-0006 rule 6), and the events the kernel skipped are counted (ADR-0020). Counters say **how many** were lost, but not **which process's** FORK or EXIT is missing. A 2026 study of provenance capture found that none of the tools it examined checks its own completeness (R-027).

Bookkeeping has the answer: an opening balance, plus the transactions, must equal the closing balance. ADR-0007 already takes the opening balance, a `bpf_iter` process snapshot at every segment open. Nothing takes a closing one.

Can the reader prove, per process, that the tree is complete?

## Decision drivers

1. Locate each lifecycle loss to a process, not just count it (ADR-0006 driver 1).
2. Put the check at the end that knows the whole run, the reader (the end-to-end argument, R-030).
3. Adds no work on the event path.
4. An exact check, not a statistical estimate.

## Considered options

1. **Counters only** (today).
2. **A closing snapshot at END, reconciled by the reader.**
3. **Periodic snapshots** (every N seconds) plus the closing one, reconciled by window.
4. **Capture–recapture estimation** of unseen lifecycle events, from the snapshot and the event stream as two observers.

## Decision outcome

**Chosen option: 2,** with option 3 kept open. It is exact (driver 4), costs one iteration at the end (driver 3), and the reader does it (driver 2). Option 4 is rejected as a number: snapshots only see processes that live long enough to be in one, so the two observers aren't independent and the estimate would be biased.

### Rules

1. **Closing snapshot.**
   - At an orderly stop, after the last drain, p15d takes one more `bpf_iter/task` snapshot, in the same form as ADR-0007's opening one, into the daemon ring, before END.
   - END records whether it was taken. A crash means no closing snapshot, and the reconciliation then reports "not possible", never "complete".
2. **Reconciliation** (the reader, `p15/proctree.py`), with every process keyed by `(tgid, start_ns)` (ADR-0009):
   - **alive at the end:** each process must be in the opening snapshot or have a FORK in the run. Otherwise it is counted `fork_unexplained` and listed with its parent from the snapshot. The snapshot carries the parent's key, so the tree is **repaired** and the repair is labelled;
   - **gone by the end:** each process in the opening snapshot, or with a FORK, that isn't in the closing snapshot must have an EXIT. Otherwise it is counted `exit_unexplained`;
   - **the counters must agree:** the unexplained counts must not exceed the kernel's skips plus the ring losses for those types over the run. A larger count means a loss nothing counted, which is a bug and makes the run INVALID.
3. **Reported:** p15-trace's Trust block and STATS-adjacent output show both counts and the verdict: complete, repaired (with n), or not possible.
4. **With ADR-0020 rule 5** (`self_exec_id` in the records): a gap in a process's exec sequence locates a skipped EXEC the same way. Both are checks done at the reader.

### Consequences

- Good:
  - a lost FORK or EXIT is located to its process. A lost FORK of a process alive at the end is repaired from the snapshot;
  - a loss that no counter caught is detected rather than invisible, which is a check on the counters themselves.
- Bad:
  - one task iteration at stop, small at desktop process counts, to be measured;
  - processes born and gone between two snapshots are outside this check. For them, the counters and rule 4 remain the evidence;
  - a crash leaves no closing snapshot, and that is said.

### Confirmation

1. A unit test with a synthetic run:
   - a FORK removed → `fork_unexplained = 1`, repaired from the snapshot;
   - an EXIT removed → `exit_unexplained = 1`;
   - a count above the counted losses → INVALID.
2. `it_p15d.sh` case 1 (200 children, 0 skips): `fork_unexplained = exit_unexplained = 0`, verdict "complete".
3. Case 3 (forced spine overflow): the unexplained counts are at most the counted losses.

### Falsifier

Reopen if the closing snapshot's cost at the VM's process count is above ADR-0007's per-segment snapshot cost, or if a run with zero counted losses shows unexplained processes. The latter would be a snapshot bug, or an uncounted loss to find.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | ADR-0007 takes a `bpf_iter/task` snapshot at each segment open, with parent identity | DOC | [ADR-0007](0007-wal-segmented-crc-batches-snapshot.md) rule 3 |
| 2 | Provenance capture tools don't verify their own completeness | PDF | Houssel et al. 2026 (R-027) |
| 3 | Checks belong at the end points | PDF | Saltzer, Reed, Clark 1984 (R-030) |
| 4 | Opening balance + transactions = closing balance, checked by reconciliation | INF | bookkeeping practice |
| 5 | Snapshot-based observers can't see processes that are born and die between snapshots | INF | by construction |

## Pros and cons of the options

### 1. Counters only
- Good: nothing to build.
- Bad: how many, never which process.

### 2. Closing snapshot (chosen)
- Good: exact per process, repairs lost FORKs, and checks the counters.
- Bad: one iteration at stop; short-lived processes are out of reach.

### 3. Periodic snapshots
- Good: catches more short-lived processes, and bounds how long an inconsistency can last.
- Bad: an iteration every N s, and reconciliation across windows. Kept open until option 2's cost is measured.

### 4. Capture–recapture
- Good: an estimate of what both observers missed.
- Bad: the observers aren't independent (snapshots favour long-lived processes), so the estimate is biased. It is an estimate, where ADR-0006 wants counts.
