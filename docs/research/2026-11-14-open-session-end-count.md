# Opens in flight when the open path's session detaches: where the count lives

Dragon, 2026-11-14. This is decision 113 (accepted, E-0304) carried out. It records one choice the decision left open, and the limits of what was built. Journal: E-0307. Grades: SRC read in source, MEAS run by this session, INF reasoned and not run.

## 1. The fault

The open path's `kprobe.session` on `security_file_open` has the detach fault of the flow programs (E-0303). On 7.0 a call that is inside the function when the session is detached never runs its return handler, because `fprobe_return()` skips a probe that is no longer registered (`kernel/trace/fprobe.c` L485, SRC, E-0302). Its entry was counted and its return never is, so `SESSION_ENTRY = SESSION_RETURN + SESSION_NO_INODE` breaks by one and the run ends INVALID.

The window is short. `security_file_open()` on 7.0 is `call_int_hook(file_open, file)` and nothing else (`security/security.c` L2635 to L2638, SRC), so a task is inside it only for as long as the LSM hooks take, or longer if it is preempted there. No run has shown the book broken this way (OPEN). The fix is the same in kind as the flow programs': shut a gate, wait a grace period, count what is in flight while still attached, then detach.

## 2. The choice: where the count lives

The flow programs count per task, in the task storage slot they already had (`rw_starts`). The open session has no task slot. Three places were possible.

| | Where | Cost added to every open | What it can check |
|---|---|---|---|
| T | a new task-storage slot, as for the flow programs | a `bpf_task_storage_get` at the entry and at the return, and an atomic add at each (INF: the order of the flow fix, whose cost the VM did not resolve from zero, E-0255; but the open path has no slot today, so both lookups are new) | the count is independent of the counters |
| F | **the open-file entry the session already registers and already looks up at both ends** | at the entry, one load of a word it already writes; at the return, one atomic OR on an entry it has just looked up (INF: not measured; the commands are in the PR) | the count is independent of the counters |
| S | no mark: after the gate and the grace period, the remainder `SESSION_ENTRY - SESSION_RETURN - SESSION_NO_INODE - SESSION_GATED` is declared to be the opens in flight (the design note's option B) | nothing | nothing: the book closes by construction, so a lost return can never be seen in it again |

**Built: F.** The session's entry already sets `ST_SESSION_ENTRY` in the entry's `state` word. The return now sets `ST_SESSION_RETURNED` with an atomic OR, and the end's iterator claims every entry that is marked entered, not returned and not yet claimed (`ST_SESSION_CLAIMED`, by compare-and-exchange). The OR returns the old value, so a return that races the iterator either set its mark first (the compare-and-exchange then fails, and the retry sees the mark) or sees the claim and counts `SESSION_RETURNED_AFTER_COUNT`. There is no third outcome and no retry loop on the return's side.

Why F and not T: the open path's cost is a watched figure (its budget per open and close is missed today: decision 39, E-0213), and F adds no lookup. Why not S: it gives up the book.

What F costs that T would not:

1. **The iterator walks the whole open-file map** at the end, once: 65,536 entries by default, up to 4,194,304 by option. Not measured (OPEN). It runs once per run, after the gate.
2. **An open with no open-file entry cannot be marked** (the map was full). It sets the low bit of the session's cookie instead and is counted `SESSION_NOSLOT_ENTRY`, its return `SESSION_NOSLOT_RETURN`. The difference is such opens still in flight, which nothing observes directly: the same limit as the flow fix's slot-less calls.
3. **A return lost during the run is counted at the end only if its file is still open then.** The mark lives in the open-file entry, which the file's free deletes. A lost return on a file since freed is in no count, and the book breaks, as it did before this change. A lost return on a file still open is counted `SESSION_OPEN_AT_END`, and cannot be told from an open in flight. The flow fix has the second half of this limit and not the first.
4. **Stale marks.** If a file's free is not seen (a skipped `security_file_free`) and a new file gets its address and inode, the entry carries the earlier open's marks. The entry clears them and counts `SESSION_REENTERED` (reported, expected 0).

## 3. The book

```
SESSION_ENTRY + SESSION_RETURNED_AFTER_COUNT + SESSION_NOSLOT_RETURN
  = SESSION_RETURN + SESSION_NO_INODE + SESSION_GATED + SESSION_OPEN_AT_END + SESSION_NOSLOT_ENTRY
```

Each kind of call, to show the terms balance (INF, and `test_run.c` for the arithmetic):

| The call | Left | Right |
|---|---|---|
| returned as usual | entry 1 | return 1 |
| a file without an inode | entry 1 | no inode 1 |
| entered after the gate | entry 1 | gated 1 |
| in flight at the count, never returned | entry 1 | open at end 1 |
| in flight at the count, returned before the detach | entry 1, returned after count 1 | return 1, open at end 1 |
| no open-file entry, returned | entry 1, no-slot return 1 | return 1, no-slot entry 1 |
| no open-file entry, never returned | entry 1 | no-slot entry 1 |

`SESSION_CLAIM_RACE` and `SESSION_REENTERED` are reported and are not terms. The second book of the session (what each return did) is unchanged; its failure message now prints every term too.

## 4. What an entry after the gate loses

A gated entry registers nothing and has no return. The path program (the fentry) is not gated: it still registers the file and writes its OPEN. What is not written for an open that begins after the gate is its OPEN_VERDICT (a denial), and the session return's OPEN when the path program was skipped. Each such open is counted `SESSION_GATED`. The window is from the gate to the detach: one grace period, the bounded wait (`--flow-stop-wait-ms`, 200 ms by default, ended early when nothing is in flight), and the two iterators.

## 5. What is tested, and what cannot be

No task can be held inside `security_file_open` from user space: on 7.0 nothing in it waits (§1), and this target has no BPF LSM to make it wait. So cases 16 and 17's method (hold a real call across the detach) does not carry over. Instead:

- **Case 20, `test_open_iter`** (MEAS here, kernel 6.18): the shipped object's iterator, loaded alone, run over eight planted entries. It claims the three in flight, leaves the returned, the already claimed and the never entered, and counts nothing on a second pass.
- **Case 18** (`--test-open-end-mode 1`): for one process, the session's entry marks the open and asks for no return, which is exactly what a detach in flight leaves behind. The end's iterator must count the three opens and the book must close.
- **Case 19** (`--test-open-end-mode 2`, with the pause between the count and the detach): for one process the entry marks the open as already claimed, so its return runs the returned-after-the-count branch; and two opens made during the pause must be gated and still have their OPEN records.

What no test shows: a real open caught in flight by a real detach, and a real return racing the real iterator. The first is the same code path as case 18 from the iterator's side. The second is two atomic operations on one word, argued in §2 and not run under contention (OPEN).

Cases 18 and 19 need `kprobe.session`, so they are CI's and the VM's to run.

## 6. Decisions waiting

- **119. The count's home.** Recommendation: F as built. Evidence: §2. If the VM's `prog_stats` and `open_cost` show the session's cost per open rose by more than the run-to-run spread, the fallback is S for the open path only, which is free and gives up this one book.
- **120. `RETURNED_AFTER_COUNT` for opens is tested by staging, not by timing.** Recommendation: accept; a timed test needs a way to hold a task in an LSM hook, which this target does not have.
