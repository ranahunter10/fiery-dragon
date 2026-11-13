# Calls in flight when the flow programs detach: a design note (Dragon, 2026-11-13)

For decision waiting 23 (E-0246, E-0247). The maintainer decides; no fix is written here.

**How this was established.** By reading only: our code on PR #90 at 7984a97, and Linux at tag v7.0 (028ef9c): `kernel/trace/fprobe.c`, `kernel/trace/fgraph.c`, `kernel/trace/bpf_trace.c`, `kernel/bpf/bpf_task_storage.c`, `kernel/bpf/bpf_local_storage.c`, `kernel/bpf/trampoline.c`, `kernel/sched/membarrier.c`, `kernel/fork.c`. Nothing was run. Every kernel claim is SRC with its line; every cost is INF until `bench/flow_cost` measures it. The other session checks each line before anyone builds on it.

## 1. The fault, from the source

- A kprobe.session is an fprobe with an entry handler and an exit handler (`bpf_trace.c` L2843-2846). Its link's release calls `unregister_fprobe()` (L2382-2387).
- `unregister_fprobe()` removes the probe from the fprobe hash (`fprobe.c` L949 `del_fprobe_hash`, which sets `fph->fp = NULL` and unlinks it, L155-156).
- A call that entered before that still returns through `fprobe_return()`, which runs the exit handler only `if (is_fprobe_still_exist(fp) && !fprobe_disabled(fp))` (L485). For a probe that has been unregistered the test fails, the handler is skipped, and **nothing is counted**: not the probe's `nmissed`, not the program's `recursion_misses`.
- Our entry counted `SESS_ENTRY`; the return never counts `SESS_RETURN`. Book B1 (`SESS_ENTRY = SESS_RETURN + exclusions`) is off by the number of calls open at detach. E-0246 saw exactly that.

So the fault is not a race to be narrowed. It is the kernel's defined behaviour for every call that is inside `vfs_read`, `vfs_write`, `vfs_readv` or `vfs_writev` at detach, and on an ordinary host some task is always blocked in a read.

**Two more ways the same book can break, found while reading** (neither seen in a run):
- **A return skipped while its entry ran.** `kprobe_multi_link_prog_run()` skips the program when another BPF program or a map system call holds `bpf_prog_active` on that CPU (L2571-2575), at the entry or at the return alike. At the entry the session then also skips its return (L2601), so nothing is counted and B1 holds. At the **return**, the entry has already counted: B1 is off by one. This one is counted (`recursion_misses`, our `flow_missed`), but the counter does not say which half was skipped.
- **A session skipped whole and counted nowhere.** `function_graph_enter_regs()` returns early when ftrace's recursion lock is taken (`fgraph.c` L662-664) or the task's 4096-byte shadow stack is full (L592-594, which bumps the task's own `trace_overrun`). fprobe's entry is then never called, and its own comment says the missed counter for this is still to do (`fprobe.c` L413-416). B1 holds, since nothing was counted; but a transfer is unrecorded and no counter that p15d reads moves. STATE's "hooks that are not skipped for other tasks" is true of preemption; it is not "never skipped". Risk, not a known failure: both need a traced function entered from inside a tracing callback, or very deep nesting.

## 2. What any fix can and cannot do

Three facts bound every option.

1. **The kernel will not run the return.** No detach order changes L485. An fsession does not either (§4.1).
2. **So a call open at detach can only be counted, not recorded.** Its bytes, if any moved, are not known: there is no return value.
3. **A count taken at the end cannot tell a call that is still open from a return that was lost earlier.** Both leave one entry without its return. Whatever the design, B1 at the end closes over the sum of the two. What a design can add is *when* and *where*: which tasks, which files, since when, and whether a task that "has a call open" then makes another call.

The third point matters for the choice. STATE's text for option A says B1 becomes "exact". It does, as an equation. It does not become a stronger detector of lost returns than option B at the final check; its gain is elsewhere (§5).

## 3. Option A, examined

As STATE states it: shut a gate so new entries skip their return; wait about 1 s; a task iterator claims each open `rw_starts` slot atomically; a return that finds its slot claimed counts "returned after the count".

### 3.1 The gate and an entry already past it: a wait is not enough

The entry program reads the gate, and some instructions later writes its slot. The program cannot be preempted (`cant_sleep()`, `bpf_trace.c` L2569), but it can be **stopped by the host**: on this VM a vCPU, or the whole guest, is descheduled for seconds to minutes (E-0088, E-0250). An entry that read "gate open" and is frozen before it writes its slot is missed by an iterator that ran after any fixed wait. Its call is then open, counted in `SESS_ENTRY`, and claimed by nobody: B1 breaks by one, on the host where stalls are a measured fact.

**What closes it: an RCU grace period, not a timer.** The program runs inside `rcu_read_lock()` (L2577). After p15d sets the gate, a `synchronize_rcu()` returns only when every program instance that was running has finished, so every entry that saw the gate open has written its slot, and every later one sees it shut. User space can ask for exactly that with no BPF system call: `membarrier(MEMBARRIER_CMD_GLOBAL)` is `synchronize_rcu()` when more than one CPU is online (`membarrier.c` L651-657). It does not touch `bpf_prog_active`, so ADR-0026's rule (no map system call once attached) is kept. It returns `-EINVAL` under `nohz_full` (L653): p15d must treat that as "the count is not exact" and say so in END, not fall back to a sleep silently.

The gate itself is a global in the object's `.bss`, written through the skeleton's mapping: a store to memory, no system call.

The wait keeps a use, as quality and not as correctness: most calls in flight are short and finish in milliseconds, recorded as usual while the programs are still attached. p15d can watch the residual of B1 in the mapped counters and stop waiting when it reaches 0 or a bound passes.

### 3.2 A task that exits or execs between the cut and the detach

- A task cannot exit inside `vfs_read`: a fatal signal makes the call return first, and the return hook runs if still attached. It cannot exec there either: exec is a system call of its own, and the other threads that `de_thread` kills return from their calls before they die. The exception is a kernel oops inside the call, which kills the task without a return: one entry is then never matched, in any design. Stated, not handled.
- Task storage lives until the last reference to the task is dropped (`fork.c` L555, `bpf_task_storage_free` in `__put_task_struct`). The iterator holds a reference to the task it visits, so a claim never touches freed storage.
- **The order matters.** If the count is taken *before* detach (as A says), a task that returns and exits afterwards is handled: its return either ran ("returned after the count") or was skipped by the detach, and the count stands. If the count were taken *after* detach, which would need no claim and no extra term, a blocked reader that is released and reaped between the detach and the iterator takes its slot with it, and B1 breaks. That is likely exactly when p15d stops: at shutdown, when everything is being signalled. So the simpler order is wrong, and A's order is right.

### 3.3 A failed storage creation

`bpf_task_storage_get(..., F_CREATE)` returns NULL when the allocation fails or the storage lock is not obtained (`bpf_task_storage.c`, the `IS_ERR` path of `bpf_local_storage_update`; `bpf_local_storage.c` L82-83, L343 and after). Today that only costs the start time (START_UNKNOWN). Under A the call then has no slot to claim, and if it is open at the end B1 breaks.

Fix inside A: the session's cookie holds the file pointer, whose low bit is free. An entry with no slot sets it and counts `V_NO_SLOT_ENTRY`; its return sees the bit and counts `V_NO_SLOT_RETURN`. The difference is the number of slot-less calls still open, which nothing can observe directly. It goes into B1 as a term defined by subtraction, **for those calls only**, and both counters are 0 unless creation failed. Once a task has its slot, later calls find it without allocating.

### 3.4 Nested calls

One slot holds one call. If a task entered `vfs_write` inside its own `vfs_read`, the inner entry would overwrite the outer's mark, and the outer call, still open at the end, would be counted by nobody. Reading the 7.0 callers, the usual suspects do not nest: overlayfs reaches its backing file through `vfs_iter_*` (design check K5), exec and module loading use `kernel_read`, a page fault inside the copy goes through the address space, not `vfs_read`. No nesting caller was found; none was proved absent.

Fix inside A: the slot holds a **count** of open calls, not a mark. This is the "per-task count of open calls" of the brief, and it is not a separate option: it is what A's slot has to be to survive nesting. It also gives a free detector: an entry that finds its task's count already above 0 is either a nested call or a task whose earlier return was lost. Counted (`V_ENTRY_WHILE_OPEN`), it reports during the run what §2's third point says the end cannot.

### 3.5 Migration

No state in A is per CPU except the counters, and those are summed over rows. A call that enters on one CPU and returns on another finds the same slot, because the slot belongs to the task. No effect. (SRC for the mechanism; the conclusion is INF.)

### 3.6 The claim, so that each open call is counted once

After the barrier no entry writes a slot. Until detach, returns still do, and the iterator runs beside them on another CPU. One word per slot, changed only by compare-and-exchange (the atomic the dry run proved on the target, E-0146): the low half is the count of open calls, the high half the count the iterator has claimed.
- The iterator moves the low half into the high half and adds it to `OPEN_AT_END`.
- A return takes one from the high half if it is above 0, counting `RETURNED_AFTER_COUNT`; else one from the low half.
- Only two actors ever touch one task's word (that task's own return, and the iterator), so a compare-and-exchange fails at most once each. The loop is bounded at three tries; a fourth failure is counted (`V_CLAIM_RACE`, expected 0) and is a term of the book.

### 3.7 The book

```
SESS_ENTRY = SESS_RETURN + V_EXCL_SELF + V_EXCL_KTHREAD + V_OWNED_BY_SOCK
           + V_GATED                                  entries after the gate shut: no return run
           + OPEN_AT_END - RETURNED_AFTER_COUNT       calls the iterator found open, less those that then returned
           + (V_NO_SLOT_ENTRY - V_NO_SLOT_RETURN)     slot-less calls still open; 0 unless creation failed
           + V_CLAIM_RACE                             expected 0
```
Its failure message prints every term (today it prints one).

## 4. The alternatives

### 4.1 An fsession in place of the kprobe.session: the same fault

An fsession's exit half is linked as an fexit of the function's trampoline (`trampoline.c` L821-822). When a trampoline's image is replaced at detach, `bpf_tramp_image_put()` first patches the old image "to avoid calling into fexit progs", jumping from after the original call straight to the epilogue, and says why: "The progs will be freed even if the original function is still executing or sleeping" (L528-530, L545-547). A call in flight returns through the patched image and skips the exit program. Same fault, same lack of a counter. And a trampoline program can be skipped for another task under contention (E-0089), which the session cannot. Not a fix. (Its per-call cost is still worth measuring for other reasons: decision waiting 21 of #91.)

### 4.2 The gate alone, with the programs left attached

Shut the gate, pass the barrier, and wait until every open call has returned. A read blocked on a terminal or an idle socket never returns, so the wait has no bound; and p15d's exit destroys the links whatever it has waited for. With a bound it becomes option B.

### 4.3 Option B: the gate, the barrier, and the remainder by subtraction

`OPEN_AT_END := SESS_ENTRY − SESS_RETURN − exclusions − V_GATED`, reported. No slot, no iterator, **no cost per call**. B1 then closes by definition at the end.

What it gives up, precisely (§2 point 3): not the detection of a lost return at the final check, which A does not have either, but
- any sign **during** the run that a return was lost (A's `V_ENTRY_WHILE_OPEN`);
- **where** the open calls are (A can name each task, its file and since when);
- a second, independent count of the same events, which catches a bug in our own programs' counting (an early return that forgets its counter breaks A's book and not B's);
- exactness under nesting and under a failed creation, which B has for free, having no slot.

### 4.4 Changing the order of detach

It cannot help the sessions (§2 point 1). It does matter for something else: §6.

## 5. Comparison

| | A as STATE has it | **A as examined here** | B |
|---|---|---|---|
| Correct with a vCPU frozen mid-entry | no (a wait) | yes (the RCU barrier) | yes (the barrier) |
| Correct with a nested call | no (one mark) | yes (a count) | yes |
| Correct when storage creation fails | no | yes, by a counted remainder | yes |
| Correct when a task exits after the count | yes | yes | yes |
| A lost return seen during the run | no | yes, at the task's next call | no |
| Each open call located | possible | yes | no |
| Catches a miscount in our own programs | yes | yes | no |
| Added per call | a lookup at every return | an atomic add at entry; a lookup at the returns that have none today (empty, failed, no inode); a compare-and-exchange at every return | nothing |
| New code | gate, iterator, claim | the same, plus the barrier, the count word, the cookie bit | gate, barrier |

**The cost per call (INF).** E-0237 measured option A's two task-storage lookups with their two clock reads at 39.4 ns per read on the VM (320.4 against 281.0 ns). The entry and the successful return already make those lookups. What this adds to them is one atomic add and one compare-and-exchange on a line the task owns; and, for a return that moved nothing, one lookup. The estimate is under 20 ns per successful transfer and under 40 ns per empty or failed return. It is an estimate: a `flow_cost` arm decides (§7).

## 6. The class around it (a first pass at work queue item 2; SRC where a line is given, else OPEN)

| Program | Hook | At detach | At attach | Book that can break |
|---|---|---|---|---|
| `flow_read`, `flow_write`, `flow_readv`, `flow_writev` | kprobe.session | the return of a call in flight is skipped, uncounted (`fprobe.c` L485) | **a call in flight has no entry, so its return does not run: the first transfer of every read that was blocked when p15d started is not recorded and not counted** | B1 at detach; nothing at attach |
| `file_open_session` | kprobe.session on `security_file_open` | the same; the window is the time inside the LSM hooks, which is short but not zero (`security.c`: `call_int_hook(file_open)`) | an open in flight has its OPEN from the fentry only if the fentry attached first | `SESSION_ENTRY = SESSION_RETURN + SESSION_NO_INODE` (`p15_file.h` L9) |
| `file_open` | fentry | none: one run, at entry | none | — |
| `file_free`, `inode_free` | kprobe.multi, entry only | none | a file opened before the attach and freed after it gives `FREE_UNREGISTERED`, counted | — |
| the six network programs | fexit | a `connect` or `accept` in flight returns through the patched image: no record, and no counter was bumped at entry, so no book breaks (`trampoline.c` L528-530, L545-547) | **an `accept` blocked since before the attach entered the function without the trampoline: its return is not recorded.** A server sitting in a blocking `accept` when p15d starts loses its next connection's ACCEPT, uncounted | none: the loss is silent |
| fork (`tp_btf`), exec, exit, rename (classic tracepoints), the two socket tracepoints | one run per event | none | none | — |
| the task and file iterators | on demand | — | — | — |

Three things follow.

1. **The attach side is the mirror of the detach fault, and it is silent.** Nothing can record the return of a call whose entry was not hooked. For sockets the tracepoint fires at the end of the call, so a blocked `recv` is recorded. For a pipe, a terminal or a file read through `vfs_read`, and for a blocked `accept`, the first completion after start is missing. It cannot be fixed by a hook; it can be **declared** (the run's first transfers by tasks that the opening snapshot shows already alive may be missing) and **bounded**: the opening snapshot's task pass could mark each task that is inside one of the hooked functions at that moment. OPEN: whether a task iterator can tell that cheaply.
2. **The open path's session needs the same treatment as B1**, with the same gate and barrier; its window is short, so its count is almost always 0.
3. **The spine detaches first and should detach last** (`daemon/loader.c`, `p15_loader_detach`: `spine_bpf__detach` is the first call). Between that and the last flow program's detach, a FLOW or an OPEN can name a process whose EXIT, or whose FORK, the run no longer records. It attaches first already (`loader.c` L169). This is the same change F-11 made for the socket tracepoints, one level up.

Also, from §1: a return skipped by `bpf_prog_active` breaks B1 and is counted only in a per-program counter that does not say which half was skipped. Under A that call appears in `OPEN_AT_END`, so B1 closes; `flow_missed` above 0 already makes the run DEGRADED. With `flow_missed` at 0, `OPEN_AT_END` is exactly the calls open at the cut; otherwise it is an upper bound on them.

## 7. Recommendation, cost and tests

**Recommendation: option A in the form of §3** (the barrier, a count per task, the cookie bit, the claim word), with the bounded wait kept for quality. The reasons are in §5: it is the only form that is correct under the three conditions this host and this code can produce (a frozen vCPU, a nested call, a failed creation), and beyond B it reports a lost return during the run and names each open call. **If the `flow_cost` arm shows the cost per call above what the maintainer accepts, option B with the same gate and barrier is correct and free**, and what it gives up is listed in §4.3. That choice is the maintainer's, on the measured number.

Whichever is chosen: the spine detaches last (§6 point 3), and the open path's session gets the same book term.

**Cost per call:** INF, under 20 ns per successful transfer and under 40 ns per return that moved nothing (§5). At stop: one `membarrier`, a wait of at most the bound, one pass of a task iterator (the closing snapshot's pass took 0.21 to 0.91 ms for about 165 tasks, E-0107).

**Tests that would prove it** (none written yet):
1. **`it_p15d` case, a call held across detach.** A helper blocks in `read()` on an empty pipe, a second in `write()` to a full pipe, a third in `readv()` on a terminal-like FIFO; p15d runs with `--flow` and stops. Expected: END with the invariant closed; FLOW_STATS' `open_at_end` equal to 3 exactly; `returned_after_count` 0; `v_no_slot_*` 0. Today this case fails B1: that is the gate.
2. **The same with a release in the window.** A test switch pauses p15d between the count and the detach; the helper's pipe is written during the pause. Expected: `returned_after_count` 1, and that read's FLOW is in the WAL.
3. **The barrier.** Not testable by timing. A unit test of the stop sequence with an injected `membarrier` that fails must end with the run marked "count not exact", never with a silent sleep.
4. **Planted bugs** (`mutate_p15d.py`): each new term removed from B1; the gate never shut; the claim without the compare-and-exchange; the cookie bit ignored.
5. **A `flow_cost` arm, `count`:** the session with the count word on every entry and return, against `ts` (today's option A slot) and `session`. Its difference from `ts` is the cost per call; the VM decides.
6. **The VM matrix** on the PR, as CONTRIBUTING §5 asks, with `--flow`: the soak's END must close with `open_at_end` reported and plausible (the soak's own blocked readers).

## 8. Decisions for the maintainer

Numbered as STATE's "Decisions waiting" lists them.

110. **The detach fault's fix.** Options: A as examined in §3; B (§4.3). Recommendation: A in §3's form, built behind the `flow_cost` arm's number; B if that number is refused. Evidence: §5.
111. **`membarrier` as p15d's barrier, and what a failure means.** Recommendation: use `MEMBARRIER_CMD_GLOBAL` after the gate and again after detach before the books are read; on failure the END record says the flow books' end count is not exact and the run is DEGRADED. Evidence: §3.1; `membarrier.c` L651-657.
112. **The spine detaches last.** Recommendation: yes, in the same PR as the fix. Evidence: §6 point 3.
113. **The open path's session gets the same term.** Recommendation: yes, after the flow programs' fix has passed the VM matrix, as STATE's recommendation for 23 already says. Evidence: §6 point 2.
114. **Calls in flight at attach.** Recommendation: declare it in ADR-0005's limits now; a design check of marking such tasks in the opening snapshot later. Evidence: §6 point 1.
115. **Sessions skipped by ftrace and counted nowhere** (§1). Recommendation: read each task's `trace_overrun` is not possible from p15d; so state the limit in STATE's "hooks that are not skipped" line, and ask upstream whether fprobe's TODO has a patch. Evidence: `fgraph.c` L662-664, L592-594; `fprobe.c` L413-416.
