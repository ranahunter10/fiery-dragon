# The canary and the self-check: what ADR-0019 G4.4 left open, and what was built

Dragon, 2026-11-14. Decision 104 (accepted, E-0304) and the research note's I4 (decision waiting 28). ADR-0019 G4.4 fixes the canary's shape: every 10 s a process `fd-canary` (fork, exec of `/bin/true` with a nonce, exit), its FORK, EXEC and EXIT within 1 s, a miss writes a CANARY_MISS record, raises a counter, logs an error and makes the run DEGRADED. This note records the choices the ADR does not make, what each was decided on, and what the result can and cannot see. Journal: E-0308. Grades: SRC read in source, MEAS run by this session (dev container, kernel 6.18, spine only), INF reasoned and not run, OPEN not known.

## 1. Why it is needed (F-05, now shown)

The books prove that every event that entered a hook was accounted for. They say nothing when events stop entering a hook: the program's counters stop with it and every equation still holds. Case 25 of `it_p15d` shows it (MEAS): with the exec program's link closed, the run ends with `invariant 1`, every book closed, and no EXEC is recorded for the rest of the run. Only the canary and the link check notice.

## 2. Choices the ADR leaves open

**a. What "within 1 s" means when the reader is the one that is slow.** The canary's records travel through the rings to the drain, so the drain judges. Three outcomes, not two:

| Verdict | When | Counted | Run |
|---|---|---|---|
| in time | everything wanted was seen at a poll no later than 1 s after the start | `canary_runs` | unchanged |
| LATE | everything was seen, at a poll later than that | `canary_late` | DEGRADED |
| MISS | the deadline has passed, the drain has polled at least 3 times since the start, the last poll found the rings empty, and something is still unseen | `canary_missed` | DEGRADED |

LATE is what the ADR's own confirmation asks for ("a test that a stuck drain raises CANARY_MISS", G4): case 23 holds the drain 1.5 s after every poll and gets one (MEAS: late by about 520 ms). MISS waits for an empty poll so that records still queued are never called missing.

**b. A guest that is not scheduled.** This VM's host stops the guest for seconds to minutes (E-0088, E-0250). To a strict 1 s rule every such stall is a LATE canary and a DEGRADED run with nothing wrong in capture. Built: a poll that comes more than 5 s after the previous one starts the deadline again and counts `canary_stalled`. The cost of this rule is real: a drain stuck for more than 5 s at a time is treated as a stall and not as LATE. Alternatives: (i) no stall rule, the ADR to the letter, with spurious DEGRADED runs on this VM; (ii) the stall rule with LATE reported and not DEGRADED. Recommendation: as built, and the 5 s bound revisited when the target is not this VM (decision waiting 121).

**c. What the canary must cause beyond the ADR's three records** (the maintainer's brief: one open and one transfer). The child opens `/dev/null` and writes one byte before its exec. Wanted, by what is attached:

| Bit | Evidence | Program it proves is running | When wanted |
|---|---|---|---|
| 1, 2, 4 | the canary's FORK, EXEC, EXIT records | the spine's three tracepoints | always |
| 8 | its OPEN record | the path program (fentry) | file identity on |
| 32 | `SESSION_ENTRY` moved since the canary started | the open session | file identity on |
| 64 | `FREE_RUN` moved since then | `security_file_free`'s program | file identity on |
| 16 | its FLOW record | the `vfs_write` session | flow programs attached |

Bits 32 and 64 are run counters, not records, because those two programs write nothing for a clean open of the canary that could be told apart (a CLOSE is written by whichever task drops the last reference). They are system-wide counters: any open or free by any process moves them. That is sound for what is asked, "did this program run at all since the canary's open", because a program that has stopped has stopped for every task.

**Not covered** (decision waiting 122): the rename tracepoint, `security_inode_free`'s program, the three other vfs sessions (read, readv, writev), the two socket tracepoints, and all of NET. Each needs its own act by the canary (a rename, a read, a loopback connect). Recommendation: add a read and a rename next, since both are cheap; NET after the flood design, because a connect every 10 s is traffic a reader must learn to ignore.

**d. The records.** The ADR names CANARY_MISS. Built: CANARY_MISS (type 43), one per failure, with a kind (RECORD, LATE, LINK), the canary's number, pid, wanted and seen masks, lateness, or the link's index and name; and SELF_STATS (type 42) at every stats tick, with the counts. SELF_STATS is there because a record written only on failure cannot tell "no failure" from "the canary is not running": a reader checks that `canary_runs` advances.

**e. The verdict's state.** The ADR says DEGRADED for a canary. The research note's I4 says INVALID for a detached link. The maintainer's brief for this work says DEGRADED for both, and that is what is built. A blind program means records are missing from the run, which is DEGRADED's meaning elsewhere (a lost record); nothing written is wrong, which is what INVALID is for.

**f. On or off by default.** The ADR says every 10 s. Built: `--canary-s`, default 0 (off), as `--flow` was until its matrix passed. With it on, every run longer than the interval has processes named `fd-canary` and their opens in it, p15d's idle cost changes, and any bench or test that counts `/bin/true` runs or all opens exactly must exclude them. Recommendation: run the matrix with `-- --canary-s 10`, then make 10 the default in its own PR (decision waiting 123). The link check has no switch: it is on whenever p15d holds a link.

## 3. The link check, and what I4 assumed

I4 asks that p15d notice "another process detaching p15d's links". On 7.0 no other process can do that through `bpf()` to the link types p15d holds (SRC): `link_detach()` calls `link->ops->detach` and returns `-EOPNOTSUPP` when there is none (`kernel/bpf/syscall.c` L5907 to L5910), and none of `bpf_tracing_link_lops` (L3580), `bpf_raw_tp_link_lops` (L3871), `bpf_perf_link_lops` (L4185) or `bpf_kprobe_multi_link_lops` (`kernel/trace/bpf_trace.c` L2478) has one. The iterator links have no `detach` either (`kernel/bpf/bpf_iter.c` L491 to L497), but they do have `update_prog`: a privileged process that gets a descriptor for one by its id could replace its program, which is why the check compares the program id as well as the link id. A link ends when its last reference goes, and p15d holds that reference in its own descriptor table.

So the check that was built asks what can actually go wrong: p15d's descriptor closed or replaced, by a fault in p15d or by something acting inside its process (ptrace, an injected call). At start p15d records, for every link, the descriptor, the kernel's link id and the program id. At every stats tick the writer asks the kernel about each descriptor again; one that is no longer a link, or names another link or program, is counted once, logged, written as a CANARY_MISS of kind LINK, and the run is DEGRADED. Case 24 replaces a link's descriptor with `/dev/null` and the check names it at the next tick (MEAS).

What the link check cannot see, and the canary can: a program that is still attached and no longer runs. The system-wide switches that do this without touching p15d (`kernel.ftrace_enabled`, the kprobes `enabled` file in debugfs) are known in kind; which of p15d's programs each one silences on 7.0 I have not read or run (OPEN). The canary covers whichever programs it exercises (§2c), whatever the cause.

What neither sees: an attacker who recognises the canary and lets it through (the ADR says so), and p15d being killed (I4's third point, a liveness signal that leaves the host, is not built).

I4's second point, recording other processes' `bpf()` commands at the `security_bpf` hook, is not built either. It is a new program and a new record; it belongs with the threat model (decision waiting 108).

## 4. Decisions waiting

- **121. The stall rule** (§2b): 5 s between polls starts the canary's second again. Recommendation: accept for this VM.
- **122. The canary's coverage** (§2c): add a read and a rename now, NET later. Recommendation: yes, as a follow-up.
- **123. The canary on by default** (§2f): after a matrix with `--canary-s 10`. Recommendation: yes, in its own PR.
- **124. DEGRADED, not INVALID, for a link found gone** (§2e). Recommendation: DEGRADED, as built. This differs from I4's wording.
- **125. I4's premise** (§3): on 7.0 another process cannot detach these links through `bpf()`. Recommendation: reword decision waiting 28 to "p15d checks its own descriptors; the canary checks that programs run", and move "record others' `bpf()` commands" under the threat model.
