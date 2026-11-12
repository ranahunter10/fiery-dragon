# Why an open+close costs us 897 ns of program bodies, what the published tools do instead, and what to measure next (2026-11-12)

The maintainer's request of 2026-11-12: find where our per-program cost (897 ns per open+close, E-0192) stands against the state-of-the-art tools, read their code and the papers, and change our design where it benefits us. This note answers with what is measured, what the tools' code shows, and a list of candidate changes. Each candidate is graded INF until a harness on the VM measures it. **No design change is taken here.** Grades as in `CONTRIBUTING.md` §5. Sources in `papers.csv`: R-042 (eAudit, full text), R-043 (the tools' kernel-side code, read at pinned commits on 2026-11-11), R-044 (Linux v7.0 run paths), and the code re-read for this note at the same commits (Falco libs 0815626, Tracee 2f9dc40, Tetragon 63332a1).

## 1. Where an open+close's time goes today

| Part | ns | Grade | Source |
|---|---|---|---|
| Hook paths, entering the programs (trivial body on `vfs_read`): fentry 14.2; kprobe.session 141.0, of which its return half about 117; kprobe.multi 20.8 | about 176 for fentry + session + close | MEAS (on `vfs_read`; that the costs carry over to `security_file_open` is INF) | E-0138 |
| Path fentry body | 492.5 | MEAS | E-0192 |
| … `bpf_d_path` 93.7; the ring copy 37.6; header 15.8; claiming a slot 7.6; facts 5.9; object map about 14; open-file map lookup about 13 | about 188 | MEAS | E-0187, E-0192 |
| … the rest, which includes the seven inner brackets' own cost (about 15.7 ns each, about 110) | about 305 | INF | E-0187 ("each whole-program figure also holds its inner brackets' own cost") |
| Session entry: registering the open file (hash insert 93.9) | 139.6 | MEAS | E-0192 |
| Session return | 20.3 | MEAS | E-0192 |
| Close: lookup 12.7, CLOSE record 52.6, delete 46.2 | 244.9 | MEAS | E-0192 |
| **Program bodies, profiled build** | **897.3** | MEAS | E-0192 |
| The open-file map alone: insert 93.9 + three lookups (fentry, return, close, about 38) + delete 46.2 | about 178 | MEAS, sum of sections | E-0187, E-0192 |
| p15d in user space, above idle, per open+close (v1) | 552.1 | MEAS | E-0176 |
| Bytes per open+close in the WAL (OPEN 115.6, CLOSE 56.0) | 171.6 | MEAS | E-0176 |
| Whole pipeline added to the program making the call (v1; v2 not yet run end to end) | 1,396.3 | MEAS | E-0176 |

Two things follow:
- **The 897 ns is a profiled figure.** The brackets add their own cost to every outer section. The unprofiled bodies on the shipped object are measured by `bench/prim_cost/prog_stats.py` with the kernel's statistics. Its v1 figure was 1,139 ns, against 1,201 profiled (E-0184, E-0187). **The budget gate (STATE E-0193) should be judged on that, not on the profiled build.** That is item 1 of §5.
- **The bodies are not the whole cost.** The hook paths (about 176 ns) and p15d (about 550 ns) are outside them. An end-to-end rerun of `bench/open_cost` on today's main gives the number a published comparison would use. That is item 2 of §5.

## 2. What the tools do on the same operation

| Tool, version | Hook for an open | What it reads in the kernel | State kept per file in the kernel | Close | Grade |
|---|---|---|---|---|---|
| Falco modern_bpf, `falcosecurity/libs` at 0815626 | `openat_x`, a program tail-called from one dispatcher on the syscall-exit tracepoint (`driver/modern_bpf/programs/tail_called/events/syscall_dispatched_events/openat.bpf.c`) | the fd, dirfd, the **user's path argument** (relative, read from user memory), flags, mode, and dev and ino through the new fd (`extract__dev_ino_overlay_from_fd`) | none: the fd table lives in user space (libsinsp) | `close_x`: the return value and the fd, nothing else | SRC |
| Tracee at 2f9dc40 | one `kprobe/security_file_open` (`pkg/ebpf/c/tracee.bpf.c` `trace_security_file_open`): **our hook point** | its own dentry walk (`get_path_str`), flags, dev, ino and ctime as the file's identity, the syscall's path argument | none | not at this hook | SRC |
| Tetragon at 63332a1 | generic kprobe/fentry/LSM programs chosen by policy (`bpf/process/bpf_generic_*.c`) | in-kernel selectors decide **before** the expensive work; then a tail-call pipeline (filter, process, args, actions, send, `generic_calls.h`); its own d_path walk (`bpf/lib/bpf_d_path.h` `d_path_local`) | none per file; the process cache is in user space (R-050) | by policy | SRC |
| eAudit (Sekar, Kimm, Aich, S&P 2024) | syscall entry and exit tracepoints only (§3.2) | the syscall's arguments; one combined record at exit for most calls (§3.4) | generic maps with LRU eviction (§3.3) | the call's record | PDF (R-042) |

eAudit's techniques for cost (R-042, §3.3 to §3.7; R-043 for its flush code):
- records of about 17 bytes on average (against sysdig's 175): one byte per event id, the low 3 bytes of the timestamp with a full stamp when the high bytes change (about every 16 ms), integers in 1, 2, 4 or 8 bytes, no tid for single-threaded processes;
- per-CPU caches of 100 records copied into one shared ring, the consumer woken once per 8 ring operations;
- the user side writes the buffers as they are, one `write` per wake-up;
- **agent** cost, its user-space collector's CPU over the benchmark's, 3.1 % on average, median 48 ns per syscall (§4.3). That is the figure to set beside p15d's 552 ns per open+close (two records), not beside our programs' bodies. Its kernel side shows in its wall-clock overhead: 18 % on average, 5.8 % without find, tar and rdwr (§4.4).

## 3. Why we cost more, difference by difference

1. **Two programs on one function, one of them a kprobe.session.** Tracee has one kprobe; Falco one tail call from a shared exit hook. We pay a fentry and a kprobe.session, whose return half alone costs about 117 ns of hook path (E-0138). The session exists for two reasons: the verdict at return, and the non-preemptible fallback that keeps every open when the fentry is skipped (E-0189, ADR-0029).
2. **Identity in the kernel.** No tool keeps a map entry per open file. Falco's fd table, Tetragon's process cache and Tracee's (dev, ino, ctime) all put identity in user space. Our open-file map costs about 178 ns per open+close (§1), and the object map more. They exist because ADR-0015 rule 1 gives ids in the kernel, so that the fentry, the session and the close name one fid.
3. **The path at the LSM point.** Falco reads the user's argument. That is cheap, but it is relative and open to a race (the string can change after the check). Tracee and Tetragon walk dentries as we do. Our `bpf_d_path` costs 94 ns and our walk 233 ns on 8 components (E-0196). **This is a cost we keep**: the kernel's object, not the caller's string, is the point of hooking `security_file_open` (ADR-0015).
4. **Record size.** 171.6 bytes per open+close against eAudit's about 17 bytes per record. Bytes cost in the ring copy (37.6 ns for an OPEN), in the drain, in the WAL and in p15d's 552 ns.
5. **User space.** p15d checks and copies each record (`p15_rec_check`, a batch copy): 552 ns per open+close, about 276 per record (E-0176). eAudit's collector writes raw buffers, one `write` per wake-up (R-042 §3.3), at a median 48 ns per syscall. **This is the largest gap against a published number**, and where p15d's time goes is not measured.
6. **What we pay for on purpose:** an object identity read from the kernel's inode, never from a user string; a path even when the fentry is skipped; never-shed books with a counter on every loss. None of the four tools gives all three.

## 4. Candidate changes (each INF until measured; none decided)

| # | Change | Saves (INF) | Costs, risks | Changes |
|---|---|---|---|---|
| C1 | **One program on `security_file_open`:** kprobe.session only. The return writes the OPEN with the walked path always (ADR-0029's option b, its falsifier 3); no fentry. | the fentry's hook and body (about 506), less what the walk costs over `bpf_d_path` (about 77 to 140 by path length) | the walk instead of the kernel's own `bpf_d_path` for every open (equal in every harness case, E-0196, E-0198; RACED flagged) | ADR-0029, ADR-0015 rule 6 |
| C1b | C1 with kprobe.multi entry only (20.8 ns of hook against 141). The OPEN is written at entry; a denial is known at the close as NEVER_OPENED. | about 120 more | the verdict's errno is lost: a denial and a failed `->open` look alike | as C1, and ADR-0015 rule 5 |
| C2 | **Open-file ids in user space.** OPEN and CLOSE carry the `struct file` address; the reader pairs a CLOSE with the last OPEN of that address. The order is safe: `security_file_free` runs before `kmem_cache_free` (fs/file_table.c v7.0 L69-80), so a CLOSE is reserved before its address can be reused, and the ring keeps reservation order. | the open-file map, about 178 | a CLOSE for every `struct file` freed, including those capture never opened (pipes, sockets, `O_PATH` opens: no `security_file_open`, fs/open.c L900-926). In the hour's soak that is 38.2 % of all frees (497,875 of 1,303,887), so 62 % more CLOSEs (MEAS, [evidence](../evidence/vm/2026-11-12-graph3-and-costs/README.md)). It would pay only if the close can skip them without a map, for instance by the superblock's magic (pipefs, sockfs, anon_inodefs: one more read, INF); `O_PATH` and pre-capture files would still emit | ADR-0015 rule 1 |
| C3 | Compact records (eAudit): a timestamp delta from a per-batch base, no `start_ns` in bulk headers (from the spine instead), variable-size integers | ring copy, drain, WAL and p15d time, in proportion to bytes | bulk records would depend on the spine for the process key; a decoder change and a schema version | ADR-0006, ADR-0009 |
| C4 | p15d: profile where 552 ns per open+close go (per-record callback, check, copy) and batch what can be batched | OPEN until profiled | none before the profile | none |

Not changed by any of these: the object identity from the inode, the books, the snapshot. C1 and C2 together are the two largest items, and they are independent of each other.

## 5. What to measure next, in this order

Results (2026-11-12, [first](../evidence/vm/2026-11-12-graph3-and-costs/README.md), [second](../evidence/vm/2026-11-12-open-cost-v2/README.md)):
- Item 1: the shipped programs cost 741.4 ns per open+close, median of 7 rounds, the kernel statistics' own cost included (path 306.7, free 229.5, session 182.9).
- Item 2: capture adds 1,140.5 ns to an open+close of a known file, against E-0176's 1,396.3, on a host about 20 % slower that day. p15d costs 699.4 ns per open+close above idle, against 552.1, and its idle rate is 1.83 ms per second.
- Item 3: 38.2 % of frees are of files capture never opened.

1. **The shipped object's bodies**, unprofiled: `bench/prim_cost/prog_stats.py` on today's main (commands in the session). This tells whether the 500 ns budget (E-0193) is missed by 400 ns or by less.
2. **The whole pipeline end to end**, `bench/open_cost` on today's main: v2 of the open path, the walk fallback and the adaptive poll, all since E-0176.
3. **How many frees are unregistered** in the hour's soak: `free_run`, `free_unregistered`, `close_emitted`, `inode_free_run` and `session_entry` from its last FILE_STATS. This sizes C2's extra CLOSEs.
4. Then a harness, `bench/open_variants`: C1, C1b and C2 built from `file.bpf.c` with -D flags, as `P15_PROFILE` is today (the shipped object unchanged, checked instruction for instruction). Each variant is loaded only by the harness, timed by bpf_stats and by the thread's CPU per open+close (hook paths included), with paired rounds and an A/A arm, and books per variant. A new ADR is then chosen on its numbers.
