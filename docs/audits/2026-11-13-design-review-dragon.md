# Design review: where the capture layer falls short of its own goal (Dragon, 2026-11-13)

The maintainer's brief: review the existing design before more is built on it, and say with evidence where it falls short of **complete, exact, robust provenance capture that an attacker on the host cannot easily blind, and a graph that answers "what caused this and what did it affect"**.

**This is a first pass, and it is not complete.** §7 lists what was read and what was not. Nothing here was run: every finding is from reading our code (`main` at edc9fde, PR #90 at 07cfb50, PR #91 at 7b8d400) and the kernel at tag v7.0 (028ef9c), plus arithmetic on numbers already in the journal. Where a finding needs a run to become a result, §6 gives the maintainer the commands. Grades as in `CONTRIBUTING.md` §5. The other session checks each finding against the code before anyone acts on it.

Three kinds of finding:
- **defect:** a concrete failure scenario exists (stated; "not run" where it has not been reproduced);
- **shortcoming:** a goal of the design is not met, with no failure of the code as written;
- **risk:** suspected, without a scenario yet.

## 1. Findings, ranked by severity × likelihood

| # | Kind | Finding | Grade |
|---|---|---|---|
| F-01 | defect, not run | One unprivileged process doing small reads or writes can fill the bulk ring, and the ring is shared: other processes' OPEN, CLOSE and NET records are lost with its FLOWs | INF from MEAS |
| F-02 | defect, not run | A WAL write error ends p15d (`P15_EXIT_IO`). The WAL has no size cap, no reserve and no retention, and nothing restarts p15d: a full disk ends capture, and F-01's flood fills a disk at the disk's own speed | SRC |
| F-03 | defect, run by the other session | Calls in flight at detach break book B1 (E-0246, E-0247); the same class may exist in every entry/return pair | MEAS (theirs), risk for the rest |
| F-04 | defect, not run | The open-file map (65,536 entries by default) can be filled by one unprivileged process; every other process's new open files then go unregistered, and the run stays RUNNING | SRC sizes, INF effect |
| F-05 | shortcoming | The canary of ADR-0019 G4.4 (accepted) is not built: after the load-time self-tests, nothing checks that the programs are still attached and recording | SRC |
| F-06 | shortcoming | Data paths that pass no hook and are in no step's plan: AIO, reflink and dedupe ioctls, fallocate, POSIX and SysV message queues, SysV shared memory, unconnected UDP's destination | SRC |
| F-07 | shortcoming | Three gates can pass while their property fails: `flow_cost` times a model of the read program, not the shipped one; the books cannot see an event that reached no hook; the soak measures recall only | SRC |
| F-08 | shortcoming | The graph: a socket is two nodes and an open is an edge whatever its access (both raised in #91); nodes have no versions; the process node is the whole process; the export omits FLOW | SRC |
| F-09 | shortcoming | Two processes that share an address space (`CLONE_VM` without `CLONE_THREAD`, and every `vfork`/`posix_spawn` child until its exec) are two nodes joined by one parent → child edge; FORK records neither the clone flags nor whether the address space is shared (`schema/records.toml`, FORK's fields) | SRC |
| F-10 | shortcoming | "Cannot easily blind" has no stated boundary: ADR-0013 (threat model) is not written, and the WAL is not tamper-evident | SRC |
| F-11 | defect, small | At attach, the four vfs sessions attach before the two socket tracepoints: a socket `read()`/`write()` in between is counted `owned_by_sock` and recorded by nobody | SRC |
| F-12 | shortcoming | A path is relative to the opening task's root, and no record carries the mount namespace: two containers' `/etc/passwd` have one label (their identities stay apart) | SRC |
| F-13 | risk | A stale open-file entry survives a missed free when the reused `struct file` has the same inode: two opens, one `fid` | INF |
| F-14 | risk | Kernel threads are excluded by rule, so a file changed by `nfsd` or `ksmbd` for a remote client has no writer in the graph | INF |
| F-15 | risk | The remaining entry/return pairs and the task iterators at attach and detach (work queue item 2) | OPEN |

## 2. The top five, in depth

### F-01. A flood by one process blinds the bulk ring for everyone

- **Where.** One ring, `bulk_rb`, 4 MiB by default (`bpf/progs/file.bpf.c` L44; `daemon/config.c` L26 `--bulk-ring-kb` 4096). `net.bpf.c`'s ring is the same map (`daemon/loader.c` L140 `bpf_map__reuse_fd`). OPEN, OPEN_VERDICT, BACKING, CLOSE, FILE, FD, NET and FLOW all reserve from it. SRC.
- **The arithmetic** (INF, from MEAS):
  - a traced one-byte read costs 289.8 ns untraced plus 426.4 ns with option A and the record (E-0237, on a bench body that does less than the shipped program: F-07), so one CPU makes about 1.4 million reads a second;
  - each is a 96-byte FLOW: about 134 MB a second into the WAL;
  - the VM's disk gave 63.7 MB a second at its minimum (STATE, P5);
  - so one thread out-produces the disk about twofold. The queue fills, the drain waits (ADR-0017's back-pressure), and the 4 MiB ring fills in well under a second. From then on about half of all reservations fail, **for every record type in the ring.**
- **The failure.** An unprivileged user runs `dd if=/dev/zero of=/dev/null bs=1`. Its own FLOWs are lost, counted in `flow_lost`. So are other processes' OPENs (`open_lost`) and NET records, at the same rate. The run goes DEGRADED, which is correct and visible. But the attacker's own later opens and connects are among the records lost: **the flood is cover for the steps that follow it.** The spine (exec, exit) survives on its own ring.
- **What does not prevent it.** Folding (step 2c) folds a run of reads on one open file; a flood that alternates a read and a write on a pipe never folds (ADR-0005 "Consequences" says so). The process is not a kernel thread and not p15d, so no exclusion applies. No rule filters by who floods (ADR-0005 driver 3: no policy in the kernel).
- **How to verify.** §6, run V-1. Success for the finding: `flow_lost` and `open_lost` both above 0 while the flood runs.
- **Smallest fixes, and their costs.** They can be combined.
  1. **FLOW on a ring of its own.** Identity and intent (OPEN, CLOSE, FILE, FD, BACKING, NET) keep the bulk ring; a flood then sheds only FLOWs. Cost: a third ring map and its drain path (the drain already routes by type), a new ADR superseding ADR-0006 rule 1 in part, and the rings' sizes swept. It does not stop the loss of other processes' FLOWs.
  2. **Name the flooder.** On a failed FLOW reservation, count the loss per process in a small map, and write the top entries with FLOW_STATS. A DEGRADED run then says who caused it. Cost: one map update on the loss path only; a schema field.
  3. **A coarse record under flood.** Beyond a per-task rate, a task's transfers on an open file are summed into one record per sweep, flagged COARSE: existence, bytes and the interval are kept, interleaving is not. That keeps every edge at the price of exactness for the flooder alone. Cost: it departs from ADR-0005 driver 1 for flagged records, so it needs an ADR and the folding tests extended.
  4. **Per-CPU staging** (decision waiting 6) raises the ceiling; it does not change who is shed.
- The ceiling gate (work queue item 8) should include this case by design: a flood by one process while a second process does known opens and connects, with the second process's recall as the result.

### F-02. A full disk, or any write error, ends capture

- **Where.** `daemon/writer.c` L218-225: a failed `p15w_append` calls `p15_fail(run, P15_EXIT_IO, "WAL append failed")`; L582 the same for rotate and `fdatasync`. `daemon/wal.c` has no check of free space, and `daemon/config.c` has no option for a size cap or retention. ADR-0007 has no rule for a full disk (no line of it says "full", "space" or "retention"). The repository has no service unit. SRC.
- **The failure.** (a) An ordinary host: the soak's WAL grew 184 MiB an hour without FLOW (the capture review §3; E-0202, E-0203); with FLOW it grows faster by an amount not yet measured; nothing ever deletes a segment, so the disk fills in time and p15d exits. (b) An attacker: F-01's flood writes at the disk's speed, about 63.7 MB a second on the VM, 229 GB an hour; or any user who can write to the WAL's filesystem fills it directly. p15d exits with an error; the host then runs uncaptured until someone restarts it. The exit is loud (an exit code, a log line, no END in the WAL), which is right. What is missing is what happens next.
- **How to verify.** §6, run V-2.
- **Options, and their costs.** This is a policy the maintainer sets; the code needs one of them.
  1. **A reserve.** p15d watches the free space of the WAL's filesystem; below a mark it stops writing FLOW (counted, the run DEGRADED, a record saying so) and keeps the spine and identity until a second mark. Cost: a `statvfs` per tick, two options, a record type.
  2. **Retention.** A size cap; the oldest segments are deleted, each deletion written as a record. Cost: audit data is destroyed by design, so it needs an ADR; simple to build.
  3. **Exit as today, under a supervisor.** A unit that restarts p15d, and the next run's first record names the previous run's end and the time not captured. Cost: least code; the outage still happens.
  - In every case: the runbook states that the WAL's filesystem must not be writable by other users.

### F-03. Calls in flight at detach (known), and the class around it

The other session found and explained this (E-0246, E-0247): on 7.0 `unregister_fprobe()` makes `fprobe_return()` skip the exit handler of calls that had already entered, so a read blocked at detach has an entry and no return, and B1 breaks. It is decision waiting 23 and the first item of the work queue; its design note is the next thing this session's successor writes (§8).

What this review adds, all OPEN until read against `kernel/trace/fprobe.c`:
- the same applies to the kprobe.session on `security_file_open` (its return writes the verdict), with the file books in place of B1;
- at **attach** the pair is safe by construction (a call that entered before the attach has no entry and no return), but the books' first interval should say so;
- the order of detach matters to more than B1: the spine detaches first (`daemon/loader.c` L304), so a FLOW written in the last moments can name a process whose EXIT the run no longer records.

### F-04. One process can exhaust the open-file map for everyone

- **Where.** `files` has `P15_FILE_MAP_DEFAULT` 65,536 entries (`bpf/include/p15_file.h` L92), one per open `struct file` that capture has seen; `objs` has 131,072 (L93). When `files` is full, an open or a first transfer is written with a fresh, unregistered id (`file.bpf.c` L309; `p15_file.h` L54), counted `file_map_full`. SRC.
- **The failure.** A process's descriptor limit is its own; the hard limit on current distributions is well above 65,536 (INF: the VM's `ulimit -Hn` says, V-3). One unprivileged process opens `/dev/null` 70,000 times and sleeps. From then on every other process's new open file has no entry: its CLOSE cannot be paired, each of its transfers is UNREGISTERED and carries the object's facts inline (a larger record, which feeds F-01), and in the graph each transfer names an open file of its own. Nothing is lost and everything is counted, but the run stays RUNNING, and identity by open file, which ADR-0015 rule 1 and folding's key (ADR-0005 rule 4) rest on, is gone for the whole host.
- **How to verify.** §6, run V-3.
- **Options.** (1) Size the map from the host (`fs.file-max`, or the snapshot's count plus headroom) at load, and say so in the header: cost, memory. (2) Make it a state: `file_map_full` above 0 moves the run to DEGRADED, as a loss does. (3) Name the holder, as F-01 option 2. An LRU map is not an option: it evicts silently.

### F-05. Nothing checks that capture is still alive

- **Where.** ADR-0019 G4.4, accepted 2026-10-25, L106-111: every 10 s a canary process is forked, executed and reaped; its FORK, EXEC and EXIT must arrive within 1 s; a miss writes CANARY_MISS and makes the run DEGRADED. No source file implements it: `grep -ril canary daemon bpf/progs python/p15` gives only `daemon/exitcodes.h`. p15d reads each program's `recursion_misses` (`daemon/drain.c` L144) and never asks whether a link is still attached. SRC.
- **Why it matters.** The books are sums of what the programs counted. If a program stops running (its link is detached, a tracepoint is disabled, a kernel fault), its counters stop, and every book still closes: seen equals emitted equals drained. The run ends RUNNING with invariant 1. The books prove that what entered a hook was accounted for; they cannot prove that events still enter the hooks. The ADR names this ("silent blindness, a stuck pipeline or detached programs"). How an attacker with root would do it is not explored here; that belongs to ADR-0013 (F-10).
- **Fix.** Build G4.4 as accepted, extended with one open and one transfer when those programs are on, since the ADR predates them. Cost: one short process every 10 s; a record type; an `it_p15d` case that detaches a link by a test switch and expects DEGRADED.

## 3. Coverage: every path checked against v7.0 (question 1)

| Path | Kernel (v7.0) | Seen today (with #90) | Planned | Hook that would see it |
|---|---|---|---|---|
| `read`, `pread64`, `write`, `pwrite64` | `fs/read_write.c` L717, L740, L765, L795 → `vfs_read`/`vfs_write` | yes | — | — |
| `readv`, `preadv*`, `writev`, `pwritev*` | L1082, L1105, L1134, L1155 → `vfs_readv`/`vfs_writev` | yes | — | — |
| socket send and receive, any call | `net/socket.c` L732, L1082: the two tracepoints | yes | — | — |
| **AIO** (`io_submit`) | `fs/aio.c` L1594-1602, L1622-1633 call `f_op->read_iter`/`write_iter` directly | **no** | **in no step** (named once, `kernel-v7.0.md` L88) | `aio_read`/`aio_write`, or the iocb completion; a socket through AIO does reach the tracepoints |
| io_uring read and write | `io_uring/rw.c` L834-837, L1173-1176 | no | 2e | `io_uring_complete` (ADR-0005 rule 11) |
| splice, sendfile, tee, vmsplice, copy_file_range | — | no (a send inside splice is written as SEND, decision 47.4) | 2d | their own records |
| **reflink and dedupe** (`FICLONE`, `FICLONERANGE`, `FIDEDUPERANGE`) | `fs/ioctl.c` L239 `vfs_clone_file_range`, L442 `vfs_dedupe_file_range` | **no** | **in no step** | `vfs_clone_file_range`; on btrfs and xfs this copies a file's contents with no read and no write |
| **fallocate** (punch hole, zero range, collapse) | `fs/open.c` L252 `vfs_fallocate` | **no** | **in no step** (2d names truncate) | `vfs_fallocate`: it changes contents |
| mmap, loads and stores | — | no | 2d, at map time; per-access declared out of scope | — |
| **POSIX message queues** | `ipc/mqueue.c` L1233 `mq_timedsend`: its own system call, no `vfs_write` | **no** | **in no step** | `do_mq_timedsend`/`do_mq_timedreceive` |
| **SysV message queues and shared memory** | `ipc/msg.c` L971 `msgsnd`; `shmat` | **no** | **in no step** | `do_msgsnd`/`do_msgrcv`; `security_shm_shmat` |
| `process_vm_readv`/`writev`, ptrace | `mm/process_vm_access.c` L292, L299 | no | slice D | — |
| `/proc/PID/mem` | `fs/proc/base.c` L899 `mem_rw` behind the file's `write` | **as a WRITE into a procfs file**, not into the process | slice D | until then the edge points at the wrong node |
| **Unconnected UDP** (`sendto` with an address) | — | the SEND's bytes, **no destination**: FLOW has no address and NET has no record without `connect` | ADR-0004 L98 says "SOCK_FLOW, Phase 3"; FLOW as built has no field for it | the address at `udp_sendmsg`, or `msg_name` at the tracepoint's caller |
| Kernel threads (`nfsd`, `ksmbd`, writeback) | — | excluded by rule (ADR-0005 rule 1) | declared | F-14 |
| ioctl-carried data (`TIOCSTI`, device ioctls), signals, futexes | — | no | undeclared | list them in ADR-0005 rule 11's out-of-scope row, or hook `TIOCSTI` |

**The shortcoming (F-06)** is not that these are unhooked; it is that six of them are in no plan and in no declared limit, so the claim "complete" has no list to be checked against. The smallest fix is a table like this one in an ADR (a successor to ADR-0005 rule 11), each row either planned in a step or declared out of scope with its reason, and a self-test or soak step per planned row.

## 4. The other questions, briefly

**Identity (question 2).**
- Process: (tgid, leader's start time) is exact, and an exec by a non-leader thread keeps it (the kernel copies the leader's start time; not re-read here: INF). F-09 is the gap: shared address spaces.
- File: the trust table (ADR-0015 rule 3) keeps two files apart on filesystems whose (dev, ino, generation) is not reliable, at the price of one file becoming several nodes when its inode leaves the cache and returns (counted as `n_objs`). That is the right side to err on.
- Path: a label, relative to the opener's root (`bpf/include/p15_dpath.h` L9), with no mount-namespace id beside it (F-12). After a rename the node keeps its first path until 2d's RENAME records.
- Socket: the cookie is exact; the two-node split is G1 of #91's note.

**Accounting (question 3).** Not audited book by book in this pass (§7). What was found: F-03, F-05 (books close when a program stops), F-11. CPU hotplug is covered: rows are sized by possible CPUs (`daemon/loader.c` L113). Counters are 64-bit.

**Robustness (question 4).** F-01, F-02, F-04, F-05, F-10. A kill of p15d: the WAL ends without END and loses at most the durability window (ADR-0007), which is by design; the time until a restart is uncaptured and unrecorded (F-02 option 3). The VM stall: decision 24's stop watchdog counts observations, not seconds, which is right for a frozen guest; the soak's blindness to a stall is the other session's decision waiting 26.

**The graph (question 5).**
- The interval rule in #91 is BackTracker's as written, and events are its t0 = t1 case.
- **Folding and intervals:** Xu's condition (no flow into the object and none out of the process inside the window) is what makes one edge over [first, last] equal to its events for a walk that starts outside the window. For a point of interest **inside** an aggregate's window, the folded edge gives the object the threshold min(thr, last) where the events give the end of the last read before thr; the two agree only because nothing flowed into the object in between. So 2c's property test must draw points of interest inside windows, not only at events, and must cover the socket and io_uring instants, where ADR-0005 rule 5 is knowingly looser.
- Versions: none yet. The threshold rule does not need them; FD (ADR-0005 rule 14) and a CDM-style export do.
- Granularity: one node per process. A long-lived server's every request depends on every earlier one. The field's answers (execution units) need instrumentation we do not have; say so in the limits.
- The export: omits FLOW until its rule is decided (#91), so today it is faithful to opens only.

**Measurement (question 6): F-07.**
- `bench/flow_cost/flow_cost.bpf.c` builds its FLOW with one ring reservation (L103-131) and no identity work. The shipped `emit_flow` also reads the inode's facts, looks up two hash maps and bumps at least four atomic counters per transfer. E-0237's 426.4 ns is therefore a floor for the shipped program, and criterion P2's per-read figure should come from `bench/prim_cost/prog_stats.py` on the shipped object, as the open path's did (E-0213).
- The books are a consistency check of what the hooks counted. A path in §3's table that reaches no hook, or F-05's stopped program, leaves every book closed. Only ground truth from outside the hooks can show those, which is the soak.
- The soak checks recall ("at least n" for execs and connects, exact paths for opens). Criterion F3, precision, has no harness: an extra, wrong edge passes.
- `it_p15d.sh` case 13 runs one process. It cannot show cross-task effects (skips under contention, the FILE-before-FLOW race, two threads on one descriptor).
- `daemon/tests/mutate_p15d.py` has no mutant in `file.bpf.c`'s flow programs (none of its entries names them): the kernel side of 2b has no mutation gate yet.

## 5. What is sound

Stated so the list above is read in proportion. These hold under this review: the spine on its own ring and never shed; identity taken from kernel objects, never from a caller's string; loss counted per cause and located by GAP; back-pressure to the ring instead of a drop in the daemon; the exact TCP join by initial sequence number; the snapshot and its reconciliation; one schema generating every layout; a decoder with no defaults. None of the findings asks for any of these to be redone.

## 6. Runs for the maintainer (each confirms or refutes a finding; none is needed to merge this PR)

All on the VM, the tree built from PR #90's head. V-1 and V-3 keep the WAL on disk (not `/tmp`, which is a tmpfs); V-2 uses a small tmpfs on purpose. Success means the finding is confirmed; the opposite result refutes it and is as useful.

**V-1 (F-01).** In one tmux pane:
```
mkdir -p ~/v1 && sudo build/p15d --flow --wal-dir ~/v1 --duration 30 --stats-ms 1000
```
In a second pane, as the ordinary user, within those 30 s:
```
dd if=/dev/zero of=/dev/null bs=1 count=30000000
```
Then (p15w-inspect has no text form of FLOW_STATS, so the reader prints the last of each):
```
PYTHONPATH=python ~/p15venv/bin/python -c "
import sys, pathlib
from p15 import wal
recs = list(wal.read_run(pathlib.Path(sys.argv[1])).ring_records(2))
for n in ('FLOW_STATS', 'FILE_STATS', 'NET_STATS'):
    last = [x for x in recs if x.name == n][-1].f
    print(n, {k: v for k, v in last.items() if 'lost' in k or 'emitted' in k or 'full' in k})
" ~/v1/*/
```
Confirmed if `flow_lost` and `open_lost` are both above 0. Please keep the whole output: the rates matter as much as the verdict.

**V-2 (F-02).**
```
sudo mkdir -p /mnt/p15small && sudo mount -t tmpfs -o size=8m none /mnt/p15small
```
```
sudo build/p15d --flow --wal-dir /mnt/p15small --duration 120; echo "exit $?"
```
While it runs, in a second pane: `dd if=/dev/zero of=/dev/null bs=1 count=5000000`. Confirmed if p15d exits before 120 s with "WAL append failed". Afterwards: `sudo umount /mnt/p15small`.

**V-3 (F-04).**
```
ulimit -Hn
```
If that prints less than 70000, the finding is refuted for this host as configured; stop there. Otherwise, with `sudo build/p15d --wal-dir ~/v3 --duration 40 --stats-ms 1000` running in one pane, in a second:
```
bash -c 'ulimit -n 100000; python3 -c "import os,time; f=[os.open(\"/dev/null\",0) for _ in range(70000)]; time.sleep(20)"'
```
and, while that sleeps, `cat /etc/hostname` a few times in a third. Then `build/p15w-inspect -v ~/v3/*/ | grep -E "FILE_STATS|END" | tail -2`. Confirmed if the first number of `map_full=` is above 0 and END says state 0.

## 7. What this pass read, and what it did not

Read in full: `CLAUDE.md`, `CONTRIBUTING.md`, STATE's next step and decisions waiting, ADR-0005, the 2026-11-12 capture review, three research notes (state of the art, user-space pipelines, the graph and DuckDB), `graph.sql`, `track.py`, `raw.py`, PR #90's flow programs as first pushed, `p15_flow.h`, the writer's flow books. Read in part, by search: the other ADRs (titles, and the lines a search for each topic found), `loader.c`, `wal.c`, `drain.c`, `file.bpf.c`'s open path, the schema. Kernel v7.0: the files and lines cited.

**Not done, and owed:**
- every ADR read end to end (0001 to 0031);
- each book checked term by term, and every early return in `spine.bpf.c`, `net.bpf.c`, `snap.bpf.c` and the open path;
- commit 3c3adc5's version of the flow programs (this review read the version before it);
- `kernel/trace/fprobe.c` for F-03;
- the WAL format against a crash at each byte offset;
- the reader's reconciliation and the process tree.

A review by this model of #90 found four defects and missed a fifth that was on a line it had read. The same can be true here: a finding's absence from this list is not evidence of soundness.

## 8. Decisions for the maintainer

Numbered from 101, as STATE's "Decisions waiting" lists them.

101. **F-01, the shared ring.** Options: FLOW on its own ring; name the flooder; a coarse record under flood; wait for the ceiling gate. Recommendation: run V-1 first; if confirmed, a design note for the first two together, and the ceiling gate designed to include a flood beside a victim process. Evidence: §2 F-01.
102. **F-02, the disk.** Options: a reserve that sheds FLOW first; retention; exit under a supervisor. Recommendation: the reserve and the supervisor, by a new ADR beside ADR-0007; retention only if the maintainer accepts deleting audit data. Evidence: §2 F-02.
103. **F-04, the open-file map.** Recommendation: size it from the host at load, and make `file_map_full` a DEGRADED state. Evidence: §2 F-04.
104. **F-05, the canary.** Recommendation: build ADR-0019 G4.4 as accepted, extended to an open and a transfer. It is already decided; the decision here is only its place in the order. Evidence: §2 F-05.
105. **F-06, the coverage table.** Recommendation: adopt §3's table into an ADR, each row planned or declared out of scope; AIO and the reflink ioctls into 2d or 2e. Evidence: §3.
106. **F-07, the read path's cost on the shipped program.** Recommendation: `prog_stats.py` on the shipped object with `--flow`, before criterion P2's per-read figure is set. Evidence: §4.
107. **F-09, shared address spaces.** Recommendation: FORK version 2 says whether the child shares the parent's address space (`child->mm == parent->mm`, readable at the fork tracepoint: INF, not tried), and the graph adds a child → parent edge for `CLONE_VM` until the child's exec. Evidence: §1.
108. **F-10, the threat model.** Recommendation: write ADR-0013 before the ceiling gate, since F-01, F-02, F-04 and F-05 each need its boundary: which attacker (unprivileged, root), and what "blind" means (lose records unseen, or lose them counted).
109. **The order.** Recommendation: the detach fault (queue item 1) stays first; then V-1 to V-3; then 101 to 104 by what the runs show.
