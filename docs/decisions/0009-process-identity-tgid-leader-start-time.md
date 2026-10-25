---
status: accepted
date: 2026-10-25
owner: Ashish Rana
consulted: [capture blueprint v1 §4.3 (task_key proposal), Linux v7.0 source (tag v7.0, 028ef9c), P2 evidence]
supersedes: none
---

# 0009: Identify a process by (boot id, tgid, the thread-group leader's start_boottime)

**Scope:** process and thread identity, which the Phase-1 spine needs. File identity and network-endpoint identity (the rest of the planned ADR-0009) are separate ADRs, written when Phases 2 and 3 start; the planned list is updated accordingly.

## Context and problem statement

Every record names the process that caused it. A pid alone is reused, so a graph built on pids merges unrelated processes. v3.7 had identity bugs of the same family: endpoint identity without the transport merged UDP with TCP (blueprint L4).

The blueprint proposed a counter-based `task_key` kept in task local storage. Phase 0 found that the kernel already keeps a value that does the job.

**Question:** what key identifies a process, uniquely and stably, in every record, including across `exec`?

## Decision drivers

1. **Unique** for the lifetime of a boot, and across boots when paired with the boot id.
2. **Stable across exec**, including exec from a non-leader thread, which replaces the leader's `task_struct`.
3. **Reconstructible** for processes that existed before the daemon started (snapshot), and checkable against `/proc`.
4. Cheap: no map write per fork, no extra hook.
5. Correct inside pid namespaces (containers).

## Considered options

1. **Kernel-native key:** `(boot_id, tgid, start_ns)`, with `start_ns = task->group_leader->start_boottime`
2. Counter `task_key` assigned at fork/exec and kept in task local storage (blueprint v1 §4.3)
3. `(pid, /proc/<pid>/stat starttime)`, read from userspace

## Decision outcome

**Chosen option:** option 1, because the kernel itself guarantees driver 2 (source below) and it needs no state of our own (drivers 3 and 4). Option 2 must assign keys to pre-existing processes after the fact. It needs a map write on every fork, and the key can't be recomputed from anything but our own records.

**Definitions:**
- **Process** = `(boot_id, tgid, start_ns)`, where `tgid` is the init-namespace thread-group id and `start_ns` = `group_leader->start_boottime` (ns since boot, including suspend).
  - `boot_id` is not in every record. It is in the WAL segment header (ADR-0007), so a record's process key is `(tgid, start_ns)` within its segment.
- **Thread** = `(tid, task->start_boottime)`, used where a record must name one thread.
  - Caveat: after a non-leader exec, the surviving thread takes the leader's start time (rule below), so the post-exec thread identity equals the process identity. That is intended.
- **Program image** = the process plus the EXEC record that started the image. A process that execs three times has one process key and three images.

**Why it is stable across exec** (SRC, `fs/exec.c` lines 963–974, v7.0): in `de_thread`, a non-leader thread that execs takes over the leader's pid *and* its birth time:

```c
tsk->start_time = leader->start_time;
tsk->start_boottime = leader->start_boottime;
```

So `(tgid, group_leader->start_boottime)` is the same before and after every exec. In the leader-exec case nothing changes at all.

**Why it is unique within a boot** (INF from source):
- `start_boottime` is set once at fork from the monotonic boot clock (`kernel/fork.c` line 2363).
- A tgid can be reused only after its previous process has been reaped, and a later fork reads a later clock value.
- Two processes alive at once can't share a tgid.

**Record header consequence:** the common header (ADR-0008) carries `tgid`, `tid` and `start_ns` (u64). This replaces the blueprint's `task_key`, at the same size.

### Consequences

- Good: no per-fork state and no lazy assignment. Every record is self-identifying from fields the BPF program reads with one CO-RE read.
- Good: pre-existing processes get exactly the same key from a `bpf_iter/task` snapshot at start (ADR-0007), with no race.
- Good: `/proc/<pid>/stat` field 22 is `start_boottime` in clock ticks (`fs/proc/array.c` line 581), so a userspace cross-check is possible at tick resolution.
- Good: containers. BPF reads the init-namespace tgid, so pid-namespace reuse inside containers doesn't alias.
- Bad: 12 bytes (`tgid` + `start_ns`) instead of the blueprint's 8-byte counter; the header already has `tgid`, so the net cost is the same as `task_key`.
- Bad: correctness rests on kernel internals (`group_leader`, `start_boottime`). A rename fails CO-RE relocation loudly at load.

### Confirmation

- **L4 test (Phase 1):** a process forks; a thread execs; the parent execs twice. Every spine record of that process must carry the same `(tgid, start_ns)`, and the thread's exec must not create a new process key.
- **L4 test:** for live processes, `start_ns` in the snapshot equals `/proc/<pid>/stat` field 22 × (10⁹ / `CLK_TCK`) within one tick.
- **Property test** in the analysis tier: no two EXIT records with `group_dead` for the same `(tgid, start_ns)`.

### Falsifier

Reopen if:
- an L4 test finds two different processes with the same `(tgid, start_ns)` in one boot;
- a non-leader exec changes `start_ns`;
- a kernel update renames or moves `start_boottime` or `group_leader`.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | A non-leader exec copies the leader's `start_time` and `start_boottime` into the surviving thread | SRC | [`fs/exec.c` lines 963–974, v7.0](https://github.com/torvalds/linux/blob/v7.0/fs/exec.c#L973) |
| 2 | `start_boottime` is set at fork from `ktime_get_boottime_ns()` | SRC | [`kernel/fork.c` line 2363, v7.0](https://github.com/torvalds/linux/blob/v7.0/kernel/fork.c#L2363) |
| 3 | `/proc/<pid>/stat` start time is `start_boottime` converted to clock ticks | SRC | [`fs/proc/array.c` lines 580–581, v7.0](https://github.com/torvalds/linux/blob/v7.0/fs/proc/array.c#L580) |
| 4 | Task storage maps are available on the target (needed only by option 2) | MEAS | [`03-p2-feature-probe.txt`](../evidence/phase0/03-p2-feature-probe.txt); E-0007 |
| 5 | Uniqueness within a boot | INF | from 1–2 and pid reuse rules; tested by the Confirmation L4 tests |
| 6 | The source is upstream v7.0; Ubuntu's 7.0.0-38 could differ | INF | to be confirmed by the L4 tests on the VM |

## Pros and cons of the options

### 1. Kernel-native `(tgid, leader start_boottime)`
- Good: stable across exec by kernel design; reconstructible; no state.
- Bad: depends on two kernel fields (loud if renamed).

### 2. Counter `task_key` in task storage
- Good: a compact, opaque u64.
- Bad: a map write per fork; lazy assignment for pre-existing tasks; not recomputable outside our own records. It also needs its own rule for the non-leader-exec case, where the leader's `task_struct`, and its storage, are released.

### 3. `(pid, /proc starttime)` from userspace
- Bad: read after the fact from `/proc`, so racy for short-lived processes, and only tick resolution.
