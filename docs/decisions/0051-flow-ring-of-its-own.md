---
status: proposed
date: 2026-11-14          # drafted; the date of the merge if accepted
owner: Ashish Rana
consulted: [Dragon (design review F-01, 2026-11-13), Falco libs 0815626, Tetragon 75b95a2, Tracee 2f9dc40]
supersedes: ADR-0006 rule 2 in part (the bulk ring no longer carries FLOW)
---

# 0051: FLOW records on a ring of their own, drained last and never into the drain's last free batches

## Context and problem statement

One bulk ring carried OPEN, CLOSE, FILE, FD, BACKING, NET and FLOW (ADR-0006 rule 2, ADR-0004 rule 4). FLOW is the only class whose rate any process sets at will: a one-byte `read`/`write` loop makes about 1.4 million FLOWs a second on one CPU (E-0237), twice what the VM's disk takes (the design review's F-01, arithmetic from MEAS). When the ring is full every reservation fails alike, so the flood takes other processes' OPENs, CLOSEs and connects with it, and the flooder's own next steps hide in the loss. The question: how do we keep one process's transfers from costing other processes their identity and network records?

## Decision drivers

1. **Identity and intent are never lost because of someone else's volume.** OPEN, CLOSE and NET name what a process touched and where it connected; a FLOW without them cannot be placed.
2. **Every loss is counted by class** (ADR-0006 driver 3, unchanged).
3. **No policy in the kernel** (ADR-0005 driver 3): nothing decides whose records are worth keeping by name or user.
4. **Cost on the fast path**: nothing added per record beyond what a reserve already costs.
5. **The WAL and its readers do not change.**

## Considered options

1. **FLOW on its own ring, drained last, with a batch reserve** (this ADR).
2. **Per-CPU rings** (Falco: `BPF_MAP_TYPE_ARRAY_OF_MAPS` of ring buffers, one per CPU, `driver/modern_bpf/maps/maps.h`, `helpers/base/maps_getters.h`). Isolates CPUs, not classes: a flooder with one thread per CPU fills them all, and a victim on the flooder's CPU loses with it.
3. **A rate limit per group** (Tetragon: `bpf/process/bpf_rate.h`, a sliding window per cgroup in a per-CPU hash, a THROTTLE message, events dropped while throttled; applied to exec, fork and exit only). Keeps a flood from reaching the ring at all, but drops the throttled group's events: a policy choice that needs ADR-0013's threat model and the coarse record of option 4 to stay counted and placeable.
4. **A coarse record above a per-task rate** (the review's F-01 option 3): the flooder's transfers on an open file summed into one FLOW per window, flagged. Keeps every edge of the flooder at the price of its exactness; departs from ADR-0005 driver 1 for flagged records.
5. **Do nothing; the run is DEGRADED** and says so. Correct and loud, but the flood is cover.

## Decision outcome

**Chosen option:** 1, because it gives driver 1 for every record class except FLOW at no cost per record (driver 4) and no change to the WAL (driver 5). Options 3 and 4 remain candidates for the second step, which makes the flooder pay for its own flood (decision waiting 135); option 2 is orthogonal and not needed for isolation.

Rules:
1. **The flow ring** (`flow_rb`, `bpf/progs/file.bpf.c`): FLOW only, `--flow-ring-kb` (default 4096, a power of 2; one page without `--flow`). Its high-water mark for a wakeup is a quarter of it (ADR-0020 rule 2). FILE, the record that registers a pseudo open file on its first transfer, is identity and stays on the bulk ring.
2. **The drain** (`daemon/drain.c` `take_all`) reads the spine, then the bulk ring, then the flow ring. The flow ring takes a new batch only while more than `keep` batches of the queue are free (`p15q_may_take`); `keep` is `--flow-keep-batches`, or a quarter of `--queue-batches`, at least 1 and below `--queue-batches`. A poll that leaves FLOWs in the ring for that reason counts in `flow_deferred`, and the drain polls again at once, as for a full queue.
3. **In the WAL** FLOW records stay on the bulk ring, so every reader is unchanged. Their order relative to OPEN and FILE in the stream is no longer reservation order; the readers order by timestamp (`graph.sql` orders by `ts_ns, ring, seq`).
4. **The books** are unchanged: FLOW is counted by type (`flow_drained`, FLOW_STATS's `flow_lost`), and the WAL's bulk-ring equation still holds, since FLOWs are written to the WAL's bulk ring.
5. **FLOW_RING** (type 45, STATS class) is written with every FLOW_STATS: the ring's size, its most bytes waiting this interval, `deferred`, the queue's full count, `keep` and the queue's size.

### Consequences

- Good: a flood of transfers loses FLOWs only. Other processes' identity and network records keep the bulk ring and the reserved batches.
- Good: the cost is one ring map (4 MiB by default) and one compare per batch the flow ring takes; no per-record work.
- Bad: other processes' FLOWs are still lost in a flood, with the flooder's. That is the second step's job (decision waiting 135).
- Bad: the flood still costs the writer and the disk its FLOWs up to the queue's share; the F-02 guard (`daemon/space.h`) bounds the disk.
- Bad: FLOW and its FILE are on two rings, so a FLOW can reach the WAL before the FILE that registers its open file. The readers order by time; a reader that relied on stream order would break. None does: FLOW and FILE are read only by the graph, which loads them into raw tables and joins them by `fid`, ordering by `ts_ns, ring, seq` (`python/p15/graph/graph.sql`); `trace.py` and `provenance.py` do not read FLOW.

### Confirmation

- `it_p15d.sh` case 30 (VM, CI with `P15_IT_NET=1`): a 64 KiB flow ring and a slowed writer, `dd bs=1` floods while a second process creates and closes 300 files and connects 30 times. Pass: FLOWs lost (`flow_lost > 0`); no identity or NET record lost; all 300 OPENs, 300 CLOSEs and 30 connects in the WAL; FLOW_RING shows the ring filled and the drain deferred; exit 3 with the books closed.
- `test_queue` `test_reserve`, `test_config` (the reserve's rule); planted bugs 123 to 126 (`daemon/tests/mutate_p15d.py`).
- The design review's run V-1 repeated on this tree: `open_lost` stays 0 while `flow_lost` grows.

### Falsifier

- Case 30 or V-1 shows an identity or NET record lost while only a flood of transfers runs.
- A reader is found whose result depends on FLOW following its FILE in the stream.
- The flow ring's map costs a measurable amount on the open path (bench `open_cost` before and after).
