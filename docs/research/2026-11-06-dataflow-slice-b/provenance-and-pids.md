# Research B: what capture must record about file and socket data flow, and which reductions are safe

2026-11-06. Read-only research. No third-party code was run.

Grades: **PDF** (paper §, read through WebFetch summaries), **SRC** (repo@commit file:line), **DOC**, **INF** (inference, not a result), **OPEN**.

Pinned sources:
- PIDSMaker `ubc-provenance/pidsmaker@15e5515` (2026-11-04)
- CamFlow `camflow-dev@0948c30`
- SPADE `SPADE@1ff5119`. The CDM schema I used is SPADE's `cfg/spade.storage.CDM.avsc` (namespace cdm20). `darpa-i2o/Transparent-Computing@244ae24` holds only READMEs (DOC).

## 1. Causality-preserving reduction

### Xu et al., CCS'16 (CPR)

**Event model.** Each event e=(u,v) has a start time ts and an end time te (PDF §3.1.1).

**Aggregability.** Two events can merge only if they have the same type, source and destination. For file reads and writes they must also share the fd (PDF Def. 4).

**The merge rule.** e2 folds into e1 only if both checks pass (PDF §3.2, Alg. 1-3):
- **Backward check:** no *incoming* event of the source u overlaps [te(e1), te(e2)].
- **Forward check:** no *outgoing* event of the destination v overlaps [ts(e1), ts(e2)].

Alg. 3 states these windows in start times, while the prose uses end times (PDF, ambiguous).

**Timestamps and attributes.** The merged event spans [ts(e1), te(e2)]. The paper does not say how attributes combine (PDF).

**Algorithm.** Online, with one stack per (src, dst, type). Events that cannot be aggregated are emitted. No formal memory bound is given (PDF §3.2, §4.4).

**Results (PDF §4.2, Tables 2-3):**

| Method | Reduction | Effect on queries |
|---|---|---|
| CPR | 56% | 0 false positives on 20,000 POIs |
| CPR+PCAR | 70% | False connectivity in 2 of 10 tasks |
| CPR+PCAR+DOM | 77% | — |
| Naive 10 s window (comparison) | — | 17% false connectivity |

**Domain reductions.** All events of a "temporary file" (one touched by only one process in its lifetime) are dropped (PDF §3.4.2).

### Hossain et al., USENIX Sec'18 (FD / SD)

**Definitions.**
- **FD** preserves forward reachability from u@t for every t in NewAnc(u), the times u's ancestor set changes. It also preserves backward reachability at all t (PDF §3.3 Def. 4).
- **SD** does the same for source nodes only, meaning nodes with no incoming edges (PDF §3.4).
- Only read, write and load events are reduced. Fork, execve, rename and similar events are kept (PDF §3).

**Algorithms (PDF §4), run on a versioned graph:**
- **REO** drops (u,v) if the latest version of u already has an edge to some version of v.
- **RNO** creates a new version of v only if v's current version has outgoing edges.
- **SD** also drops (u,v) when Src(u) ⊆ Src(v).
- REO does not traverse past execve (PDF §6.1).
- Merged timestamps become a covering interval (PDF §3).

**Results.** Average reduction factors are LCD (=CPR) 1.8x, FD 7x and SD 9.2x. FD ranges 4.6-15.4x and SD 5.4-19.1x (PDF §1.1, §6.3). FD runs online at about 860K events/s (PDF §6.6).

**State.** FD keeps the latest version of each entity with a lookback window k. SD adds a Src set per entity (PDF §4.3).

### LogGC, CCS'13

- Removes events unreachable from live objects, plus temporary files (PDF §3).
- Explicitly treats a malicious library that is created, run and deleted inside one process as safe to remove (PDF limitations).
- Basic GC alone removes about 14% on user hosts. The 14x figure needs BEEP units and instrumentation (PDF Table 5). Runs as a batch.

### NodeMerge, CCS'18

- Merges into learned templates the files a process reads in its first k seconds that are read-only, meaning no write after time t_g (PDF §6).
- Reduction is up to 75.7x over raw and 32.6x over CPR/PCAR (PDF Table 4).
- Order among the merged reads is lost (PDF §10.1).
- Evaded by malware that waits past t_g (PDF §10.5).

### SEAL, USENIX Sec'21

- Lossless and query-preserving. It merges the incoming edges of a node but keeps every start and end time, delta-coded (PDF §3.3-3.4).
- 12.94x on DARPA TC, against 8.96x for FD (PDF §5.2).
- States that lossy methods "might introduce false connectivity under time constraints" (PDF §5.3).

Not read: Zhu et al. (TIFS'21), LogApprox, Ellipsis (OPEN).

### Which rules can run in the kernel per (process, file)

All of this subsection is INF.

**CPR can, using four generation counters:**
- **Read F→P.** The backward check becomes "has anyone written F?", so keep `F.wgen`. The forward check becomes "has P had any outgoing flow (write, send, clone, exec)?", so keep `P.ogen`.
- **Write P→F.** The checks mirror: `P.igen` (any input to P) and `F.rgen` (any read, exec or map of F).

A pending aggregate keyed by (process identity, open file, type) absorbs a new event iff both counters still equal their values when the aggregate started. This is equivalent to CPR's merge into the top of the stack.

**FD can be derived downstream.** REO needs only the backward half, so it can be computed from CPR records that carry generations. The reverse is not possible.

**SD, LogGC and NodeMerge cannot run in the kernel.** They need global or offline state.

**When capture emits:**
- **First event:** start a pending record. first_ts must be kept.
- **A counter changed:** flush.
- **Last close, exec, exit, or map eviction:** flush. Eviction must flush, never drop.

## 2. Versioning and identity

**CamFlow:**
- **Versioning.** Nodes "must be versioned to avoid cycles". On each flow into a node that has outgoing edges, the version is bumped and an `RL_VERSION` edge is written (SRC provenance_record.h:24-88).
- **Edge compression.** An edge is skipped when the destination's last incoming edge had the same source id, version and type (SRC :116-142). This is weaker than CPR because it has no forward check (INF). It is on by default (SRC hooks.c:2898-2901).
- **Identity.** (id, boot_id, machine_id, version), where id comes from a per-boot counter. Inodes add `ino` and the superblock UUID (SRC include/uapi/linux/provenance.h:71-77, 205-210).
- **Read/write.** Recorded from the `file_permission` hook with `offset=file->f_pos` and `flags=mask`. There is no byte count (SRC provenance_relay.h:136-139). Bytes exist only as task totals (SRC provenance_task.h:334-341).

**SPADE Audit reporter:**
- **Identity.** Files are path-keyed. The inode annotation is off by default (SRC cfg/spade.reporter.Audit.config:107).
- **Versioning.** Versions and epochs are on (SRC :73-77, :161). The epoch bumps on re-create, the version on write, truncate or chmod (SRC ArtifactManager.java:453-492).
- **I/O.** With the defaults `fileIO=false` and `netIO=false` (SRC :44-47), `close` emits one Used or WasGeneratedBy edge per open session, chosen by open mode (SRC Audit.java:1644-1672). When I/O is traced, edges carry `size` (SRC :1794-1798).

**LPM (USENIX Sec'15):** keeps a per-inode version incremented on write "to break cycles". Hi-Fi did not version files (PDF §3.4.3). The paper does not specify per-read fields.

**OPUS:** OPEN (not read).

**CDM:** `AbstractObject.epoch` tracks "when an object is deleted and a new one is created with the same identifier" (SRC CDM.avsc:356-358).

## 3. DARPA TC CDM (SRC CDM.avsc)

**Data-flow event types:**
- Read and write: READ, WRITE, SENDTO, RECVFROM, SENDMSG, RECVMSG
- Connection: CONNECT, ACCEPT, BIND
- Code and memory: MMAP, MPROTECT, EXECUTE, LOADLIBRARY, SHM
- Kernel pipes: TEE, SPLICE, VMSPLICE
- Process lifecycle: CLONE, FORK, EXIT
- Files: OPEN, CLOSE, RENAME, LINK, UNLINK, TRUNCATE
- Kernel modules: INIT_MODULE, FINIT_MODULE

**Event fields:** `timestampNanos` (UTC epoch ns), `sequence` (per-subject order), `subject`, `predicateObject[2]` with `…Path`, `location` (offset), `size` (bytes), and `threadId`.

**Object records:**
- **FileObject:** `epoch`, type (FILE, DIR, UNIX_SOCKET, …), fd, `size`, hashes
- **NetFlowObject:** local and remote address and port, `ipProtocol`, `initTcpSeqNum`
- **Subject:** `startTimestampNanos`, `parentSubject`, `cmdLine`, properties.path

**What PIDSMaker actually reads.** Subject uuid, cmdLine and path. File path or filename. The four netflow address and port fields. For events: type, subject, predicateObject, uuid and timestampNanos (SRC create_database_e3.py:29-319).

It never reads `size`, `location`, `sequence`, `predicateObjectPath`, `predicateObject2` or `epoch` (SRC, grep).

## 4. What PIDSMaker consumes

The previous agent's findings were verified:
- **Four tables.** `event_table` has no size, count or offset column (SRC postgres/init-create-databases.sh:18-61).
- **index_id** is one counter across the netflow, subject and file tables (SRC create_database_e3.py:332-347).
- **Read-type edges are reversed** when inserted: EXECUTE, MMAP, OPEN, ACCEPT, READ, RECVFROM, RECVMSG and similar (SRC dataset_utils.py:8-20; create_database_e3.py:290-301).
- **10 edge types are kept**: CONNECT, EXECUTE, OPEN, READ, RECVFROM, RECVMSG, SENDMSG, SENDTO, WRITE, CLONE (SRC dataset_utils.py:33-54). Everything else is filtered at graph build (SRC build_default_graphs.py:346).

**Addition:** ACCEPT is not the only type dropped late. MMAP, MPROTECT, LOADLIBRARY, RENAME, UNLINK, EXIT and CLOSE are dropped too. Stock detectors therefore never see W→X (SRC; INF).

**Windows and fusion:**
- `time_window_size: 15.0` minutes and `fuse_edge: True` in every detector config (SRC config/*.yml:5-9).
- A window closes only at a 1,024-event batch boundary, so it is at least 15 minutes long (SRC build_default_graphs.py:321-381).
- **Fusion rule:** per (src, dst) pair within a window, edges are sorted by time and only the **first edge of each run of the same type** is kept, with its timestamp and uuid (SRC :392-453).
- Example: R,R,W,R becomes R@t1, W@t3, R@t4.
- The rule has no interleaving check, and drops last_ts, count and bytes (INF).

**Features by detector** (SRC config/<detector>.yml `node_label_features`, featurization, batching):

| Detector | Labels used | Features | Time |
|---|---|---|---|
| Kairos | subject path; file path; remote ip and port | hashing of every `/` prefix (feat_inference_HFH.py:7-15) | TGN with `time_encoding`; `msg` = src emb + edge type + dst emb |
| Orthrus | type, path, cmd_line; file type and path; netflow type, ip, port | word2vec on `/`-split tokens (utils.py:381-383) | TGN, edge_type |
| Flash | path, cmd_line; file path; ip, port | word2vec on a time-sorted (src, op, dst) list per node, capped at 300 entries (featurization_flash.py:30-50) | order only |
| MAGIC | (labels configured but unused) | node type only | none |
| ThreaTrace | type, path, cmd_line | node type + in/out edge counts per type (data_utils.py:275-287) | none |

What follows for capture:
- **Full path at open is required.** Kairos hashes every prefix, so a basename collapses the feature (INF).
- **cmd_line** is used by Orthrus, Flash and MAGIC's label.
- **Bytes are never used.**
- **ThreaTrace counts edges after fusion.** Capture that aggregates more coarsely than "one record per same-type run" would change those counts (INF).

**Is one read edge per (process, file) per window enough?** PIDSMaker needs the first timestamp of each same-type run, per pair, per window. CPR records carrying first_ts and last_ts therefore lose nothing PIDSMaker uses (INF).

A record that spans two windows must be re-emitted at the window boundary by the exporter, with a synthetic uuid (INF). New edge types need `num_edge_types` (DOC docs/docs/datasets.md:291-302).

The detectors' own papers were not read; the features above are PIDSMaker's implementation (OPEN).

## 5. Missing edges versus extra edges

**Dependency explosion** means an event "unnecessarily dependent on too many other events", which follows from assuming every output depends on all earlier inputs (PDF LogGC §1; SoK S&P'23 §III-A).

**The SoK's measurements on E3-Theia** (PDF §IV-G, Table IX):

| Reduction | Data removed | DeepLog precision / recall | ProvDetector top-20 paths retained |
|---|---|---|---|
| None | 0% | 52.94 / 87.10 | — |
| LogGC, NodeMerge | 9-10% | unchanged | — |
| CPR | 22% | 46.30 / 80.65 | 95% |
| LogApprox | 61% | 32.86 / 76.67 | 85% |
| F-DPR / S-DPR | about 90% | 5.97 / 14.29 | 55% |

The SoK reports "an inverse relation between storage efficiency and anomaly detection performance". It says DPR "may drop unique flow events which fully severs the causal relation between two entities" and "has been observed to delete attack-relevant data" (PDF §III-B, §IV-C).

**Other evidence:**
- A naive time window gave 17% false connectivity, against 0 for CPR (PDF Xu §4).
- PCAR introduced false connectivity in 2 of 10 tasks (PDF).
- FD and SD "may change the paths generated during a backward or forward analysis" (PDF Hossain §4.2.5).

**OPEN:** I found no paper sentence saying "loss of a single edge breaks the attack chain". The SoK's "fully severs the causal relation" is the closest citable wording.

**Fileless hazard (INF).** The temporary-file rules (LogGC; CPR §3.4.2) and LogGC's created-run-deleted case describe a memfd payload exactly. NodeMerge can be evaded by waiting past t_g.

## Requirements this puts on the capture layer (INF unless marked)

1. **Events.**
   - **Never aggregated:** OPEN (flags), CLOSE, CONNECT, ACCEPT, BIND, EXECUTE (including memfd and `/proc/self/fd`), CLONE/FORK, EXIT, RENAME/LINK/UNLINK/TRUNCATE, MMAP and MPROTECT with PROT_EXEC or a writable shared mapping, SPLICE/TEE/VMSPLICE/sendfile.
   - **Aggregated under rule 4:** READ/WRITE and SEND/RECV.
2. **Attributes.**
   - **File:** (dev, ino) plus a capture epoch bumped on create and on reuse; the **full absolute path at open**; the kind (regular, dir, memfd, pipe, unix socket).
   - **Subject:** identity (ADR-0009), exe path, full cmdline.
   - **Netflow:** local and remote address and port, protocol, TCP ISN (CDM `initTcpSeqNum`, ADR-0022).
3. **Timestamps.** first_ts (mandatory, since PIDSMaker keeps the first) and last_ts per aggregate. A per-subject sequence number. A recorded mapping from monotonic time to UTC epoch ns.
4. **The only safe in-kernel aggregation is CPR with generation counters.**
   - **READ F→P** folds iff `F.wgen` and `P.ogen` are unchanged since the aggregate began. **WRITE P→F** folds iff `P.igen` and `F.rgen` are unchanged. The same applies to sockets.
   - The key includes the open file (the fd condition of PDF Def. 4).
   - **Flush** on interleave, last close, exec, exit, mmap(PROT_EXEC) of the object, age (aligned to the 15-minute export window), and eviction.
   - **Each record carries** count, bytes, min/max offset (as CamFlow `f_pos` and CDM `location`/`size`), first_ts, last_ts and the generations.
   - **Never in the kernel:** temp-file drops, templates, SD. Derive FD and SD downstream.
5. **Counters.**
   - Events folded, per type.
   - Flushes by reason: src-interleave, dst-interleave, close, exec, exit, age, evict.
   - Pending-map and generation-map evictions, and the conservative flushes each one forces.
   - At export, every event dropped per type. Stock PIDSMaker drops MMAP, MPROTECT, ACCEPT, RENAME, UNLINK, EXIT and CLOSE.
6. **Decision for the maintainer.** Code-provenance edges are invisible to stock PIDSMaker. They can be mapped onto the 10 kept types (for example memfd exec as EXECUTE from a file node labelled `memfd:<name>`), or new edge types can be added.

## Gaps

- The CPR window boundary is ambiguous (Alg. 3 uses start times, the prose end times). Attribute merging is unspecified.
- **Writable MAP_SHARED and io_uring writes bypass `wgen`.** The likely fix is to disable aggregation on an object while a writable shared mapping exists (OPEN, needs a test).
- `inode_storage` is unavailable, so the generation map needs a hash keyed by (dev, ino) plus an epoch for inode reuse (OPEN).
- CDM18 (E3) was not diffed against cdm20. Whether TA1 file UUIDs are per inode or per version is unknown (OPEN).
- The SoK evaluated DeepLog, StreamSpot and ProvDetector, not the TGN-based PIDS. The effect on Kairos and Orthrus is unmeasured.
- There is no reduction factor for our own workloads. That needs a harness on `p15-dev-2604`.
- PDF claims come from WebFetch summaries. Verify the wording against the full PDFs before quoting them in the thesis.
