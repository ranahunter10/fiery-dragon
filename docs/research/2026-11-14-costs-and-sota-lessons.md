# Where an open+close's cost goes, what p15d's user-space path costs per step, and what the tools' current code does about overload (2026-11-14)

The maintainer's request of 2026-11-14: know why capture costs what it costs, from first principles; read the state-of-the-art tools' current code (not only pinned commits) for how production capture handles overload; and turn that into changes. This note joins the VM's numbers from E-0310 with a new user-space harness run in the dev container, and the tools' code read today at Falco libs `0815626` (2026-11-05), Tetragon `75b95a2` (2026-11-14, the tip of `main` when cloned) and Tracee `2f9dc40` (2026-09-29). It follows `2026-11-12-open-cost-against-the-tools.md`, whose candidate list (C1 to C4) it updates. Grades as in `CONTRIBUTING.md` §5.

## 1. An open+close on the VM: 1,158 ns added, where it goes

`bench/open_cost`, `same` arm (one cached file opened and closed 200,000 times), on the integrated tree with `--flow` (E-0310, [evidence](../evidence/vm/2026-11-14-vm-integration/matrix/open_cost_report.txt)): 1,009 ns without capture, 2,200 ns with it, **+1,158 ns per open+close** (95 % interval 728 to 1,233). The `distinct` arm (every open a first sighting, facts in the record) adds 1,531 ns. MEAS.

| Part | ns per open+close | Grade | Source |
|---|---|---|---|
| `file_open_path` (fentry body: header, `bpf_d_path`, facts, object map, ring copy) | 272.0 | MEAS | `prog_stats.txt` (bpf_stats, 3 rounds) |
| `file_free` (kprobe.multi body: open-file map lookup, CLOSE, delete) | 216.2 | MEAS | same |
| `file_open_session` (kprobe.session, 2 runs: entry registers the open file, return the verdict) | 182.7 | MEAS | same |
| **Program bodies** | **673.6** | MEAS | same |
| Hook paths into the programs (fentry about 14, kprobe.session about 141, kprobe.multi about 21) | about 176 | MEAS on `vfs_read` (E-0138); INF that it carries over | E-0138 |
| The rest: the programs' working set evicting the open path's cache lines, the ring's wake-up path, the bpf_stats figures' own cost | about 310 | INF (not measured) | 1,158 − 674 − 176 |

Inside the bodies (E-0187, E-0192, profiled build): `bpf_d_path` 94; the ring copy of an OPEN 38; the header 16; the open-file map **178 in all** (insert 94, three lookups 38, delete 46); the object map 14; facts 6. MEAS.

From first principles, what an open+close must cost with our guarantees: two ring records (reserve, fill, commit: about 60 ns each), the kernel's own path (94) and the facts (6): about 220 ns of bodies, plus about 35 ns of hook paths if both hooks were fentry/fexit. We spend 674 + 176. The difference is three things, each deliberate today:

1. **The open-file map (178 ns, 26 % of the bodies).** No tool keeps an entry per open file in the kernel (§3); they name an open file in user space. Ours exists for ADR-0015 rule 1 (an id from the kernel shared by the fentry, the session and the close). Candidate C2 (the `struct file` address as the open file's name, paired in the reader) removes it, at the price of a CLOSE for frees capture never saw (38.2 % of frees in the soak), unless the free filters by superblock magic first.
2. **The kprobe.session (141 ns of hook path, 183 of body).** It is there because tracing programs (fentry/fexit, `tp_btf`) are skipped for other tasks by the per-CPU recursion guard on 7.0 (E-0089, ADR-0020), and the session's return is the non-preemptible fallback that keeps every open (ADR-0029). C1 (session only) was measured and is not cheaper (2026-11-12 note §5). This cost stays while the guard does.
3. **Bytes.** 172 bytes per open+close (OPEN 116, CLOSE 56) against eAudit's 17 per record. Bytes cost in the ring copy, in p15d (§2) and in the WAL.

## 2. p15d's user-space path, step by step (new harness, dev container)

`bench/p15d_path/p15d_path.c` runs p15d's own functions on a stream of FLOW (96 B) and CLOSE (56 B) records, about 2^20 a round, median of 7 to 9 rounds, WAL on tmpfs ([evidence](../evidence/build/2026-11-14-p15d-path/); Xeon 2.1 GHz, kernel 6.18, 2 vCPU). MEAS, container: the VM's figures will differ; the proportions are what carries over (INF).

| Step | 1 MiB batches | 64 KiB batches | What it is |
|---|---|---|---|
| check (`p15_rec_check`) | 6.6 ns/record | 6.1 | the drain's per-record validation |
| copy into the batch | 2.6 | 2.3 | `put()` |
| queue (per batch, amortised) | 0.0 | 0.2 | acquire, publish, peek, release |
| CRC32C (SSE4.2) of the payload | 8.9 | 8.3 | inside `p15w_append` |
| `p15w_append` (CRC, header, `writev`) | 38.3 | 33.7 | about 29 ns of it is the copy into the page cache, in proportion to bytes |
| **the two-thread pipeline**, CPU of both threads | **82.5** | **66.1** | drain thread → queue → writer thread, as p15d runs |

- Single-thread steps add to 42 to 48 ns per record; the two threads cost 66 to 83. The difference, about 25 to 35 ns per record, is the hand-off: the writer reads batches another core wrote (cache-line transfers) and the eventfd wake-ups. MEAS (the difference); its split is INF.
- Not in the harness: reading the kernel ring (libbpf's callback per record, the epoll wake-up, the counters read after every poll). On the VM p15d costs about 250 ns per open+close above idle (E-0310), 125 per record; the harness's 66 to 83 leaves about 40 to 60 ns per record for the ring side and the VM's slower core (INF until the harness runs there).
- Against eAudit's collector, a median 48 ns per syscall (R-042 §4.3, PDF): our pipeline is in the same order once the kernel ring is excluded; the bytes are the lever (§4, C3), not the checks.

## 3. What the tools' current code does about overload

| Tool, file | Mechanism | Lesson for us | Grade |
|---|---|---|---|
| Falco libs, `driver/modern_bpf/maps/maps.h` L242, `helpers/base/maps_getters.h` (`maps__get_ringbuf_map`) | one ring buffer **per CPU** (`BPF_MAP_TYPE_ARRAY_OF_MAPS`), drained by `libpman/src/ringbuffer.c` | isolates CPUs, not classes: a flooder on every CPU still fills every ring | SRC |
| Falco libs, `helpers/base/stats.h` | drop counters **per event class** (`n_drops_buffer_open_enter`, `_connect_enter`, `_proc_exit`, ...); `n_evts` counted before the reserve | the same principle as our books: a loss is counted by what was lost | SRC |
| Falco libs, `programs/attached/dispatchers/syscall_exit.bpf.c` `sampling_logic_exit` | **dropping mode**: under overload user space turns it on; syscalls flagged `UF_NEVER_DROP` are always kept, `UF_ALWAYS_DROP` always dropped, the rest kept for 1/`sampling_ratio` of each second; `DROP_E`/`DROP_X` events mark the start and end | **shed by class, keep identity**: the idea of ADR-0051 and of the F-02 guard's order, taken further with a marked sampling window | SRC |
| Falco libs, `helpers/store/ringbuf_store_params.h` L173-179, `auxmap_store_params.h` L384 | `BPF_RB_NO_WAKEUP` on every commit; user space polls | we wake at a quarter full (ADR-0020 rule 2), which is the same idea with a bound | SRC |
| Tetragon, `bpf/process/bpf_rate.h` | a **per-cgroup sliding-window rate** (previous and current window, per-CPU hash); above the limit the cgroup is throttled, a THROTTLE event is sent once, its events dropped; `pkg/cgrouprate/cgrouprate.go` lifts it when the rate falls (with a 5 s hold) and sends throttle stop | makes the flooder's group pay. Its drops are not counted per event, only marked by start and stop: weaker than our books. Applied to exec, fork and exit only | SRC |
| Tetragon, `bpf/lib/process.h` `event_output_metric` | every failed output counted per op | counted loss, as ours | SRC |
| Tracee, `pkg/metrics/stats.go` L100-101 | `LostEvCount`, `LostWrCount`: loss counted, by ring, not by class | coarser than ours | SRC |
| auditd 3.1.2 `auditd.conf(5)`; journald v253 `journald.conf(5)` | disk tiers before full; the daemon stays alive | built for the WAL as the F-02 guard (`2026-11-14-full-disk.md`) | DOC |

What none of them gives, and we keep on purpose: identity from the kernel's object at the LSM point, a path when the fentry is skipped, and books that close with a counter for every loss.

## 4. What to cut or change, ranked by what it saves (each INF until measured)

| # | Change | Saves | Cost, risk | Status |
|---|---|---|---|---|
| C2 | Open-file ids in user space (2026-11-12 note §4), with a superblock-magic filter at the free | about 178 ns per open+close of bodies, and most of the free's 216 | ADR-0015 rule 1; 38 % of frees are of files never opened unless filtered | design note needed |
| C3 | Compact records (eAudit): drop `start_ns` from bulk headers (the spine has it), a per-batch time base | ring copy and p15d's bytes: about a third of `append`'s 29 ns per record is per 25 bytes (INF from §2) | a schema version; bulk records then depend on the spine for the process key | design note needed |
| F1 | **FLOW on its own ring** (ADR-0051, draft) | nothing per record; isolates identity from floods | one 4 MiB map | **built** on `dragon/flow-ring` |
| F2 | A per-task FLOW budget with a coarse, flagged record above it (the review's F-01 option 4; Tetragon's window, Falco's marked window) | the flooder's volume, at its own exactness | ADR-0005 driver 1 for flagged records; verifier work | decision waiting 135 |
| P1 | p15d in one thread | about 30 ns per record | a disk stall would stop the drain (ADR-0017): not recommended | rejected here |
| H1 | Measure the "rest" of §1 (310 ns): `perf stat -e cycles,instructions,L1-dcache-load-misses,LLC-load-misses` on `open_cost`'s loop with and without p15d | tells whether the cost is cache pressure (then C2 and C3 help more than their bodies say) | none | VM command in the package |

## 5. Measure next (VM)

1. `bench/p15d_path` on the VM (same commands as here): the user-space steps on the target.
2. H1, the `perf stat` pair.
3. `bench/open_cost` on `dragon/flow-ring`: the flow ring must not move the open path (ADR-0051 falsifier 3).
4. Case 30 of `it_p15d` and the design review's V-1 on `dragon/flow-ring`.
