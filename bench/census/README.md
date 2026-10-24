# Event-rate census (phase-0 probe P10)

**Question:** how many records per second, of each class, would Fiery Dragon emit on real workloads? And can the write-ahead log keep up?

Every sizing decision depends on this one number:
- ring-buffer sizes;
- the per-record byte budget;
- log bandwidth;
- whether any in-kernel reduction is needed at all (ADR-0005/0006/0007).

The census answers it **before** any capture code exists.

## What it measures

[`census.bt`](census.bt) attaches the **same hooks the capture design uses** (blueprint v1 §4.1) and counts events per record class:

| Family | Classes | Hook | Emitted by the design? |
|---|---|---|---|
| spine | `fork`, `exec`, `exit`, `rename` | `sched_process_*`, `task_rename` | yes |
| open | `open`, `open_fail` | `fexit security_file_open` | yes |
| file | `rd_reg`, `wr_reg`, `rd_pipe`, `wr_pipe` | `fexit vfs_read/readv/write/writev`, `retval > 0`, split by inode type | yes |
| file-not-emitted | `rd_sock`, `wr_sock`, `rd_chr`, `wr_chr`, `rd_other`, `wr_other` | same hooks | no. Socket I/O is emitted by the socket hooks (one-layer rule); devices aren't FILE_FLOW sources in v1 |
| xfer | `splice`, `splice_direct`, `copy_range` | `fexit do_splice`, `do_splice_direct`, `vfs_copy_file_range` | yes |
| sock | `snd`, `rcv` | `sock:sock_send_length` / `sock_recv_length`, `ret > 0` | yes |
| uring | `uring` | `io_uring:io_uring_complete` | yes |
| info | `sys` (all syscalls), `rename_exec` | `raw_syscalls:sys_enter`; renames made by exec itself | no |

[`summarize.py`](summarize.py) turns the output into a per-class report:
- total, mean/s, and p50/p99/max per second over 100 ms windows;
- payload MB/s;
- **estimated log bandwidth** of the emitted classes;
- a **verdict** comparing p99 against the disk budget. The default budget is P5's minimum 63.7 MB/s ÷ 3 headroom = 21.2 MB/s.

## How to run it (on the VM)

```bash
sudo swapoff -a                                    # measurement condition (STATE.md decision 2)
sudo bpftrace -f json bench/census/census.bt > census-<workload>.jsonl &
# ... run the workload ...
sudo pkill -INT -x bpftrace                        # SIGINT runs END, which prints the final totals
python3 bench/census/summarize.py census-<workload>.jsonl --label <workload>
sudo swapon -a
```

- **Exit status:** 0 when the output is complete with no losses; **2** when the run was cut short or bpftrace reported lost output.
- Record sizes can be overridden with `--size CLASS=BYTES` and `--record-bytes N`.
- `--format json` gives machine-readable output for aggregating several workloads.

## Running the workload set: `run.py`

```bash
python3 bench/census/run.py --list                                  # what exists
python3 bench/census/run.py --workloads light --dry-run             # what would run, what's missing
sudo python3 bench/census/run.py --workloads light --duration 60 \
    --snapshot 01-toolchain --host-note "plugged in, Best performance, Hyper-V on"
```

For each workload, the runner:
1. starts the census and waits until it has attached;
2. runs the workload **as the user who called sudo** (not root) for `--duration` seconds;
3. stops the census with SIGINT;
4. summarizes the run.

Swap is turned off during the runs and restored afterwards (STATE.md decision 2). All output goes to `/var/tmp/fd-census/<UTC time>/`, outside the repo, so nothing is committed by accident. Results are promoted to `docs/evidence/` deliberately.

| File | Content |
|---|---|
| `index.md` | one row per workload: records/s mean/p99/max, log MB/s p99, verdict |
| `conditions.json` | kernel, bpftrace version, probe/summarizer/runner hashes, git commit + dirty flag, CPUs, RAM, hypervisor, swap, `io_uring_disabled`, load, snapshot, host note |
| `<w>.jsonl` / `<w>.md` / `<w>.json` | raw census output / report / machine-readable summary |
| `<w>.workload.log`, `<w>.bpftrace.err` | the workload's own output; bpftrace's stderr |

A run is **ok** only if bpftrace stopped cleanly, the output is complete, no events were lost, and the workload exited normally. Anything else is **FAILED** with every reason listed. A workload whose tools are missing is **SKIPPED** and shown, never left out silently.

**Light workloads** (this PR):

| Workload | What it does | Approximates |
|---|---|---|
| `idle` | nothing: the VM's background floor | — |
| `exec-storm` | `/bin/echo` in a tight loop | Houssel et al. shbm (50,000 echo execs), time-bounded |
| `file-churn` | PostMark-style create/append/read/delete over 500 small files ([`workloads/filechurn.py`](workloads/filechurn.py)) | PostMark-shaped; parameters are ours |
| `super-producer` | five concurrent `find /usr` loops | Mao, Ujcich & Ma |
| `xfer` | `cp` (copy_file_range), `cat` (splice), `sendfile` on a 64 MiB file | — |
| `io-uring` | fio random read/write through io_uring | — |

**Service workloads** (Nginx, Redis, kernel build) come in the next PR. They need extra packages and system services.

**Dry run (dev container, 8 s each, tracepoint-only probe):**
- all five available workloads ran and stopped cleanly; `io-uring` was correctly SKIPPED (no `fio`);
- `exec-storm`: `rename_exec` = `exec` = 5,611;
- `file-churn`: about 118,000 operations of each kind in 8 s.

The fexit classes only light up on the VM.

## Design choices, and why

- **Cumulative counters, printed every 100 ms, never cleared.** `print(); clear();` would silently lose every event landing between the two calls. The summarizer takes deltas instead.
- **Windows are defined by `T <ns>` markers.** bpftrace prints *nothing* for an empty map (observed in the dry run), so map lines can't define windows.
- **Nothing is dropped silently.** Unknown classes, map names and line types, and bpftrace lost-event reports, are all counted and shown.
  - A counter that goes backwards, a key that disappears, or time that goes backwards is an **error**, not a warning.
- **A window shorter than 50 ms is merged into the one before it.** The END snapshot fires a few ms after the last tick, and dividing by a 5 ms window would invent a spike.
- **exec renames are counted apart** (`rename_exec`). exec itself sets the new process name, which fires `task_rename`. Counting that as `rename` would double-count every exec. This was found by the dry run below.

## Limitations, stated up front

- **Observer effect.** The census uses fexit hooks like the product will, so its overhead resembles the product's. But it is not zero, and the workload runs slightly slower than untraced. P12 (untraced baselines) quantifies this.
- **Self-exclusion by `comm == "bpftrace"`** is a measurement shortcut. Any other process named `bpftrace` would be excluded too. The product never filters on comm.
- **Record sizes are assumptions (INF):** 64 B per flow, 256 B for exec, 128 B for open. They become MEAS once ADR-0008 fixes the schema.
- **`p99` equals `max` for short runs.** With fewer than 100 windows (10 s), nearest-rank p99 is the maximum. Run workloads for ≥ 60 s.
- **The "inside exec" bracket uses `raw_syscalls` with x86-64 numbers** (59 `execve`, 322 `execveat`). On kernel 7.0 with bpftrace 0.25, `syscalls:sys_enter_execve` delivered **no events** (E-0021), so it can't be used. 32-bit compat execve uses other numbers, so its own rename counts as `rename`.
- **`copy_range` and `splice_direct` can overlap.** `vfs_copy_file_range` may fall back to `do_splice_direct`.

## Dry run (2026-10-25, dev container)

The cloud dev container (kernel 6.18, bpftrace 0.20.2) can attach tracepoints but not fentry/fexit, because `available_filter_functions` is unreadable there. So the dry run used **census.bt with the fexit blocks removed**, against a known workload:

| Known input | Census result |
|---|---|
| 30 × `prctl(PR_SET_NAME)` | `rename` = **30** |
| 50 × exec of `/bin/true` (plus background) | `exec` = 56, `rename_exec` = **56** (equal, as designed) |
| 1,000 × 1,000-byte TCP sends on loopback | `snd` = 1,001; ≥ 1,000,000 bytes |

That output is the test fixture [`testdata/container-tracepoints-2026-10-25.jsonl`](testdata/) (sha256 `146d0adb…6cda59`).

**Not covered by the dry run:**
- the fexit classes (open, file flows, xfers);
- bpftrace 0.25's JSON format, which is the version on the VM.

## VM smoke run (2026-10-25, kernel 7.0.0-38, bpftrace 0.25)

The run used a known workload, and its raw output is the fixture [`testdata/vm-7.0-smoke-2026-10-25.jsonl`](testdata/) (sha256 `1a2c2f00…beed24`). It found three things, all now covered by tests:

1. **bpftrace 0.25 prints compiler warnings to stdout, before the JSON.** The parser now accepts non-JSON lines only before the start marker, and reports them.
2. **`cat` moves data with `splice()`, not `read()`.** `splice` carried exactly 2 × (104,857,600 + 588,895) = 210,892,990 bytes, while `rd_reg` saw 0.8 MB (E-0018). A read/write-only capture would miss `cat` entirely.
3. **`syscalls:sys_enter_execve` was silent on 7.0** (E-0021), which broke the exec-rename split (`rename_exec` = 2 of 68 execs). It's fixed with the `raw_syscalls` bracket. The fixture was recorded before the fix and documents the failure.

A follow-up diagnostic (E-0022) showed it is broader than execve:
- **every `syscalls:sys_enter_*` tracepoint tested** (execve, openat) delivers **0 events to BPF** on 7.0 with bpftrace 0.25;
- yet tracefs, without BPF, shows the same events, and now prints the user strings;
- exits and `raw_syscalls` deliver normally.

Whether the kernel or bpftrace is at fault is open.

**Re-run with the fix** (fixture [`vm-7.0-smoke2-2026-10-25.jsonl`](testdata/), sha256 `fb23d297…1903f9f`):

| Check | Result |
|---|---|
| `exec` / `rename_exec` | 68 / 67 |
| `rename` | 31 (30 `prctl` + 1) |
| `splice` | exactly 210,892,990 B again |
| attached probes | 20 |
| output | complete |

**The probe is validated on the target.**

## Tests

```bash
python3 -m unittest -v bench/census/test_summarize.py bench/census/test_run.py
```

The summarizer has 35 tests: parsing contract, rates, budget math, reporting, CLI, and three real fixtures (one container, two VM). The runner has 17: selection, planning, bash syntax of every workload, ok/FAILED classification, report, and file churn. A runner mutation sweep of 8 deliberate bugs killed all 8.

A mutation sweep of 8 deliberate bugs killed all 8:
- no decrease check;
- no short-window merge;
- `rd_sock` counted as emitted;
- percentile off by one;
- lost events ignored;
- headroom multiplied instead of divided;
- wrong first-window baseline;
- per-class sizes ignored.
