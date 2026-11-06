# Capturing file data-flow and fileless execution: what the field does, and the one idea that ties it together

Date: 2026-11-06. Author: Ashish Rana (with Claude).
Scope: step 3 of the capture rebuild (file and data-flow hooks) and the broader goal the maintainer set — **make fileless attacks visible, not just one technique at a time**.

Method and grades as in `dataflow_hooks.md` (the project's earlier note, re-used here, not repeated): **SRC** source at file:line@tag, **DOC** docs, **PDF** paper, **BLOG** post/threat report, **MEAS** measured here, **INF** inference. Kernel source read from torvalds/linux at **v7.0** (the VM's kernel line). Tool code read from the HEADs cloned 2026-11-06 (commit ids below). Nothing from a cloned repo was executed (CLAUDE.md).

---

## 1. The problem, stated as an invariant

"Fileless" is a family, not a technique. A payload avoids leaving a file on a watched filesystem, or avoids the syscalls a watcher hooks. The families seen in the wild and in the tools:

| family | how it runs | kernel-visible fact it cannot avoid |
|---|---|---|
| memfd_create + execveat | ELF in anonymous RAM, run via `/proc/self/fd/N` | the exec's file is a `memfd:` with link count 0 (SRC: mm/memfd.c `MFD_NAME_PREFIX "memfd:"` L338; the file comes from `shmem_file_setup`, never linked) |
| drop-to-tmpfs then exec | ELF in `/dev/shm`, `/run`, `O_TMPFILE` | the exec's file is on tmpfs / has link count 0 / path is `(deleted)` |
| delete-after-exec | run then `unlink` the binary | `/proc/pid/exe` resolves with a `(deleted)` suffix, inode link count 0 |
| userland-exec / DDexec | map ELF segments by hand, `/proc/self/mem` + `FOLL_FORCE`, jump to entry | writable memory is made executable: an `mmap(PROT_EXEC)` of anonymous memory, or `mprotect` adding X (SRC: mm/mprotect.c `security_file_mprotect` L916), and a write through `/proc/self/mem` (SRC: fs/proc/base.c `mem_rw`/`mem_write` with `FOLL_FORCE` L899-962) |
| ptrace injection | `PTRACE_POKETEXT`/`POKEDATA` into another process | a cross-process memory write under `security_ptrace_access_check` (SRC: kernel/ptrace.c L346, `ptrace_access_vm(..., FOLL_FORCE)` L616/L644) |
| process_vm_writev injection | write another process's address space | `process_vm_writev` → `mm_access(PTRACE_MODE_ATTACH_REALCREDS)` (SRC: mm/process_vm_access.c L203, L299) |
| LD_PRELOAD / ld.so.preload | load a rogue `.so` into every new process | a write to `/etc/ld.so.preload`, or the env var at exec, or a library mapped from an unusual path |
| extended-attribute payload | ELF/script bytes parked in an xattr, read back by a loader | `setxattr` of a large `user.*`/`trusted.*` value, later `getxattr`, then one of the exec paths above (SRC: fs/xattr.c `vfs_setxattr` → `security_inode_setxattr` L286; value up to `XATTR_SIZE_MAX` = 65536) |
| io_uring data-plane | read files, open/);send sockets through io_uring, not the syscalls | the op completes at `io_uring:io_uring_complete` with `req->file`/`req->opcode`, below the syscall layer (SRC/established in `dataflow_hooks.md` Q4) |
| eBPF / kernel-module implants | load a program or module to hide and act | `init_module`/`finit_module` (SRC: kernel/module/main.c L3570, L3735, via `kernel_read_file` + `security_kernel_load_data(LOADING_MODULE)` L2447), or `bpf(BPF_PROG_LOAD)` under `security_bpf_prog_load` (SRC: kernel/bpf/syscall.c L3084) |

**The invariant (the design's spine).** However the surface technique varies, running attacker code reduces to a small set of facts the kernel must see:

1. **An exec whose backing is not a persistent file on a normal filesystem** — memfd, deleted, tmpfs, link-count 0, or writable by its runner.
2. **A W→X transition in a live address space** — anonymous memory mapped or re-protected executable (own process), or a write into another process's memory (ptrace, process_vm_writev, /proc/pid/mem).
3. **A load of new kernel-side code** — module or BPF program.

4. **An interpreter whose program text comes from somewhere other than a file** — a pipe, a socket, stdin, or a `-c`/`-e` argument. Interpreted code runs inside memory that is already executable (the interpreter's own), so it trips none of facts 1–3. This fact was missing from the first draft of this note; the maintainer's xattr case (§1a) exposed it.

Everything else (xattr, the specific tmpfs path, which interpreter) is a *carrier*, useful context but not the thing to hang detection on. This note calls facts 1–4 the **code-provenance** of an execution: where the bytes that end up running came from, for native code (1–3) and for interpreted code (4). The capture layer's job in step 3 is to attach that provenance to the process tree and the data-flow graph, cheaply and with counted loss, so layer-3 detection and the FPGA enforcement see the choke point rather than chasing each carrier.

This is the one idea the maintainer asked for — "something nobody can beat." The strength is not a longer rule list than Falco's; it is that **the four facts are choke points every pathway is forced through**, captured as first-class graph attributes with the same loss accounting as the rest of the spine.

### 1a. A worked case: the ISC xattr proof of concept (BLOG, R-033)

Xavier Mertens' PoC (SANS ISC, 2025-07-17) is a good test of the framing, because it was built to be quiet:
- the payload, a short Python one-liner, is split into 32-byte chunks, each XORed with one byte and base64-encoded, so each `user.payload` value is about 44 bytes, on seven copies of an ordinary picture;
- a separate decoder reads the seven attributes, rebuilds the text and pipes it to `python3`;
- the Python code opens a TCP connection and puts the socket on the shell's standard input and output.

What it defeats, and what it can't:
- **A per-value size threshold** (MITRE DET0406's example is > 1 KB) never fires: every value is 44 bytes. A carrier rule tuned on size is evaded by chunking. What does not shrink is the *fan-in*: one process reading `user.*` attributes from seven inodes it never otherwise touches, then writing to a pipe. That is a per-process aggregate, which is what slice B's flow summaries and slice E's xattr records produce.
- **Facts 1–3 never fire**: no memfd, no deleted binary, no W→X. The code ran inside `python3`. Fact 4 does: an interpreter whose program text arrived on a pipe from a process that had just read xattrs.
- **The end of the chain is a shell whose standard input and output are a socket.** That is visible at exec as the kind and identity of file descriptors 0–2, for a few reads on a hook we already have. It also makes the classic "download piped to an interpreter" case exact: the downloader's stdout and the interpreter's stdin are the same pipe inode. Elastic matches that case with a one-second sequence window on process names (`execution_payload_downloaded_by_curl_wget_and_piped_to_interpreter.toml`); a shared pipe inode is an identity, not a time-window guess, the same move as ADR-0022's ISN join.
- **Noise:** the OS uses xattrs constantly (`system.posix_acl_*`, `security.selinux`, `security.capability`). Capture all writes (rare), but aggregate reads per process and namespace.

---

## 2. What each tool actually does (SRC/DOC, HEADs of 2026-11-06)

- **Falco libs** (`falcosecurity/libs@0815626`). On every exec *and* in its `iter.s/task` snapshot (`dump_task`), it sets four flags on the executable: `PPM_EXE_WRITABLE`, `PPM_EXE_UPPER_LAYER` (overlayfs upper = dropped into the container), `PPM_EXE_LOWER_LAYER`, `PPM_EXE_FROM_MEMFD` (driver/ppm_events_public.h L664-667; task.bpf.c L72-86). `memfd` is detected by walking the file's dentry to a self-parent whose name starts `memfd:` (extract_from_kernel.h L905-942). The snapshot reads the exe path safely inside `bpf_rcu_read_lock` on sleepable iterators (auxmap_store_params.h L2692-2708) — the very pattern ADR-0024 settled on for our snapshot.
- **Tetragon** (`cilium/tetragon@e4ea242`). At `security_bprm_committing_creds` it records `i_nlink` and flags **unlinked-binary execution** when `i_nlink == 0 && i_ino != 0`, alongside setuid/setgid/file-caps privilege changes (bpf_execve_bprm_commit_creds.c L74, L158-160). This is fact 1, captured at exec, for ~one extra field.
- **Tracee** (`aquasecurity/tracee@2f9dc40`). The widest fileless rule set, as detectors over events:
  - `fileless_execution` — exec whose `pathname` is `memfd:*`, `/run/shm/*`, `/dev/shm/*` (detectors/fileless_execution.go).
  - `dynamic_code_loading` — a W→X story from `security_file_mprotect`, as `mem_prot_alert` with four cases `MMAP_W_X`, `MPROT_X_ADD`, `MPROT_W_ADD`, `MPROT_W_REM` (tracee.bpf.c L3718-3794, types.h L258-262).
  - `proc_mem_code_injection` (write to `/proc/*/mem`), `process_vm_write_code_injection` (dst pid ≠ self), `ptrace_code_injection` (`PTRACE_POKETEXT/POKEDATA`).
  - `dropped_executable` / `hidden_file_created` — ELF magic at `magic_write`.
  - `ld_preload` — write or rename to `/etc/ld.so.preload`, or the `LD_PRELOAD` env at exec.
  - `default_loader_modification` — writes under `/lib`, `/usr/lib`. Kernel-module and bpf load paths are hooked too.
- **Kunai** (`kunai-project/kunai@3d27742`). Two reusable mechanisms:
  - **File dedup as a flag set**, not an event per I/O: an LRU hash `FileKey(sb_ino, f_ino) → {READ, WRITE, CLOSE_AFTER_WRITE}`; the first read and first write of a file are reported, repeats folded (probes/fs.rs L40-84).
  - **Explicit rate caps with counters**: per-task and global events-per-second limits over a 1 s sampling window (fs.rs L93-150) — loss is bounded and counted, never silent.
  - `mprotect` adding `PROT_EXEC` caught at `raw_tracepoint/sys_enter` (probes/mprotect.rs).
- **Elastic ebpf** (`elastic/ebpf@51b6ec7`). `fexit/vfs_write` + `vfs_writev` with a **kprobe fallback** and the return-slot index resolved from the running kernel's BTF at load (Probe.bpf.c L784-803, Helpers.h L61-123); memfd flags decoded on `memfd_create`. The lesson is operational: guard every fexit with a BTF check and a fallback.
- **ClamAV** (`Cisco-Talos/clamav@dd3aa19`). On-access scanning via **fanotify** `FAN_OPEN_PERM`/`FAN_ACCESS_PERM` on a mount mark (clamonacc/fanotif/fanotif.c L87-127). Relevant as a cross-check source (a second, independent view of file opens), not as a capture hook.
- **auditd** (`linux-audit/audit-userspace@e505950`). Ships rule sets we can mirror as a coverage checklist: `setxattr`/`getxattr` (30-stig.rules L117), `ptrace -F a0=0x4/0x5/0x6` for POKE/register injection (42-injection.rules), `init_module,finit_module` (43-module-load.rules).
- **osquery** (`osquery/osquery@711974b`), **Velociraptor** (`6d45bf8`), **Wazuh** (`2940bdf`), **GRR** (`d71034a`). Snapshot/forensic, not real-time capture, but each carries one idea worth stealing:
  - osquery has a first-class `extended_attributes` table (tables/system/linux/extended_attributes.cpp) — xattrs are treated as ordinary queryable state.
  - Velociraptor's `Linux.Sys.Maps` parses `/proc/pid/maps` for `(deleted)` and permission bits — the userspace twin of our snapshot's provenance.
  - Wazuh rootcheck does a **cross-view** hidden-process check: compare `kill(pid,0)`/`getsid`/`getpgid`/`/proc` against `ps` (rootcheck/src/check_rc_pids.c L122-241). Our opening-vs-closing snapshot reconciliation (ADR-0023) is the same idea applied to the capture's own books.
- **CrowdSec** (`849c7a2`) / **fail2ban** (`fd09a9d`). Leaky-bucket (`rate.NewLimiter(rate.Every(leakspeed), capacity)`, pkg/leakybucket/bucket.go L85) and sliding-window (`findtime`/`maxretry`). These are the aggregation shapes for turning a storm of I/O events into a few graph edges with a counter — the same role as Kunai's EPS cap and our in-kernel first-touch.
- **OpenEDR** (`30b36f2`) is Windows-only (kernel driver `edrdrv`, user hooks `edrpm`); no Linux capture to learn from.

**The gap we can be better than.** Every tool above detects *techniques* (a memfd exec, a mprotect W→X, a ptrace poke) as independent events or rules. None of them carries **code-provenance as a single, loss-accounted attribute on the process-and-dataflow graph** that the four facts all feed. That is the design below.

---

## 3. The io_uring blind spot (BLOG, confirmed against our own notes)

ARMO's "Curing" PoC (2025) performs file reads and socket I/O entirely through io_uring, and reported Falco, some Tetragon policies, and MS Defender for Endpoint on Linux blind to it, because they hook **syscalls**. Our capture already avoids that trap for the network side (we hook `inet_*`, not `sys_enter_connect`), and `dataflow_hooks.md` Q4 settled the file side on `tp_btf/io_uring_complete` (`req->file`, `req->opcode`, `cqe->res`), which fires below the syscall layer. So io_uring coverage is a design we already hold; step 3 must *implement* it, and the load-time self-test must include one io_uring read so the coverage is proven, not assumed (the ARMO lesson). (BLOG: armosec.io io_uring rootkit; SRC: our Q4.)

---

## 4. Cross-domain framing (INF — framing only, never a result)

The maintainer asked for ideas from other fields. These shaped the design above; none is evidence.

- **Immunology, self/non-self.** The opening snapshot (ADR-0007) is a census of "self": the set of executable inodes already trusted at capture start. Fact 1 — exec from a non-persistent backing — is literally "non-self code executing." The provenance attribute is a negative-selection marker. This is why provenance belongs on the snapshot *and* on exec, not only on exec.
- **Thermodynamics, a conservation law.** Code cannot execute from memory that was never made executable. W→X is the only "reaction" that converts attacker-written bytes into runnable code. Watching the W→X choke point (fact 2) is watching the one place energy must pass, rather than every molecule.
- **Chemistry, catalysis / rate-limiting step.** Of the dozens of carriers, four reactions are mandatory intermediates (facts 1–4). Instrument the rate-limiting step, not the reactants.
- **Information theory, first-touch coding.** Kunai's "first read, first write, then fold" and our in-kernel aggregation (dedup where a miss yields a duplicate, never a loss) are a lossy code chosen so the error is always on the safe side. Pair it with a leaky-bucket (CrowdSec) to bound event rate with a counter.
- **Epidemiology, contact tracing.** The provenance graph is a transmission graph; a leaky-bucket overflow is an outbreak threshold. This is layer-3's to use, but the capture must preserve the edges it needs.

---

## 5. What this leads to (decisions to raise, in the maintainer's one-at-a-time style)

The hooks, cheapest-and-highest-value first. Each becomes a proposed ADR when its slice starts; costs from `dataflow_hooks.md` Q6.

1. **Exec-time code-provenance (slice A, no new attach point).** On the existing `sched_process_exec` classic tracepoint and in the existing snapshot (`snap.bpf.c`):
   - flags on the executable: `WRITABLE`, `FROM_MEMFD`, `DELETED`/`nlink==0`, `UPPER_LAYER` (overlayfs), and the exe's `nlink` (fact 1; mirrors Falco and Tetragon);
   - the kind (socket, pipe, regular file, tty or other character device) and identity (inode; socket cookie for sockets) of file descriptors 0, 1 and 2 (fact 4's input side, and the socket-on-stdio end of a reverse shell; joins with NET records by cookie and with the writer of a pipe by inode).
   A few CO-RE reads on hooks we already pay for. **Highest value per line; start here.**
2. **File data-flow (slice B, ADR-0015 file identity + ADR-0005 filtering).** `fexit vfs_read/vfs_write/vfs_readv/vfs_writev` with in-kernel first-touch aggregation (Kunai's flag-set shape) and a counted per-task + global cap (Kunai/CrowdSec). BTF-guarded with a kprobe fallback (Elastic). Add `tp_btf/io_uring_complete` and the `sock_*_length` tracepoints so the io_uring and socket data planes are not blind. Size it with the census first.
3. **W→X transitions (slice C, fact 2).** `fexit security_file_mprotect` (verdict + prev/req prot, the four Tracee cases) and `security_mmap_file` for anonymous PROT_EXEC. This is the userland-exec / DDexec choke point. One more program; cost ~fexit.
4. **Cross-process memory writes (slice D, fact 2).** `security_ptrace_access_check` and the `process_vm_writev`/`/proc/pid/mem` write paths. Rare events; cheap.
5. **Carriers as context (slice E).** xattr writes (`security_inode_setxattr`, flag large `user.*`/`trusted.*`), `/etc/ld.so.preload` writes, module/bpf load (`security_kernel_load_data(LOADING_MODULE)`, `security_bpf_prog_load`). Rare; attach to the provenance of the process that did them.

Each slice keeps the project's rules: a proven attach point on the VM (the census already shows every function in §1 is BTF+ftrace-attachable on 7.0.0-38, `docs/evidence/phase0/02-p1-attach-points.txt`), counted loss, a load-time self-test that exercises the path (incl. one io_uring read and one memfd exec), and no number without a harness.

**Open questions for the maintainer, when each slice starts:**
- Slice A: carry provenance as new fields on EXEC (needs EXEC v2) or a separate record? (Recommend EXEC v2; provenance and stdio are facts of that exec and cannot change after it.)
- Slice B: `vfs_*` fexit vs the single `security_file_permission` choke point that gives no bytes — the classic coverage/precision trade from `dataflow_hooks.md` Q8. (Recommend `vfs_*` + io_uring + sock, so bytes are captured.)
- Slice B: the aggregation key and window (per `(task, file)` first-touch, with a leaky-bucket cap) — numbers needed from a census run before fixing constants.
