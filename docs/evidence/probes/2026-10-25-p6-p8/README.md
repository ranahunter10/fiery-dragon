# P6 (argv at exec) and P8 (compat ABI) on the VM (2026-10-25)

**What:** `bench/probes/p6_argv/run.py --trials 1000` and `bench/probes/p8_compat/run.py`, at commit `240b7df` on branch `bench/probes-p6-p8`.

**Conditions:**
- VM `p15-dev-2604`, kernel 7.0.0-38-generic, bpftrace 0.25.0, gcc 15.2.0.
- The kernel config has `CONFIG_IA32_EMULATION=y` and does **not** set `CONFIG_IA32_EMULATION_DEFAULT_DISABLED`.
- The test programs ran as `ashu`, through runuser.

**Integrity:**
- Tarball `probes.tgz`, sha256 `0423aa064b4f70d1cfad79ab334a3efd36a344e78832eb4bcb4eb648705333c2`, as printed on the VM and matched on receipt.
- The P11 results in the same tarball are filed with the P11 PR.
- Files here are copied byte for byte (`SHA256SUMS`, 28 files).
- **Not kept**, with their sha256:
  - the built test binaries (rebuilt from the committed source by every run):
    - `p6-racer` `8e7d85f0…73b9`;
    - `p8-compat64` `5e7b6d32…b41b`;
  - P8's scratch files (`work-64/`):
    - `p8-src.dat` `4a12b181…c422`;
    - `p8-dst.dat` `463f2432…ae80`.

| Directory | What it is |
|---|---|
| `20261025T011151Z-p6`, `20261025T011154Z-p8` | **First attempt, crashed** before running the test program: `FileNotFoundError: 'runuser'` (finding 3). Kept as the record of the failure |
| `20261025T011939Z-p6` | P6, complete |
| `20261025T012006Z-p8` | P8, complete. Its `index.md` shows **9 false misses** from an analyzer bug (finding 4). [`REANALYSIS-p8.md`](REANALYSIS-p8.md) is the same raw output read by the fixed analyzer |

## Findings

### 1. P6: argv must be read at `sched_process_exec`, not at syscall entry (MEAS)

| Mode | Trials | Kernel copied the untouched all-`A` argument | Syscall-entry read = what ran | `sched_process_exec` read = what ran |
|---|---:|---:|---:|---:|
| control (nobody rewrites) | 1,000 | 1,000 | 1,000 (100 %) | 1,000 (100 %) |
| race (a thread rewrites during `execve`) | 1,000 | 93 | **45 (4.5 %)** | **1,000 (100 %)** |

- **Under the race, a tracer reading argv at syscall entry recorded something other than what the kernel executed in 955 of 1,000 execs.** The kernel itself copied 123 distinct strings across the 1,000 races.
- The copy on the new program's stack (`mm->arg_start`) matched every time. That is consistent with the source:
  - `copy_strings` runs before `bprm_execve` (`fs/exec.c` lines 1826/1846, v7.0);
  - `sched_process_exec` fires after the new mm is in place (line 1718).
- No read was missing or empty in either mode. The control mode shows the harness agrees with itself 1,000 out of 1,000.
- **Design input for the spine exec record (ADR):** take argv at `sched_process_exec` from `mm->arg_start..arg_end`. The syscall-entry hook is not needed for argv. A no-race control is only a sanity check; an attacker controls the race.

### 2. P8: the hooks see compat I/O and exec; `raw_syscalls` reports i386 numbers (MEAS, 64-bit `int $0x80` variant)

- **All 12 checks are seen** (see [`REANALYSIS-p8.md`](REANALYSIS-p8.md)):
  - `fexit vfs_read` returned 2222 and `fexit vfs_write` returned 3333, both with TS_COMPAT set;
  - `fexit security_file_open` saw both compat opens, with the file names;
  - `sched_process_exec` saw the compat `execve` of `/bin/true`.
- **`raw_syscalls:sys_enter` reports the i386 number**, 3/4/5/6/11, with TS_COMPAT set. Read with the x86_64 table, these are close/stat/fstat/lstat/munmap.
  - No id 59 or 322 appears for the compat exec.
  - **Any logic keyed on `raw_syscalls` ids must check TS_COMPAT first.**
  - The census's `rename_exec` split (ids 59/322) misses compat exec. That only affects an informational class.
- After exec'ing the 64-bit `/bin/true`, TS_COMPAT is clear at `sched_process_exec`.
- The executable itself (`gnutrue`, the target of `/bin/true`) is opened, as seen by `security_file_open`, while TS_COMPAT is still set.
- **Still OPEN: the true 32-bit variant**, where libc enters through the vDSO. The build was SKIPPED: `bits/wordsize.h: No such file or directory`, because `gcc-multilib` is not installed. Installation is decided (E-0048); after that, re-run P8.

### 3. Harness defect, found on the VM: `runuser` was not found (fixed in `240b7df`)

`subprocess` looks a program up on the *child's* PATH, which was `/usr/bin:/bin`, and `runuser` is in `/usr/sbin`. The dev-container smoke test ran as root without `SUDO_USER`, so it never took that path.

**Fix and gate:**
- `run_as` now resolves `runuser` by absolute path, and fails rather than running the program as root.
- `test_probelib.py` includes a real drop to `nobody`. It fails on the old code.

### 4. Analyzer defect, found on the VM: TS_COMPAT expected as 1, printed as 2 (fixed in this PR)

`compat.bt` prints `status & 0x2`, which is 0 or 2. The analyzer required 1, so it reported 9 misses on a run where every record was present.
- The raw output is unchanged; only the analysis was wrong.
- **Fix:** the parser normalizes the bit to 0/1.
- **Gate:** the VM's own output is now a test fixture (`bench/probes/p8_compat/testdata/`), and `test_real_vm_output_passes` fails on the old code.
- The synthetic fixtures had encoded my wrong assumption (1). Only real kernel output caught it.
