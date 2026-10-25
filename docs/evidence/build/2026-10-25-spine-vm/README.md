# Spine programs and self-test on the target VM (2026-10-25)

**Where:** VM `p15-dev-2604`, kernel 7.0.0-38-generic (held), clang 21.1.8, run by the maintainer at commit `b456050` (PR #27). Local time 2026-10-26 02:43 IST, which is 2026-10-25 UTC.

**What:** the command block from PR #27: `make clean`, `make -j4`, `make check`, `sudo make smoke`, then `sudo build/p15-spine dump 5 | tail -20`. Before it, `python3-numpy` 2.3.5 was installed from the archive because `make check` now runs the layout check.

| File | Content |
|---|---|
| [`spine-vm.txt`](spine-vm.txt) | the run, as written by `tee` on the VM. sha256 `0bbaef8d…5b29` matches the checksum the maintainer printed there. bpftool's colour codes are kept. |
| [`terminal.txt`](terminal.txt) | the whole terminal, including the `python3-numpy` install and the `sha256sum` line (CRLF from the copy). |

## Findings (MEAS, target)

1. **Build and checks pass on the target from clean.**
   - `make` exits 0.
   - `make check` exits 0:
     - schema check: 0 problems;
     - three-way layout check: 0 disagreements across 5 structs. The BTF comes from the VM's clang 21 and the numpy is the VM's 2.3.5.
     - C unit tests: 0 failures;
     - 8 Python test files: 0 failed;
     - 11 evidence checksum files and `vmlinux.h`: ok.
2. **All four spine programs pass the 7.0 verifier and attach:** `p15-spine: libbpf v1.7, 4 programs attached`.
3. **The self-test passes 21 of 21 checks, in both runs** (`make smoke` and `dump`). Each run collected 7 records, none invalid. The records are the same as in the dev container:
   - the test child: RENAME by prctl, FORK of the grandchild, RENAME by exec, EXEC, EXIT;
   - the grandchild: one EXIT;
   - every record carries the start time its FORK announced (ADR-0009);
   - EXEC filename `/bin/true` (9 of 9 bytes) and argv `true\0fd-selftest\0` (17 of 17), no flags.
4. **Counters: nothing lost and the books balance.** For every type, `reserve_failed` is 0 and `seen == emitted` (FORK 2, EXEC 1, EXIT 2, RENAME 2).
5. **`dump 5` recorded 0 records after the self-test.**
   - The counters after it are the self-test's own 7 events. So the programs did not fire at all in those 5 s. The records were not dropped (the counters count before the reserve).
   - The VM was idle (one ssh session, nothing scheduled).
   - The programs have no PID filter (SRC: `bpf/progs/spine.bpf.c`), and the self-test's processes are ordinary processes. But **capture of processes the tool did not create has not yet been observed on the target: OPEN.**

## Notes (INF, not results)

- `exit_code=1792` is the kernel's wait status, 7 << 8, for the grandchild's `_exit(7)`. The self-test decodes it as status 7.
- `exe=8388610:526290`: 8388610 is the kernel's internal `dev_t` for major 8, minor 2 (`MKDEV`, 20-bit minor), and 526290 the inode of `/bin/true`. Neither has been compared with `stat` on the VM yet.
