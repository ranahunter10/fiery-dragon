# Spine programs and self-test on the target VM (2026-10-25)

**Where:** VM `p15-dev-2604`, kernel 7.0.0-38-generic (held), clang 21.1.8, run by the maintainer at commit `b456050` (PR #27). Local time 2026-10-26 02:43 IST, which is 2026-10-25 UTC.

**What:** the command block from PR #27: `make clean`, `make -j4`, `make check`, `sudo make smoke`, then `sudo build/p15-spine dump 5 | tail -20`. Before it, `python3-numpy` 2.3.5 was installed from the archive because `make check` now runs the layout check.

| File | Content |
|---|---|
| [`spine-vm.txt`](spine-vm.txt) | the run, as written by `tee` on the VM. sha256 `0bbaef8d…5b29` matches the checksum the maintainer printed there. bpftool's colour codes are kept. |
| [`terminal.txt`](terminal.txt) | the whole terminal, including the `python3-numpy` install and the `sha256sum` line (CRLF from the copy). |
| [`dump-terminal.txt`](dump-terminal.txt) | a second run, pasted into chat (2026-10-26 02:47 IST): `dump 6` in the background while the shell runs `/bin/true` three times and `sh -c 'exit 3'`, then `stat` of `/bin/true`. Shows the last 25 matching lines of `~/spine-dump.txt` and its sha256 (`9e5b82bc…762a`); the file itself was not attached, so the first record, the self-test lines and the counters are not in the evidence. |

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
   - The programs have no PID filter (SRC: `bpf/progs/spine.bpf.c`). The second run closes the question (finding 6).
6. **Other processes are captured** (`dump-terminal.txt`, 25 records, 0 invalid).
   - For each of the three `/bin/true`: FORK by the shell (tgid 1408), RENAME `bash` → `true`, EXEC (`/bin/true` 9/9, argv `/bin/true\0` 10/10), EXIT status 0. All four records carry the start time the FORK announced.
   - `sh -c 'exit 3'`: EXEC of `/usr/bin/sh`, argv `sh\0-c\0exit 3\0` 13/13, EXIT `exit_code=768` (3 << 8).
   - Unrelated system activity was captured too: a FORK by systemd (tgid 1) and by kthreadd (tgid 2).
7. **The EXEC file identity matches `stat`.** `stat -L /bin/true` gives inode 526290 and device 2050 (0x802: major 8, minor 2 in the user-space encoding). The record has inode 526290 and device 8388610, the kernel's internal encoding of the same major 8, minor 2 (`MKDEV`, 20-bit minor). The decoder must convert one to the other before comparing with user-space tools.
8. **The last thread to exit, not the leader, carries `group_dead=1`.** A 4-thread process (tgid 1591) exited: threads 1592, 1594, then the leader 1591, all with `group_dead=0`, then thread 1593 with `group_dead=1`. So the end of a process is the EXIT with `group_dead=1`, whatever its tid, and a leader's EXIT is not the end of its process. The process tree (step 5) must use this rule, and the step-6 tests must cover it.

## Notes (INF, not results)

- `exit_code` is the kernel's wait status: 1792 = 7 << 8 for the grandchild's `_exit(7)`, 768 = 3 << 8 for `exit 3`. The 15 on tgid 1591's threads fits death by signal 15 (SIGTERM) in the same encoding. Which process 1591 was is not known.
