# EXEC v2 code-provenance facts checked at load; the ctime flag bit (2026-11-06)

**Where:** the dev container (kernel 6.18, not the target), then the VM `p15-dev-2604` (7.0.0-38-generic) at commit `e14c035` of `feat/exec-v2-provenance`.

**Files:**
- [`container.txt`](container.txt): the bug reproduced (the ctime mask removed, the self-test fails), the fixed self-test, the spine EXEC mutation sweep, the C tests, the records and Python sweeps, the Python tests and CI's lint.
- [`vm-selftest-and-sweep.txt`](vm-selftest-and-sweep.txt): the maintainer's VM terminal, byte for byte as attached in chat: the self-test and the spine EXEC mutation sweep. Not yet checked against a sha256 printed on the VM.

## What changed
1. The load-time self-test (`daemon/selftest.c`) checks every EXEC v2 fact (ADR-0025) of its test child's exec against `stat(2)`, `statfs(2)` and `fstat(2)` of the same objects, taken by the daemon just before the fork: the executable's ino, dev (the kernel's `MAJOR << 20 | MINOR` encoding), nlink, mode, owner, filesystem magic, ctime, mtime and name (the basename of the resolved path), the six credentials, and fds 0-2. Not checked: `exe_gen` and `self_exec_id`, which userspace cannot read.
2. Bit 31 of `inode->i_ctime_nsec` is masked off in `spine.bpf.c` and `snap.bpf.c` ([`p15_kernel.h`](../../../../bpf/include/p15_kernel.h)).
3. `bpf/test/mutate_spine_exec.py`: re-anchored to the one remaining build way, plus 8 mutants on the provenance facts.

## Results
| Claim | Grade | Where |
|---|---|---|
| Without the mask, the recorded ctime was exactly 2^31 ns above `stat(2)`'s (1787670545147483648 vs 1787670543000000000), in the container | MEAS | `container.txt` §1 |
| That is the multigrain-timestamp flag `I_CTIME_QUERIED` (bit 31 of `i_ctime_nsec`), masked by `inode_get_ctime_nsec()` | SRC (include/linux/fs.h, since 6.13), consistent with the 2^31 offset | — |
| With the mask, the self-test passes every check: container and VM | MEAS | `container.txt` §2; VM lines 7-45 |
| Spine EXEC sweep: 14/14 planted bugs killed, container and VM; on the VM this includes mutant 6 (mask removed), so the flag is set on the VM's `/bin/true` too | MEAS | `container.txt` §3; VM lines 51-65 |
| On the VM, `/bin/true` resolves to a file whose dentry name is `gnutrue`; the record's `exe_name` and the resolved basename agree | MEAS | VM lines 30, 43 |
| C tests 0 failures; records sweep 44/44; Python 17 files 0 failed, sweep 143/143; CI lint clean (container) | MEAS | `container.txt` §4-7 |

## Not yet
- The end-to-end cases of ADR-0025 confirmation 2 (a program run from an in-memory file; stdin a pipe, stdout a file, stderr a socket; PROC v2 against EXEC v2).
- The VM repeat of `bench-exec-cost` from `main` (ADR-0025 rule 8): the merge condition for this branch.
