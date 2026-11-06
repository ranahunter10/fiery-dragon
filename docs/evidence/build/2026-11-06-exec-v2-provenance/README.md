# EXEC v2 code-provenance facts checked at load; the ctime flag bit (2026-11-06)

**Where:** the dev container (kernel 6.18, not the target), then the VM `p15-dev-2604` (7.0.0-38-generic) at commit `e14c035` of `feat/exec-v2-provenance`.

**Files:**
- [`container.txt`](container.txt): the bug reproduced (the ctime mask removed, the self-test fails), the fixed self-test, the spine EXEC mutation sweep, the C tests, the records and Python sweeps, the Python tests and CI's lint.
- [`container-it.txt`](container-it.txt): the whole end-to-end test with the new case 6, then the case-6 checker run against expectations tampered five ways ([`c6neg.sh`](c6neg.sh)).
- [`vm-selftest.txt`](vm-selftest.txt) and [`vm-mutate-spine.txt`](vm-mutate-spine.txt): the self-test and the spine EXEC mutation sweep as `tee` wrote them on the VM. Both match the sha256 the maintainer printed there (`c28e9e24…` and `a0ee11aa…`).
- [`vm-selftest-and-sweep.txt`](vm-selftest-and-sweep.txt): the same run as the maintainer's terminal showed it (both commands in one log), attached in chat first. Its content is the two files above plus the commands.

## What changed
1. The load-time self-test (`daemon/selftest.c`) checks every EXEC v2 fact (ADR-0025) of its test child's exec against `stat(2)`, `statfs(2)` and `fstat(2)` of the same objects, taken by the daemon just before the fork: the executable's ino, dev (the kernel's `MAJOR << 20 | MINOR` encoding), nlink, mode, owner, filesystem magic, ctime, mtime and name (the basename of the resolved path), the six credentials, and fds 0-2. Not checked: `exe_gen` and `self_exec_id`, which userspace cannot read.
2. Bit 31 of `inode->i_ctime_nsec` is masked off in `spine.bpf.c` and `snap.bpf.c` ([`p15_kernel.h`](../../../../bpf/include/p15_kernel.h)).
3. `bpf/test/mutate_spine_exec.py`: re-anchored to the one remaining build way, plus 8 mutants on the provenance facts.

## Results
| Claim | Grade | Where |
|---|---|---|
| Without the mask, the recorded ctime was exactly 2^31 ns above `stat(2)`'s (1787670545147483648 vs 1787670543000000000), in the container | MEAS | `container.txt` §1 |
| That is the multigrain-timestamp flag `I_CTIME_QUERIED` (bit 31 of `i_ctime_nsec`), masked by `inode_get_ctime_nsec()` | SRC (include/linux/fs.h, since 6.13), consistent with the 2^31 offset | — |
| With the mask, the self-test passes every check: container and VM | MEAS | `container.txt` §2; `vm-selftest.txt` |
| Spine EXEC sweep: 14/14 planted bugs killed, container and VM; on the VM this includes mutant 6 (mask removed), so the flag is set on the VM's `/bin/true` too | MEAS | `container.txt` §3; `vm-mutate-spine.txt` |
| On the VM, `/bin/true` resolves to a file whose dentry name is `gnutrue`; the record's `exe_name` and the resolved basename agree | MEAS | `vm-selftest.txt` lines 25, 38 |
| End-to-end, case 6 (container): a program run from a memfd is recorded with `exe_name` `memfd:p15-it`, nlink 0 on tmpfs, and classed 'runs from memory'; stdin a pipe, stdout a file, stderr a socket each match `fstat(2)` of the object the workload opened; `echo | cat` is joined writer → reader by pipe inode and shown by p15-trace; a process alive at the closing snapshot has PROC v2 and EXEC v2 agreeing on all 17 shared facts. The whole test passes (0 failed checks) | MEAS | `container-it.txt` |
| The case-6 checker fails on each of five tampered expectations, naming the check | MEAS | `container-it.txt`, end |
| C tests 0 failures; records sweep 44/44; Python 17 files 0 failed, sweep 143/143; CI lint clean (container) | MEAS | `container.txt` §4-7 |

## Also
- The VM repeat of `bench-exec-cost` (ADR-0025 rule 8): [`../../probes/2026-11-06-exec-cost-vm/`](../../probes/2026-11-06-exec-cost-vm/README.md).

## Not yet
- Case 6 on the VM and in CI (this PR's CI run is the first).
