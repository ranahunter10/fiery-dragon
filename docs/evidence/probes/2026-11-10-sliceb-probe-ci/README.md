# Step 2a dry run on CI's runner kernel (2026-11-09 23:02 UTC)

Evidence for E-0145. Not the target kernel: the target run is the maintainer's, on the VM.

| File | What | Where it ran |
|---|---|---|
| `sliceb-probe-ci.txt` | The output of `sudo build/sliceb_probe --overlay` (lines 1187-1380 of the job log, timestamps removed) | GitHub Actions job 129500406299, kernel 7.0.0-1017-azure, PR #61 at commit `6460633` |

What it shows (MEAS, runner kernel):
- The verifier accepted all five programs (fentry and kprobe.session on `security_file_open`, kprobe.multi on `security_file_free` and `security_inode_free`, `iter/task_file`) and they attached; every program's `recursion_misses` was 0.
- 81 of 83 checks passed. The two failures are one event: the FD pass read the iterator 64 KiB at a time, its 32 KiB buffer could not take one row, and the kernel showed that row again after the next copy (rows read 48 = rows written 48, one refusal counted). The probe now reads 16 KiB at a time, as p15d reads the process snapshot (`bpf/include/p15_snap.h`).
- For all 33 opens while both were attached, the kprobe.session entry ran before the fentry (`session entry first 33, fentry first 0`).
- 21 descriptors on the anonymous-inode filesystem (bpf maps, links, programs, an eventpoll, a BTF object, the iterator) all have one object id (obj 61, inode 2084): the kernel's shared anonymous inode (`fs/anon_inodes.c` lines 195-199, v7.0). Under ADR-0015 rule 3 they would be one graph node.

`SHA256SUMS` covers every file here (`sha256sum -c SHA256SUMS`).
