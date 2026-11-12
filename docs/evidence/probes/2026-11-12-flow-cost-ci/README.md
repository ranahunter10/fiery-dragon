# Step 2b read-hook harness on CI's runner kernel (2026-11-12)

Evidence for E-0232. This is not the target kernel. The target run is the maintainer's, on the VM.

| File | What | Where it ran |
|---|---|---|
| `flow-cost-ci.txt` | The output of `sudo make bench-flow-cost ROUNDS=2 READS=20000 CHECKS=2000`, from the harness's first line to the report's last (job log lines 1226 to 1333, timestamps removed) | GitHub Actions job 131304977536, kernel 7.0.0-1017-azure, PR #89 at commit `6020f59` |

What it shows (MEAS, runner kernel):
- The 7.0 verifier accepted all four kprobe.session programs, including the two that call `bpf_task_storage_get`, and they attached to `vfs_read`.
- Task storage worked there. The check pass gave 2,000 FLOWs for 2,000 reads, each `first_ts` inside its own read's `CLOCK_BOOTTIME` bracket, with no start time lost and no failed creation.
- Every book closed in every arm and round, and every program's `recursion_misses` and link `missed` were 0.
- The timings are 2 rounds on a shared runner. They are **not** a measurement: the report itself says that no comparison is resolved. The VM run decides decision waiting 13.

`SHA256SUMS` covers every file here (`sha256sum -c SHA256SUMS`).
