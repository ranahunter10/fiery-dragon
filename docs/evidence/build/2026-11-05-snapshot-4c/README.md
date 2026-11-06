# Step 4c built: the process snapshot, the closing snapshot and the reconciliation (2026-11-05)

**Where:** first the dev container (kernel 6.18, not the target), then the VM `p15-dev-2604` (7.0.0-38-generic): `vm_verify.sh` run `20261106T074939Z` at commit `6905850`, the head of #53, with the host on its charger in Best performance mode. CI's runner (7.0.0-1017-azure) also passes the end-to-end test, with the pid-1 check on.

**Files:**
- [`container.txt`](container.txt): the schema and layout checks, the C tests (also under ASan), the Python tests, the C→Python cross-check, both planted-bug sweeps, the end-to-end test, one run inspected record by record, p15-trace's Trust block, and two findings (E-0105 and the verifier's refusal).
- [`vm-verify-20261106T074939Z.log`](vm-verify-20261106T074939Z.log): the VM run's full log, all 18 steps.
- [`vm-step10-rerun.txt`](vm-step10-rerun.txt): step 10 run again by hand. Its first run failed before compiling anything, because `/tmp` was out of space (below).
- [`vm-snapshots.txt`](vm-snapshots.txt): the SNAP_DONE, END and pid-1 PROC records of two VM runs, step 14's kept run and a 10-second run of p15d on the live system, each followed by a count of PROC records with an empty path.
- [`vm-trace-live.txt`](vm-trace-live.txt): p15-trace on that 10-second run.

All four VM files match the sha256 sums the maintainer printed on the VM.

## What changed
1. **Schema:** PROC (37) is one thread group in a snapshot: parent key, executable identity and path, argv, comm, kernel-thread and exiting flags. SNAP_DONE (38) carries the books. END v2 adds `closing_snapshot` (ADR-0023 rule 1).
2. **BPF** ([`snap.bpf.c`](../../../../bpf/progs/snap.bpf.c)) is a sleepable task iterator, run on thread-group leaders only:
   - argv comes through `bpf_copy_from_user_task`;
   - the path comes from the file mapped at `mm->start_code`, read under the mmap lock through `bpf_iter_task_vma` and only when it is `mm->exe_file` (ADR-0024 rule 1);
   - every early return is counted.
3. **p15d** ([`snapshot.c`](../../../../daemon/snapshot.c), [`snapshot_frame.c`](../../../../daemon/snapshot_frame.c)):
   - an opening snapshot at every segment open, through the WAL's `on_open`;
   - a closing one at an orderly stop, taken by the writer thread while the hooks are attached, with main draining meanwhile;
   - every record is checked;
   - the books must close, or the run is INVALID.
4. **Readers:**
   - `records.c` and `records.py` check PROC, SNAP_DONE and END v2 the same way;
   - `p15w-inspect` prints them;
   - the process tree takes pre-existing processes' parents and programs from the opening snapshot;
   - `reconcile.py` checks the tree against the closing snapshot (ADR-0023 rule 2, with ADR-0024 rule 4's window);
   - p15-trace's Trust block shows the verdict.

## Findings (MEAS, VM)
- **18 of 18 steps pass.** Step 10 passes in its rerun (39/39). No step was marked with a host stall: 0 soft lockups in the whole run, where the last run (E-0104) had 16 on battery. The planted-bug sweeps catch Python 148/148, WAL writer 27/27, p15d 20/20, spine 7/7 and record checks 39/39.
- **Every snapshot is complete, and its books close.**

  | run | snapshot | tasks = threads + entries | kernel threads | read failures, path problems, cuts | time |
  |---|---|---|---|---|---|
  | step 14, case 5 | opening | 171 = 30 + 141 | 105 | 0 | 0.91 ms |
  | step 14, case 5 | closing | 171 = 31 + 140 | 105 | 0 | 0.34 ms |
  | live, 10 s | opening | 165 = 30 + 135 | 103 | 0 | 0.21 ms |
  | live, 10 s | closing | 166 = 31 + 135 | 103 | 0 | 0.27 ms |

  - The PROC records with an empty path number twice the kernel threads (210 and 206), so every user process has its path.
  - systemd (pid 1) is in every snapshot, with `/usr/lib/systemd/systemd` and its argv. So E-0105 is the dev container's alone.
  - The 0.91 ms snapshot ran while the test suite was loading the VM.
- **Reconciliation:**
  - case 1 (200 short processes): **complete**, 0 unexplained forks and 0 unexplained exits;
  - case 3 (forced overflow): **repaired**, 10 lost EXITs located within the 320 counted (ADR-0023 confirmation 3);
  - the live run: **complete**. All 135 processes take their parent and program from the opening snapshot, and none is outside it.
- **Step 10's first failure was `/tmp`, not the code.**
  - `/tmp` is a tmpfs with a per-user quota. One planted bug in step 9 broke the WAL's size limit, so `test_wal` wrote 2.9 GB to `/tmp/p15w-test-jQ9nMi` until the 60 s timeout killed it.
  - A killed test never removes its directory, so step 10's compiler then hit "Disk quota exceeded".
  - Step 9 counted that bug as caught, correctly. The leak is a bug in the sweep, fixed in its own PR.

## Findings (MEAS, container)
- **Snapshots:** both are complete in every end-to-end run. In the inspected run, 86 tasks = 22 threads + 64 records (57 of them kernel threads), and every user process has its path and argv. The opening snapshot took 124 µs and the closing one 142 µs for about 86 tasks. This is the container; the VM's times are in the table above (ADR-0023's falsifier).
- **Reconciliation, case 1** (200 short processes, no loss): **complete**, 0 unexplained forks, 0 unexplained exits (ADR-0023 confirmation 2).
- **Reconciliation, case 3** (forced spine overflow): **repaired**. 27 lost EXITs are located to their processes, within the 383 exit losses the run counted. No FORK is unexplained: the children that lost theirs had all exited by the end, which is outside this check by design (ADR-0023 confirmation 3).
- **Tests:**
  - C: 8 test programs, 0 failures, also under ASan/UBSan;
  - Python: 17 files, 0 failures (14 new reconciliation tests);
  - the C-written PROC, SNAP_DONE and END v2 decode field by field in Python.
- **Planted bugs:** record checks 39/39 (11 new), Python 148/148 (20 new).
- **E-0105:** the container's kernel never shows pid 1 to a task iterator, even one asked for tid 1 alone, while `/proc/1` is a normal process. The cause is not known (OPEN). `it_p15d.sh` checks that pid 1 is in the opening snapshot; here that check is off (`P15_IT_PID1=0`). It must pass on the VM.
- **ADR-0024 evidence 4:** without the RCU section, the verifier refuses `bpf_d_path(&vma->vm_file->f_path)` in a sleepable program, with `R1 type=untrusted_ptr_`.
