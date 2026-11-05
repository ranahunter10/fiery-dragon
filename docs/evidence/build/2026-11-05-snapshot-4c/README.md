# Step 4c built: the process snapshot, the closing snapshot and the reconciliation (2026-11-05)

**Where:** the dev container (kernel 6.18, not the target). It loads and runs the task iterator, so the snapshot itself is proved here. It can't load fexit (E-0078), so the network case is skipped; the VM run comes next.

**File:** [`container.txt`](container.txt): the schema and layout checks, the C tests (also under ASan), the Python tests, the C→Python cross-check, both planted-bug sweeps, the end-to-end test, one run inspected record by record, p15-trace's Trust block, and two findings (E-0105 and the verifier's refusal).

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

## Findings (MEAS, container)
- **Snapshots:** both are complete in every end-to-end run. In the inspected run, 86 tasks = 22 threads + 64 records (57 of them kernel threads), and every user process has its path and argv. The opening snapshot took 124 µs and the closing one 142 µs for about 86 tasks. This is the container; the VM's cost is still to be measured (ADR-0023's falsifier).
- **Reconciliation, case 1** (200 short processes, no loss): **complete**, 0 unexplained forks, 0 unexplained exits (ADR-0023 confirmation 2).
- **Reconciliation, case 3** (forced spine overflow): **repaired**. 27 lost EXITs are located to their processes, within the 383 exit losses the run counted. No FORK is unexplained: the children that lost theirs had all exited by the end, which is outside this check by design (ADR-0023 confirmation 3).
- **Tests:**
  - C: 8 test programs, 0 failures, also under ASan/UBSan;
  - Python: 17 files, 0 failures (14 new reconciliation tests);
  - the C-written PROC, SNAP_DONE and END v2 decode field by field in Python.
- **Planted bugs:** record checks 39/39 (11 new), Python 148/148 (20 new).
- **E-0105:** the container's kernel never shows pid 1 to a task iterator, even one asked for tid 1 alone, while `/proc/1` is a normal process. The cause is not known (OPEN). `it_p15d.sh` checks that pid 1 is in the opening snapshot; here that check is off (`P15_IT_PID1=0`). It must pass on the VM.
- **ADR-0024 evidence 4:** without the RCU section, the verifier refuses `bpf_d_path(&vma->vm_file->f_path)` in a sleepable program, with `R1 type=untrusted_ptr_`.
