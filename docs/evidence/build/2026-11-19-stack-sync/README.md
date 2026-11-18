# The repository brought up to date (2026-11-19)

**Where:** the dev container (kernel 6.18, not the target). Nothing here ran on the VM. The make
checks build and run the user-space tests only: none of this proves kernel-side behaviour.

**Files:**
- [`repo-state-2026-11-18.txt`](repo-state-2026-11-18.txt): before the work. `main`, the open PRs and their merge state (#90 `dirty`), #90's checks, and GitHub's branches compared with Dragon's bundle of 2026-11-15.
- [`branches.txt`](branches.txt): after the work. Every branch pushed from Dragon's zips, its commit and tree on GitHub, and the tree the zip's README names.
- [`pr90-merge-make-check.txt`](pr90-merge-make-check.txt): `make check` on `capture/flow-programs` after `main` (to #96) was merged in.
- [`flow-ring-make-check.txt`](flow-ring-make-check.txt), [`workloads-make-check.txt`](workloads-make-check.txt): `make check` at the heads of the two chains.
- [`report-submitted.txt`](report-submitted.txt): the submitted Phase II report against the v3 build (sha256, `cmp`, page count). The PDFs themselves are not in the repository.

## Results

| Claim | Grade | Where |
|---|---|---|
| #90 conflicted with `main` only in `docs/STATE.md`'s "Last updated" line. After the merge: 29 test files, 0 failed; 79 checksum files, 0 failed | MEAS | `pr90-merge-make-check.txt` |
| All 8 branches pushed from Dragon's zips hold the tree their zip's README names | MEAS | `branches.txt` |
| `make check` at `dragon/flow-ring`: 29 test files, 0 failed; 89 checksum files, 0 failed | MEAS | `flow-ring-make-check.txt` |
| `make check` at `dragon/workloads`: 31 test files, 0 failed; 84 checksum files, 0 failed | MEAS | `workloads-make-check.txt` |
| The submitted Phase II report is byte-identical to the v3 build (25 pages) | MEAS | `report-submitted.txt` |
