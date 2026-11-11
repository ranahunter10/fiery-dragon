# Step 2a part 3 on the target VM (2026-11-11)

Evidence for E-0161. PR #64 at `bbf5e2a`, clean tree (the binary reports `bbf5e2ac465d`). Both files' sha256 match the lines the VM printed.

| File | What | Where it ran |
|---|---|---|
| `it-p15d-2a3.txt` | `make it-p15d`: every case passed, case 9 (files open before p15d) included, in 68 s | VM p15-dev-2604, 7.0.0-38-generic, 2026-11-11 01:34 UTC |
| `mutate-p15d-2a3.txt` | `make mutate-p15d`: baseline 0 s and 68 s; 43 of 45 killed by a failed check; mutant 39 survived, mutant 43 did not build | same |

What they show (MEAS, target kernel):
- **The FD pass on the target:** case 9's holder has FD rows for fds 0-3 with the file's path; a later OPEN of the file names the row's object; the holder's exit ends the open file with CLOSE; SNAP_DONE carries the FD books with nothing lost; with 1 s segments all 5 opening snapshots have the pass, and a file opened in two segments has its facts in both.
- **Its size on an idle VM:** each run's two snapshots (opening and closing) wrote 1,435 FD rows against about 283 PROC rows: about 5 open descriptors per process (case 1; 4,816 records in all, against 3,256 for the same case before the pass).
- **Mutant 39** (the loader's facts-epoch step after the self-tests) survived: since part 3, every opening snapshot starts an epoch too, so the loader's step matters only for an object opened during the self-tests and then again only before the first snapshot, which no case did. It is not redundant: such an object's facts would be missing. Case 8 now opens a file flat out while p15d starts, stops in a pause p15d makes after its self-tests (the test switch `--test-start-pause-ms`), and opens the file once more inside it.
- **Mutant 43** did not build: removing the epoch step left `kind` unused. It now disables the step instead.

**Both gaps closed on the VM** (`0f3a594`, pasted in chat, sha256 of the VM's file `12cce419...2fcef`): `mutate_p15d.py 39 43` passed its baseline (the new pause included) and gave `killed 39 loader.c if (l->file) (75 s)`, `killed 43 snapshot.c if (kind == P15_SNAP_OPENING) (74 s)`, `2/2 killed`. With the 43 of the full sweep, all 45 p15d mutants are killed by a failed check.
