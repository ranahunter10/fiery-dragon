# Step 2a part 2 on the target VM: the end-to-end test (2026-11-10)

Evidence for E-0151 and E-0152. PR #63 at commit `4d6168e` (the binary reports `4d6168e901a9-dirty`: the VM's tree had local changes; `git status --short` there is still to be sent).

| File | What | Where it ran |
|---|---|---|
| `it-p15d-2a.txt` | `sudo P15_PYTHON=... P15_IT_NET=1 make it-p15d`: every case passed, case 8 (file identity) included | VM p15-dev-2604, kernel 7.0.0-38-generic, 2026-11-10 11:18 UTC, sent by the maintainer |
| `p15d-2a-stats.txt` | **Not a result.** The command given in chat expanded `/var/tmp/p15-2a/*/` in the user's shell, which cannot read the root-owned run directory, so `p15w-inspect` was handed a path that does not exist and printed zero records. The 30 s run itself exited 0 | same |
| `terminal.txt` | The terminal session: the two sha256 lines match the files here; `make -j3 all` as the user failed to link `build/test_run` (the file is root-owned from an earlier `sudo make`), then `sudo make it-p15d` built everything; `make mutate-p15d` exited 2 and its output file has not been sent (sha256 `9a5aa4cb...acb5a`) | same |

What `it-p15d-2a.txt` shows (MEAS, target kernel):
- The file-identity object loads, attaches and passes its load-time self-test in every run (`files=on`); the runs' books close with it (`invariant 1`), also under the forced spine overflow of case 3.
- Case 1 (200 runs of `/bin/true` in 8 s on an otherwise idle VM): 1,060 OPEN and 1,061 CLOSE records against 814 spine records; the whole segment is 353,424 bytes for 3,328 records.
- Case 8: OPEN with path and facts for the create (tmpfs, `magic=0x1021994`), the reopen by another process naming the same object without its facts again, CLOSE for the first open file, CLOSE flagged NEVER_OPENED for the FIFO.
- CLOSE outnumbers OPEN in three runs (1,061/1,060; 2,036/2,029; 192/185): files whose OPEN was taken by the load-time self-tests' reader or that were registered by the session entry before the drain began. The same reader threw away object facts (E-0151, fixed by the facts epoch).

`SHA256SUMS` covers every file here (`sha256sum -c SHA256SUMS`).
