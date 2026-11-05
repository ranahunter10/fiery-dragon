# The 2026-11-05 merge of #32–#46, verified (2026-11-05)

**What:** the maintainer's decision 13 (merge commits, in order) carried out by this session, and the checks that it landed what the VM and CI verified.

**Files:**
- [`merge.txt`](merge.txt): the tree comparison, `main`'s new first-parent history, the evidence commits, and which remote branches `main` contains;
- [`fresh-clone.txt`](fresh-clone.txt): `make check` on a fresh clone of `main`.

## Findings (MEAS)

1. **`main` is byte-identical to the verified tip.** After merging #32–#46 with merge commits, `main`'s tree is `8e533cc…`, the tree of #46's head `193c51f`. That head contains every commit the VM ran (`cc757c4`) and CI passed.
2. **The evidence's commit hashes stay reachable.** `42eb513` (the "before" of E-0095), `cc757c4` (the VM rerun), `c112803` and `9407485` are all ancestors of `main`. Squash merges would have left them only in the PR refs. That was the reason for decision 13.
3. **A fresh clone passes.** On a fresh clone of `main` at `9e8162d`, after `git submodule update --init --recursive` (the Makefile asks for it), `make check` exits 0 and `make it-p15d` passes. Case 5 is skipped in the container, as always.
4. **45 merged branches are fully contained in `main`.**
   - They can be deleted. This session can't delete branches: the GitHub proxy refuses both the API call and `git push --delete`. The maintainer runs the deletion.
   - `bench/census-probe` isn't contained: its 3 commits are patch-equivalent to commits in `main`. A test docstring cited one of them (`cb836f9`), reachable from no PR ref. That citation is repointed to `main`'s identical `5aa5002` in this PR, after which the branch can go too.
   - The other branches that aren't contained are this session's open PRs, #47–#51.
