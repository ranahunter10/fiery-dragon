# The handoff of 2026-11-18, checked in a cloud session

Run on 2026-11-18 in a Claude cloud session container (Python 3.13.18; no DuckDB, no google-crc32c,
no libelf-dev, and package installs blocked), not on the VM. Nothing here is a BPF or kernel result.

| File | What it holds |
|---|---|
| `package-and-repo-checks.txt` | the package's checksums, GitHub's branches against Dragon's bundle, `main`'s commit, and the trees after `git am` against `prs/README.md` (E-0329) |
| `make-check-main.txt` | `make check` on a fresh clone of `main` (b5331c2), after `git submodule update --init --recursive`: it stops at `deps` (libelf-dev) |
| `python-tests-main.txt`, `check-evidence-main.txt` | `tools/ci/run-tests.sh` and `tools/ci/check-evidence.sh` on that clone: 29 test files, 20 pass, 9 fail on import of the two missing pinned packages; 75 of 75 checksum files |
| `python-tests-branch.txt` | `tools/ci/run-tests.sh` on `feat/graph-story-viewer`: 32 files, 21 pass (`test_viewer.py` 27 tests), 11 fail on the same imports; `test_rules.py` is one of them, so its new cross-check did not run here (E-0328) |

The open PRs could not be read: this session's GitHub API access to the repository was refused (HTTP 403).

`SHA256SUMS` covers every file here.
