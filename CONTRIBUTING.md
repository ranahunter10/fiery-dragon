# Contributing to Fiery Dragon

These rules apply to everyone: the maintainer, AI coding sessions, and anyone else. Each rule exists because something went wrong without it in the previous capture layer.

## 1. Flow

1. `main` is always releasable and **protected**. Nobody pushes to it directly.
2. Every change starts on a branch from the latest `main`:

   | Branch prefix | For |
   |---|---|
   | `feat/<area>-<topic>` | new capability, e.g. `feat/bpf-file-flow` |
   | `fix/<area>-<topic>` | a bug fix |
   | `adr/NNNN-<topic>` | a decision record |
   | `docs/<topic>` | documentation only |
   | `chore/<topic>` | tooling, CI, dependencies |
   | `bench/<topic>` | measurement harnesses and results |

3. Open a pull request. CI must pass and the maintainer must approve.
4. **Squash-merge**, so `main` gets one commit per PR, titled with the PR title.
5. Delete the branch after the merge.
6. **Tags and releases are created by the maintainer only.** An AI session marks a release candidate with a `release/vX.Y.Z` branch and supplies the tag commands.

## 2. Commits

```
<area>: <imperative summary, ≤ 72 chars, no final period>

<why the change is needed, what it changes, wrapped at 72 columns>

Refs: ADR-0003, #12
Signed-off-by: Full Name <email>
```

- **`area`** is one of:
  - `bpf`, `daemon`, `schema`, `py`, `bench`, `tests`, `tools`, `ci`, `docs`, `adr`, `build`;
  - or a sub-area, e.g. `py/graph`, `bpf/file`.
- **Summary:** imperative ("add", "fix", "drop", not "added" or "fixes").
- **Body:** say *why*. The diff already shows *what*.
- **`Signed-off-by`** (`git commit -s`) is required. It certifies the [Developer Certificate of Origin](https://developercertificate.org/): you have the right to submit this code under the repo's licenses.
- **`Fixes: <12-char sha> ("<subject>")`** when the commit fixes an earlier commit.
- **AI-assisted commits** keep the session's attribution trailers (`Co-Authored-By:` and the session link). The maintainer's sign-off means they reviewed it.

Good examples:
- `bpf/file: emit FILE_FLOW from fexit vfs_read with byte count`
- `daemon/wal: truncate torn tail on CRC mismatch at open`
- `adr: 0003 revise hook policy to BTF-checked attach points`

## 3. Pull requests

- **Small and single-purpose.** As a guide, ≤ ~400 changed lines, excluding generated files and evidence. Larger work becomes a stack of PRs, each reviewable on its own.
- **The description follows the template** (`.github/PULL_REQUEST_TEMPLATE.md`). The four required parts are:
  1. **What to look at first:** the 3–5 places where a bug would hide.
  2. **What it does not do.**
  3. **The exact test command, with its pasted output.**
  4. **The decisions it assumes** (ADR numbers).
- **Generated code is reviewed through its generator and its tests**, not line by line.
- **Every review comment gets an answer** before merge. "Looks fine" is not an answer.
- **The author never grades their own work.** The reviewer re-runs the test command in a fresh clone.

## 4. Decisions (ADRs)

- **Any decision that is hard to reverse, or that someone could reasonably have made differently, is an ADR** in `docs/decisions/NNNN-<title>.md`, using the MADR template there. That covers platform, hooks, record format, identity rules, test adequacy and similar.
- **Every ADR states:**
  - its **owner**;
  - its **date**;
  - the **evidence**, each claim graded SRC / DOC / PDF / MEAS / INF / OPEN;
  - the **options considered**;
  - its **falsifier**: what observation would reopen it.
- **An ADR is never edited after it is accepted.** A change is a new ADR that *supersedes* it, and both stay in the repo.

## 5. Evidence

- **No number without a harness.** Every figure quoted in `docs/` links to the raw output that produced it, under `docs/evidence/`, and to the command or script that ran.
- **Evidence grades:**

  | Grade | Meaning |
  |---|---|
  | SRC | read in source code at a pinned version |
  | DOC | official documentation |
  | PDF | a paper |
  | MEAS | measured here, raw output committed |
  | INF | inference; never quoted as a result |
  | OPEN | not yet known |

- **Measurements record their conditions:** kernel, VM snapshot, host power mode, Hyper-V state, swap state, number of runs. A measurement repeated fewer than 3 times is labelled as such.

## 6. Tests and gates

- **A gate is a test that fails when the fix it guards is reverted.** A test that still passes on the broken code is not a gate.
- **Every gate is checked by two mutation sweeps:** the author's, and an independent reviewer's.
- **No silent fallbacks:** no `getattr(x, "field", 0)` style defaults on decoded data. An unknown or missing field is an error, and errors are counted.
- **No silent caps:** every bound has a counter, and the accounting invariant must close.

## 7. Safety

- **Never execute code from a third-party repository** that was cloned for study. Read it; don't run it.
- **Verify every download by checksum** before use.
- **Scripts stop on the first error** (`set -euo pipefail`; PowerShell `$ErrorActionPreference = "Stop"`).
