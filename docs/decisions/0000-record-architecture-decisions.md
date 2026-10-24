---
status: accepted
date: 2026-10-25
owner: Ashish Rana
consulted: [ESE-P15 v3.7 engineering journal, capture blueprint v1 (2026-10-21), MADR 4.0]
supersedes: none
---

# 0000: Record architecture decisions as ADRs in the repository

## Context and problem statement

In the previous capture layer (ESE-P15 v3.7), decisions were spread across several places: chat threads, an Excel journal, and design notes that sometimes disagreed with the code. Some choices were later defended with rhetoric instead of evidence. The "industry-floor 5.15" kernel argument was overtaken within weeks, and nobody had written down what would reopen it.

The question: **where and how do we record decisions, so that each one has an owner, evidence and a trigger for revisiting it, and so that it is reviewed like code?**

## Decision drivers

1. Each decision is reviewable in the same PR flow as code, and visible next to the code it governs.
2. Each decision carries its evidence, with grades, and a falsifier.
3. Decisions are never silently rewritten: history is kept.
4. The format is lightweight enough that writing one isn't avoided.

## Considered options

1. ADRs in the repo using MADR 4.0, extended with owner, falsifier and graded evidence
2. Keep decisions in an external spreadsheet (the v3.7 approach)
3. Use GitHub issues or discussions as the record

## Decision outcome

**Chosen option:** option 1, ADRs in `docs/decisions/` from the extended MADR template (`adr-template.md`). It is the only option where a decision goes through the same review and history as code (driver 1). It also makes evidence and a falsifier mandatory fields instead of good intentions (driver 2).

Rules:
- **When to write one:** any decision that is hard to reverse, or that someone could reasonably have made differently. Examples: platform, toolchain, hook policy, record format, identity rules, test adequacy, quantification protocol.
- **Numbering:** sequential (`NNNN-title-with-dashes.md`). Numbers are never reused.
- **Proposing:** a PR on an `adr/NNNN-<topic>` branch with `status: proposed`. Discussion happens in the PR.
- **Accepting:** the PR sets `status: accepted` and the date. Merging it is the acceptance.
- **Accepted ADRs are never edited** (typo fixes excepted). A change of mind is a new ADR that says `supersedes: ADR-NNNN`. The old ADR's status becomes `superseded by ADR-MMMM`; changing that status line is the only edit allowed to an accepted ADR.
- **The index** in `docs/decisions/README.md` is updated in the same PR.

### Consequences

- Good: every design choice has an owner, its evidence, and a written condition for revisiting it.
- Good: a reviewer of a code PR can check the decisions it claims to rely on (PR template, part 4).
- Bad: decisions take a PR's worth of effort. We accept that cost; it is the point.

### Confirmation

- The PR template requires listing the ADRs a change assumes.
- A code PR that needs an undecided choice stops until that ADR exists (`CONTRIBUTING.md` §4).

### Falsifier

Reopen if, after Phase 1, decisions are routinely being made outside ADRs, or if ADRs are being edited after acceptance. That would mean the process is too heavy, or that it is being ignored.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | In v3.7, decisions lived in chats, an Excel journal and notes that diverged from code | MEAS | ESE-P15 project history; blueprint v1 §1 lessons L6, L13 |
| 2 | MADR 4.0 defines status, decision drivers, options, outcome, consequences and confirmation | DOC | https://adr.github.io/madr/ |
| 3 | Comparable projects keep design decisions in-repo (Falco `proposals/`; Tetragon `docs/` design notes) | SRC | research notes `testing_ci_process.md` (2026-10-21) |

## Pros and cons of the options

### 1. ADRs in the repo (MADR, extended)
- Good: reviewed and versioned like code; next to the code; plain text, so diffs and grep work.
- Bad: needs discipline to write them before the code.

### 2. External spreadsheet
- Good: familiar; easy to scan.
- Bad: not reviewed with the code; no diff history; already drifted from reality in v3.7.

### 3. Issues or discussions
- Good: easy to start; threaded discussion.
- Bad: the outcome is buried in comments; it can be edited silently; it isn't part of the code's history.
