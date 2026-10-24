# Journals

Fiery Dragon keeps three records. They start fresh on 2026-10-21; the ESE-P15 v3.7 journals are history and are not continued here.

| Record | File | What goes in it |
|---|---|---|
| **Engineering log** | [`engineering-log.csv`](engineering-log.csv) | Facts as they happen: what was built, measured, found or broken, each with its evidence |
| **Decision journal** | [`../decisions/`](../decisions/) | One ADR per decision, plus the index in its README |
| **Research register** | [`../research/papers.csv`](../research/papers.csv) | Papers, docs and posts we rely on, with what we used from each and whether we have verified it |

## Why CSV

- Opens directly in Excel.
- GitHub renders it as a searchable table.
- Diffs line by line in a PR, so a new row is reviewed like code.
- No tool or format lock-in.

## Engineering log rules

- **Append-only.** Rows are never edited or deleted. A correction is a new row that names the row it corrects ("Corrects E-0012: …").
- **`id`:** `E-NNNN`, sequential.
- **`date`:** when the fact was established, not when it was written down.
- **`area`:** platform, toolchain, hooks, schema, daemon, wal, py, bench, tests, ci, process, docs.
- **`evidence`:** a path under `docs/evidence/`, an ADR, or a PR. Rows E-0001–E-0008 point to the ESE-P15 project notes until the phase-0 evidence is imported.
- **`grade`:** SRC / DOC / PDF / MEAS / INF / OPEN, as in `CONTRIBUTING.md` §5.
- **`ref`:** the PR or commit that recorded it, or `-`.

## Research register rules

- **`verified`** stays `no` until someone has opened the primary source and checked the exact claims in `key_claims_used`. Then fill in `verified_how` (e.g. "read §5 and Table 6 of the PDF") and `verified_date`.
- **Only verified claims** may be decisive in an ADR. Unverified rows can motivate a question, not answer it.
- **A wrong claim is corrected in a new row** that names the old one, and the old row's `notes` says "see R-NNN".
