#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The project's two CSV journals keep their shape (docs/journal/README.md, CONTRIBUTING.md §5).

    python3 tools/ci/check_csv.py        (from the repository root)

Checks every row of `docs/journal/engineering-log.csv` and `docs/research/papers.csv`:
- it has exactly the header's number of fields (a missing field shifts every later column);
- its id has the file's form (E-NNNN, R-NNN), is unique, and ids ascend in file order;
- engineering log: `date` is YYYY-MM-DD and `grade` is one of the grades (optionally followed by
  a parenthesis, e.g. "MEAS (helper: INF)");
- papers: `verified` is yes, no or partly.

Every problem is printed with its line; exit 1 if there is any, 0 otherwise.
"""
from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

GRADES = ("SRC", "DOC", "PDF", "MEAS", "INF", "OPEN", "decision")
FILES = {
    "docs/journal/engineering-log.csv": r"E-\d{4}",
    "docs/research/papers.csv": r"R-\d{3}",
}


def check(path: Path, id_form: str) -> list[str]:
    problems: list[str] = []
    with path.open(newline="") as f:
        rows = list(csv.reader(f))
    if not rows:
        return [f"{path}: empty"]
    head = rows[0]
    seen: set[str] = set()
    last = ""
    for n, row in enumerate(rows[1:], start=2):
        where = f"{path}: row {n}"          # csv rows, not lines: an entry may hold a newline
        if len(row) != len(head):
            problems.append(f"{where} ({row[0] if row else '?'}): {len(row)} fields, header has {len(head)}")
            continue
        r = dict(zip(head, row))
        rid = r["id"]
        if not re.fullmatch(id_form, rid):
            problems.append(f"{where}: id {rid!r} is not of the form {id_form}")
        if rid in seen:
            problems.append(f"{where}: id {rid} repeated")
        if rid <= last:
            problems.append(f"{where}: id {rid} comes after {last}")
        seen.add(rid)
        last = max(last, rid)
        if "grade" in r:
            g = r["grade"].split(" (", 1)[0]
            if g not in GRADES:
                problems.append(f"{where} ({rid}): grade {r['grade']!r} is not one of {', '.join(GRADES)}")
            if not re.fullmatch(r"\d{4}-\d\d-\d\d", r["date"]):
                problems.append(f"{where} ({rid}): date {r['date']!r} is not YYYY-MM-DD")
        if "verified" in r and r["verified"] not in ("yes", "no", "partly"):
            problems.append(f"{where} ({rid}): verified {r['verified']!r} is not yes, no or partly")
    return problems


def main(root: Path) -> int:
    problems: list[str] = []
    for rel, form in FILES.items():
        problems += check(root / rel, form)
    for p in problems:
        print(p)
    print(f"{len(FILES)} journals, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")))
