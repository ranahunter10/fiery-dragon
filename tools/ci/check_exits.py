#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One fatal path (ADR-0019 G2.2): no exit(), _exit(), _Exit(), quick_exit() or abort() in the
daemon's C code, except at sites marked on the same line with a comment `exit-ok: <reason>`.

The marked sites are the daemon's single fatal function and the self-test's child process.
Every marked site is printed, so a reviewer sees the whole list in the CI log.

    python3 tools/ci/check_exits.py daemon        (or: make exit-check)

Exit 0 if every call is marked, 1 otherwise. Comments and string literals are ignored when
looking for calls, so prose that mentions exit() is not a hit.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

CALL = re.compile(r"\b(exit|_exit|_Exit|quick_exit|abort)\s*\(")
MARK = re.compile(r"exit-ok:\s*[A-Za-z]")


def code_only(text: str) -> list[str]:
    """The text's lines with comments and string/char literals blanked; line count kept."""
    out, i, n = [], 0, len(text)
    buf: list[str] = []
    state = "code"
    while i < n:
        c, nxt = text[i], text[i + 1] if i + 1 < n else ""
        if c == "\n":
            out.append("".join(buf))
            buf = []
            if state == "line":
                state = "code"
            i += 1
            continue
        if state == "code":
            if c == "/" and nxt == "*":
                state, i = "block", i + 2
                continue
            if c == "/" and nxt == "/":
                state, i = "line", i + 2
                continue
            if c in "\"'":
                state, quote = "str", c
                buf.append(" ")
                i += 1
                continue
            buf.append(c)
        elif state == "block":
            if c == "*" and nxt == "/":
                state, i = "code", i + 2
                continue
        elif state == "str":
            if c == "\\":
                i += 2
                continue
            if c == quote:
                state = "code"
            buf.append(" ")
        i += 1
    out.append("".join(buf))
    return out


def scan(paths: list[Path]) -> tuple[list[str], list[str]]:
    """(violations, allowed), each as 'file:line: text'."""
    bad, ok = [], []
    for p in sorted(paths):
        raw = p.read_text().split("\n")
        for no, (code, line) in enumerate(zip(code_only(p.read_text()), raw), start=1):
            if CALL.search(code):
                where = f"{p}:{no}: {line.strip()}"
                (ok if MARK.search(line) else bad).append(where)
    return bad, ok


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: check_exits.py DIR...", file=sys.stderr)
        return 2
    files = [f for d in argv for f in Path(d).rglob("*") if f.suffix in (".c", ".h")]
    if not files:
        print(f"check_exits: no C files under {' '.join(argv)}", file=sys.stderr)
        return 2
    bad, ok = scan(files)
    for w in ok:
        print(f"allowed  {w}")
    for w in bad:
        print(f"FORBIDDEN {w}")
    print(f"exit check: {len(files)} files, {len(ok)} marked sites, {len(bad)} unmarked calls")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
