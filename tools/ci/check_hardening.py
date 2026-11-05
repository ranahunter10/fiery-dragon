#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check that daemon binaries really carry the ADR-0019 G3.3 hardening, not just that the
flags were passed: a later flag (or a default) can silently undo an earlier one.

    python3 tools/ci/check_hardening.py build/p15-spine ...     (or: make hardening-check)

Per binary, from readelf and nm (binutils):
  pie       ELF type DYN with the PIE flag             (-fPIE -pie)
  relro     a GNU_RELRO segment                        (-z relro)
  now       BIND_NOW                                   (-z now: full RELRO)
  nx-stack  GNU_STACK without execute permission
  canary    imports __stack_chk_fail                   (-fstack-protector-strong)
  fortify   imports at least one __*_chk function      (-D_FORTIFY_SOURCE)
  cet       x86 feature property IBT and SHSTK         (-fcf-protection; every object must have it)
"""
from __future__ import annotations

import re
import subprocess
import sys


def checks(h: str, d: str, lw: str, n: str, syms: str) -> dict[str, bool]:
    """Each property from the text of readelf -h, -d, -lW, -n and nm -D."""
    stack = re.search(r"GNU_STACK\s.*\s(R?W?E?)\s+0x[0-9a-f]+\s*$", lw, re.M)
    return {
        "pie": bool(re.search(r"Type:\s+DYN", h)) and bool(re.search(r"FLAGS_1\).*\bPIE\b", d)),
        "relro": "GNU_RELRO" in lw,
        "now": bool(re.search(r"\(FLAGS\).*\bBIND_NOW\b", d)) or bool(re.search(r"FLAGS_1\).*\bNOW\b", d)),
        "nx-stack": bool(stack) and "E" not in stack.group(1),
        "canary": bool(re.search(r"\b__stack_chk_fail\b", syms)),
        "fortify": bool(re.search(r"\b__\w+_chk\b", syms)),   # not __stack_chk_fail: no \b after _chk
        "cet": bool(re.search(r"x86 feature:.*\bIBT\b.*\bSHSTK\b", n)),
    }


def run(*cmd: str) -> str:
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: check_hardening.py ELF...", file=sys.stderr)
        return 2
    bad = 0
    for b in argv:
        got = checks(run("readelf", "-h", b), run("readelf", "-d", b), run("readelf", "-lW", b),
                     run("readelf", "-n", b), run("nm", "-D", b))
        missing = [k for k, ok in got.items() if not ok]
        bad += bool(missing)
        print(f"{'ok  ' if not missing else 'FAIL'}  {b}: " + ("all of " + ", ".join(got) if not missing
                                                             else "missing " + ", ".join(missing)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
