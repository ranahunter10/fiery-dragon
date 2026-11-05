#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation sweep for the CI gate scripts check_exits.py and check_hardening.py
(CONTRIBUTING §6: every gate is checked by a mutation sweep).

Each mutant plants one bug in a checker and expects its unit tests to fail. The file is
restored after every mutant, also on error or Ctrl-C.

    python3 tools/ci/mutate_checks.py        (or: make mutate-checks)

Exit 0 only if every mutant is killed. Left out as equivalent: none.
"""
import os
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent

M = [
 ("check_exits.py", r'CALL = re.compile(r"\b(exit|_exit|_Exit|quick_exit|abort)\s*\(")', r'CALL = re.compile(r"\b(exit|_exit|_Exit|abort)\s*\(")'),
 ("check_exits.py", r'CALL = re.compile(r"\b(exit|_exit|_Exit|quick_exit|abort)\s*\(")', r'CALL = re.compile(r"(exit|_exit|_Exit|quick_exit|abort)\s*\(")'),
 ("check_exits.py", r'CALL = re.compile(r"\b(exit|_exit|_Exit|quick_exit|abort)\s*\(")', r'CALL = re.compile(r"\b(exit|_exit|_Exit|quick_exit|abort)\(")'),
 ("check_exits.py", r'MARK = re.compile(r"exit-ok:\s*[A-Za-z]")', r'MARK = re.compile(r"exit-ok:")'),
 ("check_exits.py", 'if c == "/" and nxt == "/":', "if False:"),
 ("check_exits.py", 'if c == "/" and nxt == "*":', "if False:"),
 ("check_exits.py", "if c in \"\\\"'\":", 'if c in "\\"":'),
 ("check_exits.py", 'if state == "line":', "if False:"),
 ("check_exits.py", 'state, i = "code", i + 2', 'state, i = "code", i + 1'),
 ("check_exits.py", "if CALL.search(code):", "if CALL.search(line):"),
 ("check_exits.py", "return 1 if bad else 0", "return 0"),
 ("check_exits.py", "(ok if MARK.search(line) else bad)", "(ok if MARK.search(code) else bad)"),
 ("check_exits.py", 'if c == "\\\\":', "if False:"),
 ("check_hardening.py", 'bool(re.search(r"Type:\\s+DYN", h)) and ', ""),
 ("check_hardening.py", ' and bool(re.search(r"FLAGS_1\\).*\\bPIE\\b", d)),', ","),
 ("check_hardening.py", '"relro": "GNU_RELRO" in lw,', '"relro": True,'),
 ("check_hardening.py", ' or bool(re.search(r"FLAGS_1\\).*\\bNOW\\b", d)),', ","),
 ("check_hardening.py", '"nx-stack": bool(stack) and "E" not in stack.group(1),', '"nx-stack": True,'),
 ("check_hardening.py", '"canary": bool(re.search(r"\\b__stack_chk_fail\\b", syms)),', '"canary": True,'),
 ("check_hardening.py", '"fortify": bool(re.search(r"\\b__\\w+_chk\\b", syms)),', '"fortify": True,'),
 ("check_hardening.py", r'\bIBT\b.*\bSHSTK\b', r'\bIBT\b'),
]


def main() -> int:
    originals = {f: (HERE / f).read_text() for f in {m[0] for m in M}}
    # No bytecode: a cached .pyc is trusted by source mtime (1 s) and size, so a mutant written
    # within the same second as an earlier one of the same size would run the stale code.
    shutil.rmtree(HERE / "__pycache__", ignore_errors=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    killed = 0
    try:
        for i, (f, old, new) in enumerate(M):
            if originals[f].count(old) != 1:
                print(f"mutant {i}: anchor not found exactly once in {f}; update this sweep")
                return 2
            (HERE / f).write_text(originals[f].replace(old, new))
            test = HERE / f"test_{f}"
            r = subprocess.run([sys.executable, "-B", "-m", "unittest", str(test)], capture_output=True, text=True,
                               env=env)
            (HERE / f).write_text(originals[f])
            dead = r.returncode != 0
            killed += dead
            print(("killed   " if dead else "SURVIVED "), i, f, old.strip()[:60])
    finally:
        for f, text in originals.items():
            (HERE / f).write_text(text)
    print(f"mutation sweep: {killed}/{len(M)} killed")
    return 0 if killed == len(M) else 1


if __name__ == "__main__":
    sys.exit(main())
