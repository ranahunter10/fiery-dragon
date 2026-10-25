#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation sweep for the Python gates and harnesses (CONTRIBUTING §6: every gate is checked by a
mutation sweep): tools/ci/check_exits.py, tools/ci/check_hardening.py, bench/rb_cost/summarize.py.

Each mutant plants one bug in a file and expects that file's unit tests (test_<name>.py next to
it) to fail. The file is restored after every mutant, also on error or Ctrl-C.

    python3 tools/ci/mutate_py.py        (or: make mutate-py)

Exit 0 only if every mutant is killed. Left out as equivalent: none.
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXITS, HARD, SUMM = "tools/ci/check_exits.py", "tools/ci/check_hardening.py", "bench/rb_cost/summarize.py"

M = [
 (EXITS, r'CALL = re.compile(r"\b(exit|_exit|_Exit|quick_exit|abort)\s*\(")', r'CALL = re.compile(r"\b(exit|_exit|_Exit|abort)\s*\(")'),
 (EXITS, r'CALL = re.compile(r"\b(exit|_exit|_Exit|quick_exit|abort)\s*\(")', r'CALL = re.compile(r"(exit|_exit|_Exit|quick_exit|abort)\s*\(")'),
 (EXITS, r'CALL = re.compile(r"\b(exit|_exit|_Exit|quick_exit|abort)\s*\(")', r'CALL = re.compile(r"\b(exit|_exit|_Exit|quick_exit|abort)\(")'),
 (EXITS, r'MARK = re.compile(r"exit-ok:\s*[A-Za-z]")', r'MARK = re.compile(r"exit-ok:")'),
 (EXITS, 'if c == "/" and nxt == "/":', "if False:"),
 (EXITS, 'if c == "/" and nxt == "*":', "if False:"),
 (EXITS, "if c in \"\\\"'\":", 'if c in "\\"":'),
 (EXITS, 'if state == "line":', "if False:"),
 (EXITS, 'state, i = "code", i + 2', 'state, i = "code", i + 1'),
 (EXITS, "if CALL.search(code):", "if CALL.search(line):"),
 (EXITS, "return 1 if bad else 0", "return 0"),
 (EXITS, "(ok if MARK.search(line) else bad)", "(ok if MARK.search(code) else bad)"),
 (EXITS, 'if c == "\\\\":', "if False:"),
 (HARD, 'bool(re.search(r"Type:\\s+DYN", h)) and ', ""),
 (HARD, ' and bool(re.search(r"FLAGS_1\\).*\\bPIE\\b", d)),', ","),
 (HARD, '"relro": "GNU_RELRO" in lw,', '"relro": True,'),
 (HARD, ' or bool(re.search(r"FLAGS_1\\).*\\bNOW\\b", d)),', ","),
 (HARD, '"nx-stack": bool(stack) and "E" not in stack.group(1),', '"nx-stack": True,'),
 (HARD, '"canary": bool(re.search(r"\\b__stack_chk_fail\\b", syms)),', '"canary": True,'),
 (HARD, '"fortify": bool(re.search(r"\\b__\\w+_chk\\b", syms)),', '"fortify": True,'),
 (HARD, r'\bIBT\b.*\bSHSTK\b', r'\bIBT\b'),
 (SUMM, 'if word not in ("row", "nullsys", "selftest"):', 'if word not in ("row", "selftest"):'),
 (SUMM, 'if set(kv) != set(ROW_KEYS) or kv["way"] not in WAYS:', 'if kv["way"] not in WAYS:'),
 (SUMM, 'if row["run_cnt"] <= 0:', 'if row["run_cnt"] < 0:'),
 (SUMM, 'if kv["way"] not in WAYS or verdict not in ("PASS", "FAIL"):', 'if kv["way"] not in WAYS:'),
 (SUMM, 'if r["ours"] != r["execs"] or r["invalid"]', 'if r["invalid"]'),
 (SUMM, 'or r["wrong_size"] or r["wrong_argv"]:', 'or r["wrong_argv"]:'),
 (SUMM, 'if any(s != sets[0] for s in sets):', 'if False:'),
 (SUMM, 'return r["run_time_ns"] / r["run_cnt"]', 'return r["run_time_ns"] / r["execs"] * 1.0'),
 (SUMM, 'diffs = sorted(by[(argv, w)][k] - base[k]', 'diffs = sorted(base[k] - by[(argv, w)][k]'),
 (SUMM, 'below = sum(x < 0 for x in diffs)', 'below = sum(x <= 0 for x in diffs)'),
 (SUMM, 'ratio = f"{m / nmed:.1f}"', 'ratio = f"{m / null[0]:.1f}"'),
 (SUMM, 'foreign = sum(r["foreign"] for r in d["rows"])', 'foreign = 0'),
 (SUMM, 'return 1 if probs else 0', 'return 0'),
]


def main() -> int:
    originals = {f: (ROOT / f).read_text() for f in {m[0] for m in M}}
    # No bytecode: a cached .pyc is trusted by source mtime (1 s) and size, so a mutant written
    # within the same second as an earlier one of the same size would run the stale code.
    for f in originals:
        shutil.rmtree((ROOT / f).parent / "__pycache__", ignore_errors=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    killed = 0
    try:
        for i, (f, old, new) in enumerate(M):
            if originals[f].count(old) != 1:
                print(f"mutant {i}: anchor not found exactly once in {f}; update this sweep")
                return 2
            (ROOT / f).write_text(originals[f].replace(old, new))
            test = (ROOT / f).parent / f"test_{(ROOT / f).name}"
            r = subprocess.run([sys.executable, "-B", "-m", "unittest", str(test)], capture_output=True, text=True,
                               env=env)
            (ROOT / f).write_text(originals[f])
            dead = r.returncode != 0
            killed += dead
            print(("killed   " if dead else "SURVIVED "), i, pathlib.Path(f).name, old.strip()[:60])
    finally:
        for f, text in originals.items():
            (ROOT / f).write_text(text)
    print(f"mutation sweep: {killed}/{len(M)} killed")
    return 0 if killed == len(M) else 1


if __name__ == "__main__":
    sys.exit(main())
