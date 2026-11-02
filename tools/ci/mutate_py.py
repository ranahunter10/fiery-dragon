#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation sweep for the Python gates and harnesses (CONTRIBUTING §6: every gate is checked by a
mutation sweep): tools/ci/check_exits.py, tools/ci/check_hardening.py, bench/rb_cost/summarize.py,
and the WAL reader, python/p15/wal.py and records.py.

Each mutant plants one bug in a file and expects that file's unit tests (test_<name>.py next to
it, or in python/tests/ for the python/p15 package) to fail. The file is restored after every mutant, also on error or Ctrl-C.

    python3 tools/ci/mutate_py.py        (or: make mutate-py)

Exit 0 only if every mutant is killed. Left out as untestable here: wal.py's refusal of
google-crc32c's pure-Python fallback (the pinned wheel is always the C one; the guard is three
lines at import).
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXITS, HARD, SUMM = "tools/ci/check_exits.py", "tools/ci/check_hardening.py", "bench/rb_cost/summarize.py"
WAL, REC = "python/p15/wal.py", "python/p15/records.py"
TESTS = {WAL: "python/tests/test_wal.py", REC: "python/tests/test_records.py"}

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
 (WAL, "if magic != SEG_MAGIC:", "if False:"),
 (WAL, "if (major, minor) != (MAJOR, MINOR):", "if major != MAJOR:"),
 (WAL, "if hlen < PREFIX.size or hlen % 8 or hlen > len(buf):", "if hlen > len(buf):"),
 (WAL, 'zeroed[16:20] = b"\\0\\0\\0\\0"', "pass"),
 (WAL, "if any(buf[end:padded]):", "if False:"),
 (WAL, "if k in meta:", "if False:"),
 (WAL, "if p != hlen:", "if False:"),
 (WAL, "elif crc32c(buf[p:p + 32]) != hcrc:", "elif False:"),
 (WAL, "elif flags or rsv1 or rsv2 or ring > 2:", "elif flags or ring > 2:"),
 (WAL, "plen < R.HEADER_SIZE * count or ", ""),
 (WAL, "if crc32c(payload) != pcrc:", "if False:"),
 (WAL, "elif not _tiles(payload, count):", "elif False:"),
 (WAL, "elif first != seg.seq_next[ring]:", "elif False:"),
 (WAL, "torn = (cause in (1, 6) or", "torn = (cause in (1,) or"),
 (WAL, "(cause == 7 and end_of_batch == len(buf))", "(cause == 7)"),
 (WAL, "or not any(buf[p:]))", "or False)"),
 (WAL, "seg.seq_next[ring] = first + count", "seg.seq_next[ring] = first"),
 (WAL, "if seq_expect is not None and hdr_next != seq_expect:", "if False:"),
 (WAL, "if out and s.meta[k] != out[0].meta[k]:", "if False:"),
 (WAL, 'if meta["schema.hash"] != R.SCHEMA_HASH:', "if False:"),
 (WAL, "if int(SEG_RE.match(p.name).group(1)) != i:", "if False:"),
 (WAL, 'yield (r.h["ts_ns"], ring, r.seq), r', 'yield (r.seq, ring, r.h["ts_ns"]), r'),
 (WAL, 'p += struct.unpack_from("<H", b.payload, p + 4)[0]', "p += 32"),
 (WAL, "return 1 if problems else 0", "return 0"),
 (WAL, "return lines, len(errors) + sum(1 for _, st in run.stops if not st.torn)", "return lines, len(errors)"),
 (REC, "if size < HEADER_SIZE:", "if size < 8:"),
 (REC, "if n > size:", "if False:"),
 (REC, "if n % 8:", "if False:"),
 (REC, "if n < lay.fixed_size:", "if False:"),
 (REC, "if vl > vmax:", "if False:"),
 (REC, "if lay.fixed_size + used > n:", "if False:"),
 (REC, 'slack_ok = lay.cls == "SPINE" and bool(h["flags"] & F_READ_FAILED)', 'slack_ok = bool(h["flags"] & F_READ_FAILED)'),
 (REC, "if any(bytes(buf[p:off + n])):", "if False:"),
 (REC, "elif n != lay.fixed_size:", "elif False:"),
 (REC, "bytes(buf[off + o:off + o + dt.itemsize]) if", "bytes(row[name]) if"),
 (REC, "return (kernel_dev >> 20,", "return (kernel_dev >> 8,"),
 (REC, 'if a.endswith(b"\\0"):', "if False:"),
]


def main() -> int:
    originals = {f: (ROOT / f).read_text() for f in {m[0] for m in M}}
    # No bytecode: a cached .pyc is trusted by source mtime (1 s) and size, so a mutant written
    # within the same second as an earlier one of the same size would run the stale code.
    for f in originals:
        shutil.rmtree((ROOT / f).parent / "__pycache__", ignore_errors=True)
    shutil.rmtree(ROOT / "python" / "tests" / "__pycache__", ignore_errors=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    killed = 0
    try:
        for i, (f, old, new) in enumerate(M):
            if originals[f].count(old) != 1:
                print(f"mutant {i}: anchor not found exactly once in {f}; update this sweep")
                return 2
            (ROOT / f).write_text(originals[f].replace(old, new))
            test = ROOT / TESTS[f] if f in TESTS else (ROOT / f).parent / f"test_{(ROOT / f).name}"
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
