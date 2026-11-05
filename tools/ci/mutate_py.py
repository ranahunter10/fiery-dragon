#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation sweep for the Python gates and harnesses (CONTRIBUTING §6: every gate is checked by a
mutation sweep): tools/ci/check_exits.py, tools/ci/check_hardening.py, bench/rb_cost/summarize.py,
the WAL reader (python/p15/wal.py, records.py) and the port query (proctree.py, net.py,
trace.py, report_html.py).

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
TREE, NET, TRACE, HTML = "python/p15/proctree.py", "python/p15/net.py", "python/p15/trace.py", "python/p15/report_html.py"
QUANT, HOOKS = "bench/quant/paired.py", "bench/hook_cost/summarize.py"
TESTS = {WAL: "python/tests/test_wal.py", REC: "python/tests/test_records.py", TREE: "python/tests/test_trace.py",
         NET: "python/tests/test_trace.py", TRACE: "python/tests/test_trace.py", HTML: "python/tests/test_trace.py"}

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
 (TREE, 'if r.f["kind"] != 1:', "if False:"),
 (TREE, "if c.fork_ns is not None:\n                counts[\"fork_twice\"]", "if False:\n                counts[\"fork_twice\"]"),
 (TREE, 'if not r.f["group_dead"]:', "if False:"),
 (TREE, "if p.exit_ns is not None:\n                counts[\"exit_twice\"]", "if False:\n                counts[\"exit_twice\"]"),
 (TREE, "if start is not None and p.key[1] < start:", "if start is not None and p.key[1] <= 0:"),
 (TREE, "p.in_gap = any(g.from_ns <= died and born <= g.to_ns for g in gaps)", "p.in_gap = any(g.from_ns <= born <= g.to_ns for g in gaps)"),
 (TREE, 'return f"exited {st >> 8}"', 'return f"exited {st}"'),
 (TREE, "k = self.procs[k].parent", "k = None"),
 (NET, "return self.ret == 0 or (self.op == \"CONNECT\" and self.ret == -EINPROGRESS)", "return self.ret == 0"),
 (NET, "if e.op in (\"BIND\", \"LISTEN\") and e.lport == port and e.ok:", "if e.op in (\"BIND\", \"LISTEN\") and e.ok:"),
 (NET, "lst = by_cookie.get(e.peer_cookie)", "lst = by_cookie.get(e.cookie)"),
 (NET, "k.local == e.remote and k.remote == e.local", "k.local == e.remote"),
 (NET, "and k.netns == e.netns and abs(k.ts_ns - e.ts_ns) <= JOIN_WINDOW_NS]",
  "and abs(k.ts_ns - e.ts_ns) <= JOIN_WINDOW_NS]"),
 (NET, "and k.netns == e.netns and abs(k.ts_ns - e.ts_ns) <= JOIN_WINDOW_NS]", "and k.netns == e.netns]"),
 (NET, "and k.netns == e.netns and abs(k.ts_ns - e.ts_ns) <= JOIN_WINDOW_NS]",
  "and k.netns == e.netns and k.ts_ns <= e.ts_ns]"),
 (NET, "and k.netns == e.netns and abs(k.ts_ns - e.ts_ns) <= JOIN_WINDOW_NS]",
  "and k.netns == e.netns and abs(k.ts_ns - e.ts_ns) < JOIN_WINDOW_NS]"),
 (NET, "c.connect = min(pool, key=lambda k: (abs(k.ts_ns - e.ts_ns), k.seq))",
  "c.connect = max(pool, key=lambda k: (k.ts_ns, k.seq))"),
 (NET, "c.connect = min(pool, key=lambda k: (abs(k.ts_ns - e.ts_ns), k.seq))",
  "c.connect = min(pool, key=lambda k: (k.ts_ns, k.seq))"),
 (NET, "counts[\"connect_after_accept\"] += c.connect.ts_ns > e.ts_ns", "pass"),
 (NET, "refused = [e for e in connects if e.rport == port and not e.ok]", "refused = []"),
 # ADR-0022: the exact join by the client ISN, and the reader's flag rules
 (NET, "exact = [k for k in cands if e.isn is not None and k.isn == e.isn]",
  "exact = [k for k in cands if k.isn == e.isn]"),
 (NET, "exact = [k for k in cands if e.isn is not None and k.isn == e.isn]", "exact = []"),
 (NET, 'counts["isn_mismatch"] += len(other_conn)', "pass"),
 (NET, "inferred = [k for k in cands if k not in other_conn]", "inferred = cands"),
 (NET, 'c.match, pool = "isn", exact', 'c.match, pool = "endpoints", exact'),
 (NET, 'isn = r.f["tcp_isn"] if r.h["flags"] & R.F_ISN else None', 'isn = r.f["tcp_isn"]'),
 (NET, 'sum(1 for c in accepted if c.accept.proto == "tcp" and c.accept.isn is None)', "0"),
 (REC, 'if h["flags"] & ~F_KNOWN:', "if False:"),
 (REC, 'if h["flags"] & F_ISN and not (lay.name == "NET" and h["version"] >= 2):', "if False:"),
 (REC, 'f["reserved"] or (not h["flags"] & F_ISN and f["tcp_isn"])', 'f["reserved"]'),
 (TRACE, "i = max(0, bisect.bisect_right(self.anchors, (ts, 1 << 64)) - 1)", "i = 0"),
 (TRACE, 'if not self.net_on:\n            out.append(', 'if False:\n            out.append('),
 (TRACE, 'if self.end is None:\n            out.append(', 'if False:\n            out.append('),
 (TRACE, 'run.meta["config.net"] == "yes"', 'True'),
 (HTML, "def _e(s) -> str:\n    return escape(str(s), quote=True)", "def _e(s) -> str:\n    return str(s)"),
 (HTML, 'if ctx.end is None or ctx.end.f["run_state"] == 2 or not ctx.net_on:', 'if ctx.end is None:'),
 # ADR-0020: the kernel's skips in the Trust block and in GAP windows
 (TRACE, 'if self.stats.h["version"] < 2:', 'if False:'),
 (TRACE, 'if not any(sk.values()) and not net:', 'if True:'),
 (TREE, '"_build_failed", "_missed")', '"_build_failed")'),
 # ADR-0018 rule 2: the paired statistics
 (QUANT, "nxt[w + r] += c", "nxt[w + r - 1] += c"),
 (QUANT, "r = (i + j + 2) / 2", "r = (i + j + 1) / 2"),
 (QUANT, "lo = sum(counts[: math.floor(w) + 1])", "lo = sum(counts[: math.floor(w)])"),
 (QUANT, "p = min(1.0, 2 * min(lo, hi) / total)", "p = min(1.0, min(lo, hi) / total)"),
 (QUANT, "est = median(w)", "est = median(d)"),
 (QUANT, "Interval(w[k - 1], w[m - k],", "Interval(w[k], w[m - k - 1],"),
 (QUANT, "Interval(s[j - 1], s[n - j],", "Interval(s[j], s[n - j - 1],"),
 (QUANT, "a = [math.log(v / u) for v, u in zip(aa, untraced)]", "a = [math.log(v / u) for v, u in zip(aa, traced)]"),
 (QUANT, "and not floor.ci.lo <= effect.estimate <= floor.ci.hi)", ")"),
 (QUANT, "et.p_two_sided < 0.05", "et.p_two_sided < 0.5"),
 (QUANT, "drift = abs(rom - math.exp(effect.estimate)) >", "drift = abs(rom - math.exp(effect.estimate)) <"),
 (QUANT, "return len(xs) / math.fsum(1 / x for x in xs)", "return math.fsum(1 / x for x in xs) / len(xs)"),
 (QUANT, "if t.zeros:", "if False:"),
 # ADR-0020 confirmation 5: the hook-cost report
 (HOOKS, "want = 0 if arm in UNTRACED else n", "want = n"),
 (HOOKS, "if rnd >= 0:", "if True:"),
 (HOOKS, 'out[a].append(got[a][metric] / got[a]["n"])', 'out[a].append(got[a][metric])'),
 (HOOKS, "if hits != want:", "if False:"),
 (HOOKS, 'return "\\n".join(out), 1 if bad else 0', 'return "\\n".join(out), 0'),
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
