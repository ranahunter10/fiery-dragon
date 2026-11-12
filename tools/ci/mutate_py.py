#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation sweep for the Python gates and harnesses (CONTRIBUTING §6: every gate is checked by a
mutation sweep): tools/ci/check_exits.py, tools/ci/check_hardening.py,
the WAL reader (python/p15/wal.py, records.py) and the port query (proctree.py, net.py,
trace.py, report_html.py).

Each mutant plants one bug in a file and expects that file's unit tests (test_<name>.py next to
it, or in python/tests/ for the python/p15 package) to fail. The file is restored after every mutant, also on error or Ctrl-C.

    python3 tools/ci/mutate_py.py        (or: make mutate-py)
    python3 tools/ci/mutate_py.py 172-265   only those mutants (a range or numbers): for a re-run, never for the gate

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
EXITS, HARD = "tools/ci/check_exits.py", "tools/ci/check_hardening.py"
WAL, REC = "python/p15/wal.py", "python/p15/records.py"
TREE, NET, TRACE, HTML = "python/p15/proctree.py", "python/p15/net.py", "python/p15/trace.py", "python/p15/report_html.py"
QUANT, HOOKS = "bench/quant/paired.py", "bench/hook_cost/summarize.py"
RWH = "bench/rw_hook_cost/summarize.py"
SNAP, RECON = "python/p15/snapshot.py", "python/p15/reconcile.py"
PROV = "python/p15/provenance.py"
GEN = "schema/gen/gen.py"
GRAW, GBUILD, GSQL, GPM, GCLI = ("python/p15/graph/raw.py", "python/p15/graph/build.py", "python/p15/graph/graph.sql",
                                 "python/p15/graph/pidsmaker.py", "python/p15/graph/__main__.py")
_TG = "python/tests/test_graph.py"
OCR, OCS = "bench/open_cost/run.py", "bench/open_cost/summarize.py"
_TO = "bench/open_cost/test_open_cost.py"
PCS, PCP = "bench/prim_cost/summarize.py", "bench/prim_cost/prog_stats.py"
_TPC = "bench/prim_cost/test_prim_cost.py"
OSS = "bench/open_sections/summarize.py"
PWS, _TPW = "bench/path_walk/summarize.py", "bench/path_walk/test_path_walk.py"
_TT, _TR, _TP = "python/tests/test_trace.py", "python/tests/test_reconcile.py", "python/tests/test_provenance.py"
# a file's tests: one or several; a mutant is killed when any of them fails
TESTS = {WAL: "python/tests/test_wal.py", REC: "python/tests/test_records.py", TREE: (_TT, _TR),
         NET: _TT, TRACE: (_TT, _TR), HTML: _TT, SNAP: _TR, RECON: _TR, PROV: _TP,
         GRAW: _TG, GBUILD: _TG, GSQL: _TG, GPM: _TG, GCLI: _TG, OCR: _TO, OCS: _TO, PCS: _TPC, PCP: _TPC, PWS: _TPW}

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
 (REC, 'slack_ok = (lay.cls == "SPINE" and bool(h["flags"] & F_READ_FAILED)) or', 'slack_ok = bool(h["flags"] & F_READ_FAILED) or'),
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
 # decision 1a and N5: the read-path hook-cost report
 (RWH, "want = 0 if arm in UNTRACED else n", "want = n"),
 (RWH, "if hits != want:", "if False:"),
 (RWH, "if orphan:", "if False:"),
 (RWH, "if int(cpu) <= 0 or int(wall) <= 0:", "if False:"),
 (RWH, "elif rnd >= 0:", "elif True:"),
 (RWH, 'out[a].append(rows[r][a][metric] / rows[r][a]["n"])', "out[a].append(rows[r][a][metric])"),
 (RWH, 'if m[5] != "ok":', "if False:"),
 (RWH, "skips[arm][0] += int(rmiss)", "skips[arm][0] = int(rmiss)"),
 (RWH, "[x * v / w for x, v, w in zip(s[b], aa, u)]", "aa"),
 (RWH, 'return "\\n".join(out), 1 if bad else 0', 'return "\\n".join(out), 0'),
 # ADR-0007 rule 3 and ADR-0023: the snapshots, the tree's opening balance, the reconciliation
 (REC, 'if lay.name == "PROC" and (f["reserved"] or f["kind"] not in (1, 2) or f["pflags"] & ~3):',
  'if lay.name == "PROC" and f["reserved"]:'),
 (REC, 'if lay.name == "END" and h["version"] >= 2 and f["reserved"]:', "if False:"),
 (REC, 'if f["fflags"] & ~_FFLAGS_OK[lay.name]:', "if False:"),
 (REC, 'if bool(vl) != want:', "if False:"),
 (REC, 'if vl not in (0, dt.itemsize) or f[f"{vname}_full"] != vl:', "if vl not in (0, dt.itemsize):"),
 (REC, 'if vl not in (0, dt.itemsize) or f[f"{vname}_full"] != vl:', 'if f[f"{vname}_full"] != vl:'),
 (REC, 'out["oflags"] & ~OBJ_SUBVOL_UNKNOWN or ', ""),
 (REC, ' or out["seen"] not in (1, 2, 3, 4, 5)', ""),
 (REC, 'if lay.name == "OPEN" and not f["fflags"] & gen.FF_PATH_MISSING and f["verdict"]:', "if False:"),
 (REC, 'if lay.name == "OPEN_VERDICT" and f["verdict"] >= 0:', "if False:"),
 (REC, 'bool(f["fflags"] & gen.FF_PATH_ERROR) != bool(f["path_err"])', "False"),
 (REC, 'and bool(f["fflags"] & gen.FF_FULL_SIZE) and n == lay.max_size)', "and bool(f[\"fflags\"] & gen.FF_FULL_SIZE))"),
 (REC, 'want = bool(f["fflags"] & flag) if flag is not None else True', 'want = bool(f["fflags"] & flag) if flag is not None else bool(vl)'),
 (SNAP, 'if d["tasks"] != d["threads"] + d["emitted"] + d["write_failed"]:', "if False:"),
 (SNAP, 'if d["emitted"] != d["entries"] + d["invalid"] + d["unwritten"]:', "if False:"),
 (SNAP, 'if d["entries"] != len(self.procs) + self.duplicates:', "if False:"),
 (SNAP, 'return None if p.f["parent_tgid"] == 0 else', 'return None if False else'),
 (SNAP, "return None if self.done is None else self.done.h[\"ts_ns\"] - self.done.f[\"duration_ns\"]",
  "return None if self.done is None else self.done.h[\"ts_ns\"] + 10**12"),
 (SNAP, 'if d["fd_files"] != d["fd_no_inode"] + d["fd_emitted"] + d["fd_write_failed"]:', "if False:"),
 (SNAP, 'if d["fd_emitted"] != d["fd_known"] + d["fd_registered"] + d["fd_map_full"]:', "if False:"),
 (SNAP, 'if d["fd_entries"] != len(self.fds):', "if False:"),
 (SNAP, 'if d["fd_error"]:', "if False:"),
 (SNAP, 'if d["fd_write_failed"] or d["fd_invalid"] or d["fd_unwritten"]:', 'if d["fd_invalid"] or d["fd_unwritten"]:'),
 (SNAP, 'elif self.fds:', "elif False:"),
 (SNAP, 'snaps.setdefault(sid, Snapshot(sid, "unknown")).fds.append(r)', "pass"),
 (REC, 'if lay.name == "SNAP_DONE" and f.get("fd_pass", 0) > 1:', "if False:"),
 (TREE, "        if p.fork_ns is None:\n            p.parent = S.parent_key(pr)", "        if False:\n            p.parent = S.parent_key(pr)"),
 (TREE, "p.images.insert(0, im)", "pass"),
 (TREE, "proc(p.parent).children.append(k)", "pass"),
 (RECON, "if k in opening.procs or (p is not None and p.fork_ns is not None):", "if k in opening.procs:"),
 (RECON, "if p.fork_ns is not None and p.fork_ns >= began:", "if p.fork_ns is not None and p.fork_ns <= began:"),
 (RECON, "if p.exit_ns is None:\n            rec.exit_unexplained.append(k)", "if False:\n            rec.exit_unexplained.append(k)"),
 (RECON, 'p.parent = S.parent_key(pr)', "pass"),
 (RECON, "if fork_l is not None and len(rec.fork_unexplained) > fork_l:", "if False:"),
 (RECON, "if exit_l is not None and len(rec.exit_unexplained) > exit_l:", "if False:"),
 (RECON, 'elif end.f["closing_snapshot"] != 1:', "elif False:"),
 (RECON, "why += s.problems()", "pass"),
 (RECON, 'n = f[f"{kind}_reserve_failed"] + f[f"{kind}_build_failed"]', 'n = f[f"{kind}_reserve_failed"] + 10'),
 (TRACE, "out.append(self.recon.line())", "pass"),
 # code provenance (ADR-0025): the backing classes, the writable test and the pipe join
 (PROV, "return \"memory\" if nlink == 0 or name.startswith(b\"memfd:\") else \"tmpfs\"", "return \"tmpfs\""),
 (PROV, "if nlink == 0:\n        return \"deleted\"", "if False:\n        return \"deleted\""),
 (PROV, "if magic == OVERLAYFS:", "if False and magic == OVERLAYFS:"),
 (PROV, "if mode & _WOTH:\n        return True", "if False:\n        return True"),
 (PROV, "and not (fsuid == 0 and rec.f[\"exe_uid\"] == 0)", "and not (fsuid == 99999)"),
 (PROV, "if sin == \"socket\" and sout == \"socket\":", "if sin == \"socket\" or sout == \"socket\":"),
 (PROV, "w = writers.get((e.f[\"stdin_dev\"], e.f[\"stdin_ino\"]))", "w = writers.get((e.f[\"stdin_dev\"], 0))"),
 (PROV, "if w is not None and w is not e:", "if w is not None:"),
 # ---- graph v0 (ADR-0028): the generated raw tables, the loader, the node and edge rules, the export ----
 (GEN, 'if f.name not in ("type", "len"):', 'if f.name not in ("type",):'),
 (GEN, 'key=lambda r: -r.version):', 'key=lambda r: r.version):'),
 (GEN, 'if not f.name.startswith("_")]   # padding is not data', 'if True]'),
 (GEN, "if cn in seen_here or cn in fixed:", "if cn in seen_here:"),
 (GEN, "if cn in seen_here or cn in fixed:", "if cn in fixed:"),
 (GEN, "if cn in cols and cols[cn][0] != ct:", "if False:"),
 (GEN, "cols.setdefault(cn, (ct, cd))", "cols[cn] = (ct, cd)"),
 (GEN, 'return "BLOB" if ctype.startswith("char[") else SQL_TYPES[ctype]', 'return "BLOB" if ctype.startswith("char[") else "UBIGINT"'),
 (GEN, 'new += [(f"{v.name}_{f.name}", _sql_type(f.ctype), f"{v.name}: {f.doc}")', 'new += [(f"{f.name}", _sql_type(f.ctype), f"{v.name}: {f.doc}")'),
 (GRAW, '        elif v is not None:           # an absent part is None: its columns stay NULL\n            out[k] = v', '        else:\n            out[k] = v'),
 (GRAW, '                out[f"{k}_{pk}"] = pv', '                out[f"{k}_{pk}"] = 0'),
 (GRAW, "        if len(b) >= FLUSH_ROWS:\n            self.flush(r.name)", "        if len(b) >= FLUSH_ROWS:\n            b.clear()"),
 (GRAW, "            if extra:\n", "            if False:\n"),
 (GRAW, "mask = [v is None for v in vals]", "mask = [False for v in vals]"),
 (GRAW, "        rows.clear()\n", "        pass\n"),
 (GRAW, "    if errors:\n", "    if False:\n"),
 (GRAW, 'counts["record_error"] = len(errors)', 'counts["record_error"] = 0'),
 (GRAW, "meta = [(i, k, v) for i, seg in enumerate(run.segments) for k, v in seg.meta.items()]", "meta = []"),
 (GBUILD, 'return bytes(b).decode("utf-8", "backslashreplace")', 'return bytes(b).decode("utf-8", "replace")'),
 (GBUILD, "return socket.inet_ntop(socket.AF_INET, bytes(raw_addr)[:4])", "return socket.inet_ntop(socket.AF_INET, bytes(raw_addr)[-4:])"),
 (GBUILD, "    if family == socket.AF_INET6:\n", "    if True:\n"),
 (GBUILD, 'keys = [r.proc] if ring < 2 or r.name in ("PROC", "FD") else []', 'keys = [r.proc] if ring < 1 or r.name in ("PROC", "FD") else []'),
 (GBUILD, 'keys = [r.proc] if ring < 2 or r.name in ("PROC", "FD") else []', 'keys = [r.proc] if ring < 2 or r.name in ("PROC",) else []'),
 (GBUILD, "    if out.exists():\n", "    if False:\n"),
 (GBUILD, "        if not done:\n            out.unlink(missing_ok=True)", "        if False:\n            out.unlink(missing_ok=True)"),
 (GBUILD, 'im.filename if im else None, " ".join(im.argv) if im and im.argv else None, p.comm,', 'im.filename if im else None, None, p.comm,'),
 (GBUILD, "par = p.parent or (None, None)", "par = (None, None)"),
 (GBUILD, 'p.origin or "forked in the run", p.kthread, p.in_gap,', 'p.origin, p.kthread, p.in_gap,'),
 (GBUILD, "min(seen) if seen else k[1], p.fork_ns, p.exit_ns, p.exit_code,", "min(seen) if seen else k[1], p.fork_ns, p.exit_ns, 0,"),
 (GSQL, "fs_magic IN (m_ext4(), m_xfs(), m_tmpfs()) OR (fs_magic = m_btrfs() AND (oflags & 1) = 0);", "fs_magic IN (m_ext4(), m_xfs(), m_tmpfs()) OR (fs_magic = m_btrfs());"),
 (GSQL, "fs_magic IN (m_ext4(), m_xfs(), m_tmpfs()) OR (fs_magic = m_btrfs() AND (oflags & 1) = 0);", "fs_magic IN (m_xfs(), m_tmpfs()) OR (fs_magic = m_btrfs() AND (oflags & 1) = 0);"),
 (GSQL, "fs_magic IN (m_ext4(), m_xfs(), m_tmpfs()) OR (fs_magic = m_btrfs() AND (oflags & 1) = 0);", "true;"),
 (GSQL, "    WHEN fs_magic = m_anon() AND fid IS NOT NULL THEN 'fid'   -- ADR-0027\n", ""),
 (GSQL, "    WHEN 'tuple' THEN 't:' || dev || ':' || subvol || ':' || ino || ':' || gen", "    WHEN 'tuple' THEN 't:' || dev || ':' || subvol || ':' || ino"),
 (GSQL, "    WHEN 'tuple' THEN 't:' || dev || ':' || subvol || ':' || ino || ':' || gen", "    WHEN 'tuple' THEN 't:' || dev || ':0:' || ino || ':' || gen"),
 (GSQL, "    WHEN 'fid' THEN 'f:' || fid\n", "    WHEN 'fid' THEN 'o:' || obj\n"),
 (GSQL, "WHEN 16384 THEN 'dir' WHEN 8192 THEN 'char' WHEN 4096 THEN 'pipe'", "WHEN 16384 THEN 'dir' WHEN 8192 THEN 'char' WHEN 4096 THEN 'file'"),
 (GSQL, "QUALIFY row_number() OVER (PARTITION BY obj ORDER BY ts_ns, ring, seq) = 1;", "QUALIFY row_number() OVER (PARTITION BY obj ORDER BY ts_ns DESC, ring, seq) = 1;"),
 (GSQL, "FROM raw_fd WHERE facts_len > 0\n", "FROM raw_fd WHERE false\n"),
 (GSQL, "FROM raw_backing WHERE user_facts_len > 0;", "FROM raw_backing WHERE false;"),
 (GSQL, "SELECT * FROM fid_row QUALIFY row_number() OVER (PARTITION BY fid ORDER BY pri, ts_ns, ring, seq) = 1\n), path AS (", "SELECT * FROM fid_row QUALIFY row_number() OVER (PARTITION BY fid ORDER BY ts_ns DESC, ring, seq) = 1\n), path AS ("),
 (GSQL, "bool_or((fflags & 32) <> 0) AS never_opened", "false AS never_opened"),
 (GSQL, "        UNION ALL SELECT fid, verdict FROM raw_open WHERE verdict < 0) GROUP BY fid", "        ) GROUP BY fid"),
 (GSQL, "        SELECT fid, verdict FROM raw_open_verdict\n        UNION ALL SELECT", "        SELECT"),
 (GSQL, "ON o.dev = e.dev AND o.ino = e.ino AND o.gen = e.gen AND o.ts_ns <= e.ts_ns", "ON o.dev = e.dev AND o.ino = e.ino AND o.gen = e.gen"),
 (GSQL, "ON o.dev = e.dev AND o.ino = e.ino AND o.gen = e.gen AND o.ts_ns <= e.ts_ns", "ON o.ino = e.ino AND o.gen = e.gen AND o.ts_ns <= e.ts_ns"),
 (GSQL, "OVER (PARTITION BY e.ring, e.seq ORDER BY o.ts_ns DESC, o.obj DESC) = 1", "OVER (PARTITION BY e.ring, e.seq ORDER BY o.ts_ns, o.obj) = 1"),
 (GSQL, "       CASE WHEN e.fs_magic IN (m_ext4(), m_xfs(), m_tmpfs()) THEN 't:' || e.dev || ':0:' || e.ino || ':' || e.gen\n            WHEN m.key IS NOT NULL THEN m.key", "       CASE WHEN m.key IS NOT NULL THEN m.key"),
 (GSQL, "    FROM obj_facts o WHERE NOT EXISTS (SELECT 1 FROM openfile f WHERE f.obj = o.obj)", "    FROM obj_facts o"),
 (GSQL, "    FROM obj_facts o WHERE NOT EXISTS (SELECT 1 FROM openfile f WHERE f.obj = o.obj)", "    FROM obj_facts o WHERE false"),
 (GSQL, "ORDER BY (op IN (1, 2)) DESC, ts_ns, seq) = 1", "ORDER BY ts_ns, seq) = 1"),
 (GSQL, "nullif((SELECT max(peer_cookie) FROM r WHERE r.cookie = f.cookie), 0) AS listener_cookie", "NULL AS listener_cookie"),
 (GSQL, "(SELECT bool_or(op = 3 AND ret = 0) FROM r WHERE r.cookie = f.cookie) AS listening", "(SELECT bool_or(ret = 0) FROM r WHERE r.cookie = f.cookie) AS listening"),
 (GSQL, "(row_number() OVER (ORDER BY kind_order, first_ns, key))::BIGINT AS node_id", "(row_number() OVER (ORDER BY first_ns, key))::BIGINT AS node_id"),
 (GSQL, "SELECT DISTINCT fo.file_node AS real_node, un.node_id AS user_node", "SELECT DISTINCT un.node_id AS real_node, fo.file_node AS user_node"),
 (GSQL, " AND (c.flags & 4) <> 0 AND (a.flags & 4) <> 0 AND c.tcp_isn = a.tcp_isn", " AND c.tcp_isn = a.tcp_isn"),
 (GSQL, " AND (c.flags & 4) <> 0 AND (a.flags & 4) <> 0 AND c.tcp_isn = a.tcp_isn", " AND (c.flags & 4) <> 0 AND (a.flags & 4) <> 0"),
 (GSQL, " AND c.netns = a.netns AND c.family = a.family AND c.laddr = a.raddr AND c.lport = a.rport", " AND c.netns = a.netns AND c.family = a.family AND c.laddr = a.raddr"),
 (GSQL, " AND c.raddr = a.laddr AND c.rport = a.lport AND c.ret IN (0, -115) AND a.ret = 0", " AND c.raddr = a.laddr AND c.rport = a.lport AND c.ret IN (0) AND a.ret = 0"),
 (GSQL, "FROM raw_fork WHERE kind = 1\n", "FROM raw_fork\n"),
 (GSQL, "SELECT ts_ns, 'p:' || tgid || ':' || start_ns AS src, 'p:' || child_tgid || ':' || child_start_ns AS dst,", "SELECT ts_ns, 'p:' || child_tgid || ':' || child_start_ns AS src, 'p:' || tgid || ':' || start_ns AS dst,"),
 (GSQL, "SELECT e.ts_ns, x.file_key, 'p:' || e.tgid || ':' || e.start_ns, 'EXECUTE', true, 0, NULL, NULL, e.ring, e.seq", "SELECT e.ts_ns, 'p:' || e.tgid || ':' || e.start_ns, x.file_key, 'EXECUTE', true, 0, NULL, NULL, e.ring, e.seq"),
 (GSQL, "       f.verdict = 0 AND NOT f.never_opened, f.verdict, o.fid,", "       f.verdict = 0, f.verdict, o.fid,"),
 (GSQL, "       f.verdict = 0 AND NOT f.never_opened, f.verdict, o.fid,", "       NOT f.never_opened, f.verdict, o.fid,"),
 (GSQL, "       CASE (o.f_mode & 3) WHEN 1 THEN 'r' WHEN 2 THEN 'w' WHEN 3 THEN 'rw' ELSE '-' END, o.ring, o.seq", "       CASE (o.f_mode & 3) WHEN 1 THEN 'w' WHEN 2 THEN 'r' WHEN 3 THEN 'rw' ELSE '-' END, o.ring, o.seq"),
 (GSQL, "      QUALIFY row_number() OVER (PARTITION BY d.tgid, d.start_ns, d.fid ORDER BY d.ts_ns, d.seq) = 1)", "      )"),
 (GSQL, "      QUALIFY row_number() OVER (PARTITION BY d.tgid, d.start_ns, d.fid ORDER BY d.ts_ns, d.seq) = 1)", "      QUALIFY row_number() OVER (PARTITION BY d.fid ORDER BY d.ts_ns, d.seq) = 1)"),
 (GSQL, "'CONNECT', ret IN (0, -115), ret, NULL, NULL, ring, seq", "'CONNECT', true, ret, NULL, NULL, ring, seq"),
 (GSQL, "SELECT ts_ns, 's:' || sock_cookie, 'p:' || tgid || ':' || start_ns, 'ACCEPT', ret = 0, ret, NULL, NULL, ring, seq", "SELECT ts_ns, 'p:' || tgid || ':' || start_ns, 's:' || sock_cookie, 'ACCEPT', ret = 0, ret, NULL, NULL, ring, seq"),
 (GSQL, "CASE op WHEN 3 THEN 'LISTEN' ELSE 'BIND' END", "'LISTEN'"),
 (GSQL, "        HAVING count(DISTINCT (ino, subvol, dev, gen, fs_magic, mode & 61440)) > 1)),", "        HAVING count(DISTINCT (ino, subvol, dev, gen, fs_magic, mode & 61440, nlink)) > 1)),"),
 (GSQL, "        HAVING count(DISTINCT (ino, subvol, dev, gen, fs_magic, mode & 61440)) > 1)),", "        HAVING false)),"),
 (GSQL, "(SELECT fid FROM fid_row GROUP BY fid HAVING count(DISTINCT obj) > 1)),", "(SELECT fid FROM fid_row GROUP BY fid HAVING false)),"),
 (GSQL, "WHERE how = 'open' AND path IS NULL),", "WHERE path IS NULL),"),
 (GSQL, "coalesce(s.open_path, x.name) AS path,", "s.open_path AS path,"),
 (GSQL, "coalesce(s.open_path, x.name) AS path,", "coalesce(x.name, s.open_path) AS path,"),
 (GSQL, "    SELECT b.value::UBIGINT AS boottime_ns, r.value::UBIGINT AS realtime_ns", "    SELECT b.value::UBIGINT AS boottime_ns, b.value::UBIGINT AS realtime_ns"),
 (GPM, "WHERE e.ok ORDER BY e.edge_id", "ORDER BY e.edge_id"),
 (GPM, "sha256(u.uuid) AS hash_id, coalesce(p.exe_path, '{NULL}') AS path,", "md5(u.uuid) AS hash_id, coalesce(p.exe_path, '{NULL}') AS path,"),
 (GPM, "w.wall_ns AS timestamp_rec", "e.ts_ns::BIGINT AS timestamp_rec"),
 (GPM, "FROM edge e ASOF LEFT JOIN clock c ON e.ts_ns >= c.boottime_ns", "FROM edge e ASOF JOIN clock c ON e.ts_ns >= c.boottime_ns"),
 (GPM, "+ (e.ts_ns::BIGINT - coalesce(c.boottime_ns, f.boottime_ns)::BIGINT))::BIGINT AS wall_ns", "+ (e.ts_ns::BIGINT - f.boottime_ns::BIGINT))::BIGINT AS wall_ns"),
 (GCLI, "except (W.RunError, W.HeaderError, R.RecordError, OSError) as e:", "except (W.RunError, W.HeaderError, R.RecordError, FileExistsError) as e:"),
 (GPM, "SELECT sha256(su.uuid) AS src_node, e.src::VARCHAR AS src_index_id, o.name AS operation,", "SELECT sha256(su.uuid) AS src_node, e.dst::VARCHAR AS src_index_id, o.name AS operation,"),
 (GPM, "(SELECT run FROM run_id) || ':' || e.ring || ':' || e.seq || ':' || e.op AS event_uuid,", "(SELECT run FROM run_id) || ':' || e.seq || ':' || e.op AS event_uuid,"),
 (GPM, "s.laddr AS src_addr, s.lport::VARCHAR AS src_port,", "s.raddr AS src_addr, s.lport::VARCHAR AS src_port,"),
 (GPM, '    out.mkdir(parents=True, exist_ok=False)', '    out.mkdir(parents=True, exist_ok=True)'),
 (GPM, '"OPEN": "EVENT_OPEN",', '"OPEN": "EVENT_READ",'),
 (GPM, "    if unknown:\n", "    if False:\n"),
 (GPM, '{f"{op} (not allowed by the kernel)": n for op, ok, n in by_op if not ok}', '{f"{op} (not allowed by the kernel)": n for op, ok, n in by_op if ok}'),
 (GPM, "for op, ok, n in by_op if ok and op in NOT_EXPORTED},", "for op, ok, n in by_op if op in NOT_EXPORTED},"),
 (GPM, '"SELECT count(*) FROM edge e WHERE e.ok AND e.ts_ns < (SELECT min(boottime_ns) FROM clock)"', '"SELECT count(*) FROM edge e WHERE e.ok AND e.ts_ns > (SELECT min(boottime_ns) FROM clock)"'),
 (GPM, "if sum(exported.values()) != sum(n for op, ok, n in by_op if ok and op in OPS):", "if False:"),
 (GPM, "coalesce(p.cmd, p.comm, '{NULL}') AS cmd", "coalesce(p.cmd, p.comm, '') AS cmd"),
 (GCLI, '    if res.raw_rows["record_error"]:\n', "    if False:\n"),
 (GCLI, "    bad = [k for k in MUST_BE_ZERO if res.counts.get(k, 0)]", "    bad = []"),
 (GCLI, '        return 2\n    print(f"graph: {a.out}")', '        return 0\n    print(f"graph: {a.out}")'),
 (GCLI, "        return 1\n    return 0", "        return 0\n    return 0"),
 # ---- the open-cost harness (decision 22a.4): the driver's books and the report ----
 (OCR, "    k = rnd % len(ARMS)\n", "    k = 0\n"),
 (OCR, "            total += int((t / \"schedstat\").read_text().split()[0])", "            total = int((t / \"schedstat\").read_text().split()[0])"),
 (OCR, "    if not tasks:\n", "    if False:\n"),
 (OCR, "    if r.returncode != 0:\n", "    if False:\n"),
 (OCR, 'if "pid" not in head or len(rows) != 3:', 'if "pid" not in head:'),
 (OCR, "            if r.h[\"tgid\"] != pid:\n", "            if False:\n"),
 (OCR, '            elif r.f["fflags"] & R.gen.FF_PATH_MISSING:', "            elif False:"),
 (OCR, '            elif r.var["path"].startswith(prefix):', "            else:"),
 (OCR, 'prefix = str(d).encode() + b"/"', "prefix = str(d).encode()"),
 (OCR, '                out["facts"] += r.var["facts"] is not None', '                out["facts"] += 1'),
 (OCR, '        if r.name == "CLOSE" and r.f["fid"] in fids:', '        if r.name == "CLOSE":'),
 (OCR, 'for k in ("open_lost", "close_lost", "missing_lost", "verdict_lost", "backing_lost"))', 'for k in ("close_lost", "missing_lost", "verdict_lost", "backing_lost"))'),
 (OCR, 'out["ok"] = int(end is not None and out["state"] == 0 and', 'out["ok"] = int(end is not None and'),
 (OCR, 'out["state"] == 0 and out["invariant"] == 1 and out["lost"] == 0 and', 'out["state"] == 0 and out["lost"] == 0 and'),
 (OCR, 'out["invariant"] == 1 and out["lost"] == 0 and', 'out["invariant"] == 1 and'),
 (OCR, 'out["stops"] == 0 and 0 <= short <= out["path_missing"] and out["closes"] == out["opens"])', 'out["stops"] == 0 and short <= out["path_missing"] and out["closes"] == out["opens"])'),
 (OCR, 'out["stops"] == 0 and 0 <= short <= out["path_missing"] and out["closes"] == out["opens"])', 'out["stops"] == 0 and 0 <= short and out["closes"] == out["opens"])'),
 (OCR, 'out["stops"] == 0 and 0 <= short <= out["path_missing"] and out["closes"] == out["opens"])', 'out["stops"] == 0 and 0 <= short <= out["path_missing"])'),
 (OCR, "        if proc.poll() is not None:\n", "        if False:\n"),
 (OCR, "    if code != 0:\n        b[\"ok\"] = 0", "    if False:\n        b[\"ok\"] = 0"),
 (OCR, "        if b[\"ok\"]:\n            log.unlink(missing_ok=True)", "        if True:\n            log.unlink(missing_ok=True)"),
 (OCR, "    if not a.keep:\n", "    if False:\n"),
 (OCS, "            elif int(rnd) >= 0:\n", "            elif True:\n"),
 (OCS, "            if (arm, event) in rows[int(rnd)]:", "            if False:"),
 (OCS, "            if arm not in ARMS or event not in EVENTS:", "            if event not in EVENTS:"),
 (OCS, "            if set(f) != set(CAP_KEYS):", "            if False:"),
 (OCS, '            if m[3] != "ok":', "            if False:"),
 (OCS, '        elif line.startswith("error "):\n            bad.append(line)', '        elif line.startswith("error "):\n            pass'),
 (OCS, "        elif line.strip():\n            raise ParseError(f\"unknown line: {line}\")", "        elif False:\n            raise ParseError(f\"unknown line: {line}\")"),
 (OCS, "        if missing:\n            raise ParseError(f\"round {r}: missing", "        if False:\n            raise ParseError(f\"round {r}: missing"),
 (OCS, "        if r not in caps:\n", "        if False:\n"),
 (OCS, "diff = P.hodges_lehmann([a - b for a, b in zip(t, u)])", "diff = P.hodges_lehmann([a - b for a, b in zip(t, aa)])"),
 (OCS, 't, u, aa = (per_op(rows, a, event, metric) for a in ("p15d", "none", "none2"))', 't, u, aa = (per_op(rows, a, event, metric) for a in ("p15d", "none2", "none"))'),
 (OCS, 'recs = sum(x["opens"] + x["path_missing"] + x["closes"] for x in c)', 'recs = sum(x["opens"] + x["closes"] for x in c)'),
 (OCS, "net = [(x[\"agent_cpu_ns\"] - ir * x[\"agent_wall_ns\"] / 1e9) / x[\"expected\"] for x, ir in zip(c, idle_rate)]", "net = [x[\"agent_cpu_ns\"] / x[\"expected\"] for x, ir in zip(c, idle_rate)]"),
 (OCS, 'open_cpu = [sum(rows[r][("none", e)]["cpu_ns"] for e in OPEN_EVENTS) for r in rounds]', 'open_cpu = [sum(rows[r][("none", e)]["cpu_ns"] for e in EVENTS) for r in rounds]'),
 (OCS, 'all_cpu = [sum(rows[r][("none", e)]["cpu_ns"] for e in EVENTS) for r in rounds]', 'all_cpu = [sum(rows[r][("none", e)]["cpu_ns"] for e in OPEN_EVENTS) for r in rounds]'),
 (OCS, 'null_ns = P.median(per_op(rows, "none", "nullsys", "cpu_ns"))', 'null_ns = P.median(per_op(rows, "p15d", "same", "cpu_ns"))'),
 (OCS, '    if bad:\n        out += ["## Books that did not close: no timing is reported", ""]', '    if False:\n        out += ["## Books that did not close: no timing is reported", ""]'),

 # ---- prim_cost and prog_stats (after E-0176): where a capture program's time goes ----
 (PCS, "            if ok != n:\n", "            if False:\n"),
 (PCS, "            elif int(rnd) >= 0:\n                if prim in rows[int(rnd)]:", "            elif True:\n                if prim in rows[int(rnd)]:"),
 (PCS, "                if prim in rows[int(rnd)]:\n", "                if False:\n"),
 (PCS, '            if m[3] != "ok" or ring[0] != ring[1]:', '            if m[3] != "ok":'),
 (PCS, '            if m[3] != "ok" or ring[0] != ring[1]:', "            if ring[0] != ring[1]:"),
 (PCS, "    if ring is None:\n", "    if False:\n"),
 (PCS, "        if missing:\n", "        if False:\n"),
 (PCS, '        net = [rows[r][p] - rows[r]["empty"] for r in rounds]', "        net = [rows[r][p] for r in rounds]"),
 (PCS, "    if bad:\n        return", "    if False:\n        return"),
 (PCS, '        elif line.strip():\n            raise ParseError(f"unknown line: {line}")', '        elif False:\n            raise ParseError(f"unknown line: {line}")'),
 (PCP, "        if runs < 0 or ns < 0:\n", "        if False:\n"),
 (PCP, "        if runs:\n", "        if True:\n"),
 (PCP, 'runs, ns = a["run_cnt"] - b["run_cnt"], a["run_time_ns"] - b["run_time_ns"]', 'runs, ns = a["run_cnt"], a["run_time_ns"]'),
 (PCP, 'return sorted(out, key=lambda r: -r["ns"])', "return out[::-1]"),
 (PCP, "    if not isinstance(progs, list):\n", "    if False:\n"),
 (PCP, '        if "id" not in p:\n', "        if False:\n"),
 (PCP, """line += f" {r['runs'] / ops:.3f} | {r['ns'] / ops:.1f} |\"""", """line += f" {r['runs'] / ops:.3f} | {r['ns'] / r['runs']:.1f} |\""""),
 # ---- the host-speed control and the rounds of prog_stats (E-0180) ----
 (PCS, "    if hi > STEADY * lo:\n", "    if False:\n"),
 (PCS, "    if hi > STEADY * lo:\n", "    if hi >= STEADY * lo:\n"),
 (PCS, "    if ref is not None and med > SLOW * ref:\n", "    if ref is not None and med >= SLOW * ref:\n"),
 (PCS, "    if ref is not None and med > SLOW * ref:\n", "    if False:\n"),
 (PCS, "    if not ns:\n", "    if False:\n"),
 (PCS, "            if int(m[1]) in host:\n", "            if False:\n"),
 (PCS, "            if int(m[2]) <= 0 or int(m[3]) <= 0:\n", "            if int(m[2]) <= 0:\n"),
 (PCS, "            if int(m[2]) <= 0 or int(m[3]) <= 0:\n", "            if int(m[3]) <= 0:\n"),
 (PCS, "        if host and r not in host:\n", "        if False:\n"),
 (PCS, "[host[r] for r in sorted(rows) if r in host]", "list(host.values())"),
 (PCS, "lo, hi, med = min(ns), max(ns), P.median(ns)", "lo, hi, med = min(ns), max(ns), max(ns)"),
 (PCP, "    if not m or int(m[1]) <= 0 or int(m[2]) <= 0:\n", "    if not m or int(m[1]) <= 0:\n"),
 (PCP, "    if not m or int(m[1]) <= 0 or int(m[2]) <= 0:\n", "    if not m or int(m[2]) <= 0:\n"),
 (PCP, 'NULLSYS = re.compile(r"^row event=nullsys', 'NULLSYS = re.compile(r"row event=nullsys'),
 (PCP, "    if any(x is None for x in ns) and any(x is not None for x in ns):\n", "    if False:\n"),
 (PCP, 'e["runs"] += r["runs"]', 'e["runs"] = r["runs"]'),
 (PCP, 'key=lambda e: -P.median(e["ns"])', 'key=lambda e: P.median(e["ns"])'),
 (PCP, "{min(e['per_run']):.1f} to", "{max(e['per_run']):.1f} to"),
 (PCP, "{P.median(total) / ops:.1f}", "{sum(total) / ops:.1f}"),
 (PCP, "{e['runs'] / (ops * len(e['ns'])):.3f}", "{e['runs'] / ops:.3f}"),
 # ---- path_walk: the walk against bpf_d_path (gate 2): a wrong path without a flag must fail the run ----
 (PWS, '        if r["verdict"] == "MISMATCH":\n', '        if False:\n'),
 (PWS, '        elif r["verdict"] not in ("equal", "flagged"):\n', '        elif False:\n'),
 (PWS, '    if race["mismatch"]:\n', '    if False:\n'),
 (PWS, '    if race["samples"] - race["moved"] <= 0:\n', '    if race["samples"] <= 0:\n'),
 (PWS, '    if len(ends) != 1:\n', '    if not ends:\n'),
 (PWS, '            ends.append((int(m[1]), int(m[2], 16)))', '            ends.append((int(m[1]), 0))'),
 (PWS, '        fails.append("no timing rounds")', '        pass'),
 (PWS, '            if rnd < 0:\n                continue\n', ''),
 (PWS, '            if fr != n or kr != n:\n', '            if fr != n:\n'),
 (PWS, '            if fr != n or kr != n:\n', '            if kr != n:\n'),
 (PWS, '            if n is None:\n                raise', '            if False:\n                raise'),
 (PWS, '            if not m or n is not None:\n', '            if not m:\n'),
 (PWS, '            n = int(m[2])\n', '            n = int(m[1])\n'),
 (PWS, '    if missing:\n', '    if False:\n'),
 (PWS, '    if len(races) != 1:\n', '    if not races:\n'),
 (PWS, '            if name in cases:\n', '            if False:\n'),
 (PWS, '            raise ParseError(f"unknown line: {line}")', '            pass'),
 (PWS, '        elif r["verdict"] != exp:\n', '        elif False:\n'),
 (PWS, 'EXPECT = {"deep70": "flagged"}', 'EXPECT = {}'),
 (PWS, '            if x["verdict"] == "MISMATCH":\n', '            if False:\n'),
 (PWS, '        if len(c["more"]) != max(0, min(c["n"], KEEP) - 1):\n', '        if len(c["more"]) != max(0, c["n"] - 1):\n'),
 (PWS, '            if c is None or int(m[2]) != len(c["more"]) + 1:\n', '            if c is None:\n'),
 (PWS, '            if c is None or int(m[2]) != len(c["more"]) + 1:\n', '            if int(m[2]) != len(c["more"]) + 1:\n'),
 (PWS, '"overlay", "deleted", "memfd", "pipe", "socket", "eventfd", "chroot")', '"overlay", "deleted", "memfd", "pipe", "chroot")'),
 (PWS, '(256, "RETRIED"), (512, "SYNTH"))', '(256, "RETRIED"), (512, "SYNTH"), (1, "X"))'),
 (PWS, '(1, "TRUNCATED"), (2, "RACED")', '(2, "TRUNCATED"), (1, "RACED")'),
 (PWS, '            med = [statistics.median(col) for col in zip(*rows)]', '            med = [statistics.mean(col) for col in zip(*rows)]'),
 (PWS, "    return \"\\n\".join(out + [\"\"]), 1 if fails else 0", "    return \"\\n\".join(out + [\"\"]), 0"),
 (OSS, '    if w["walked"] + w["walk_unnamed"] != c["missing"]:\n', '    if False:\n'),
 (OSS, '    if w["rec_walked"] != w["walked"]:\n', '    if False:\n'),
 (OSS, '    if w["target_wrong"]:\n', '    if False:\n'),
 (OSS, '    if c["missing"] and not w["target"]:\n', '    if not w["target"]:\n'),
 (OSS, '            if not m or out["walk"] is not None:\n', '            if not m:\n'),
 (OSS, '        if d["contend"] is not None or d["walk"] is not None:\n', '        if d["contend"] is not None:\n'),
 # ---- open_sections: the section report and the skip count under contention (decisions waiting 1-2) ----
 (OSS, "            if rows[r][s][0] != cfg[\"n\"]:\n", "            if False:\n"),
 (OSS, 'WHOLE = ("open_all", "sess_entry", "sess_return", "free_all")', 'WHOLE = ("open_all",)'),
 (OSS, "        if r not in d[\"host\"]:\n", "        if False:\n"),
 (OSS, '        net = [per(r, s) - per(r, "empty") for r in timed]', '        net = [per(r, s) for r in timed]'),
 (OSS, '    timed = [r for r in sorted(rows) if r >= 0]', '    timed = sorted(rows)'),
 (OSS, '            rest = med[whole] - sum(med[p] for p in parts)', '            rest = med[whole]'),
 (OSS, '            if m[1] != "ok":\n', '            if False:\n'),
 (OSS, '    if out["books"] is None:\n', '    if False:\n'),
 (OSS, '    if c["fentry_run"] + c["missing"] < c["opens"]:\n', '    if c["fentry_run"] < c["opens"]:\n'),
 (OSS, '    seen = c["fentry_run"] + c["missing"]', '    seen = c["fentry_run"]'),
 (OSS, '{3 / seen:.2e}', '{1 / seen:.2e}'),
 (OSS, '+ ("" if c["missing"] else', '+ ("" if True else'),
 (OSS, '            if sec in out["rows"][r]:\n', '            if False:\n'),
 (OSS, '        if d["contend"] is not None or d["walk"] is not None:\n', '        if d["walk"] is not None:\n'),
 (OSS, 'out += PC.host_lines([d["host"][r] for r in timed], ref)[0]', 'out += PC.host_lines([d["host"][r] for r in sorted(rows)], ref)[0]'),
]


def _only(args: list[str]) -> set[int] | None:
    if not args:
        return None
    out: set[int] = set()
    for a in args:
        lo, _, hi = a.partition("-")
        out |= set(range(int(lo), int(hi or lo) + 1))
    return out


def main() -> int:
    only = _only(sys.argv[1:])
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
            if only is not None and i not in only:
                continue
            if originals[f].count(old) != 1:
                print(f"mutant {i}: anchor not found exactly once in {f}; update this sweep")
                return 2
            (ROOT / f).write_text(originals[f].replace(old, new))
            t = TESTS.get(f, str((ROOT / f).parent.relative_to(ROOT) / f"test_{(ROOT / f).name}"))
            tests = [ROOT / x for x in ((t,) if isinstance(t, str) else t)]
            dead = any(subprocess.run([sys.executable, "-B", "-m", "unittest", str(x)], capture_output=True,
                                      text=True, env=env).returncode != 0 for x in tests)
            (ROOT / f).write_text(originals[f])
            killed += dead
            print(("killed   " if dead else "SURVIVED "), i, pathlib.Path(f).name, old.strip()[:60])
    finally:
        for f, text in originals.items():
            (ROOT / f).write_text(text)
    total = len(M) if only is None else len(only & set(range(len(M))))
    print(f"mutation sweep: {killed}/{total} killed" + ("" if only is None else " (a subset: not the gate)"))
    return 0 if killed == total else 1


if __name__ == "__main__":
    sys.exit(main())
