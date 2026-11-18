# SPDX-License-Identifier: MIT
"""Compare p15d's graph of a workload with what strace saw of it, and check an attack's manifest.

    python3 tools/workloads/compare.py GRAPH.duckdb STRACE.txt [--light] [--manifest M.json]
                                       [--p15d-rc N] [--json OUT.json]

Recall, per kind of fact, is the share of strace's facts the graph holds (oracle.py says what each
fact is and why it is comparable). Every miss is listed (the first 20 of each kind) so it can be
explained or filed. Facts the graph holds about the workload's processes that strace did not see
are counted as `extra` with their first examples: the kernel opens an exec's program and its ELF
interpreter itself (no open syscall), so those extras are expected and labelled.

Bytes are compared per process: file and pipe bytes read and written (READ/WRITE edges) and socket
bytes received and sent (RECV/SEND), against the same calls in strace. A run that lost FLOWs ends
DEGRADED (p15d exit 3, ADR-0051); with exit 0 any byte difference is a capture or graph defect,
unless strace saw calls the flow programs do not hook by design (`unseen`), which are reported
with their bytes.

The manifest (written by an attack scenario, tools/workloads/scenarios/a*.sh) states what the
attack did, in its own words:
  {"reach":  [{"name": .., "from_path": "/abs/file", "to_port": 14444, "bytes": 1234}],
   "rules":  ["R1", "R2"],                        alerts the graph's rules should raise
   "refused": [14501, 14502],                     ports whose connect was refused
   "comm":   ["kworker/0:1"]}                     a process renamed itself to this
`reach` holds when the graph's forward walk (p15.graph.track) from the file reaches the process
that listened on to_port; `bytes` when that process's RECV edges on the port's sockets carry
exactly that many bytes.

Exit 0 when every check ran (the verdicts are in the output); 2 on a usage or input error.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))
import oracle as O  # noqa: E402
from p15 import records as R  # noqa: E402
from p15.graph import rules as RL  # noqa: E402
from p15.graph import track as TR  # noqa: E402

FAM = {"AF_INET": 2, "AF_INET6": 10}
SHOW = 20


def ret_of(result: str) -> int:
    return 0 if result == "ok" else -getattr(errno, result, 0) if result.startswith("E") else int(result)


def recall(name: str, want: set, have: set, out: dict, note: str = "") -> None:
    miss = sorted(want - have, key=str)
    out["recall"][name] = {"oracle": len(want), "found": len(want) - len(miss),
                           "ratio": round((len(want) - len(miss)) / len(want), 6) if want else None,
                           "missed": [list(x) if isinstance(x, tuple) else x for x in miss[:SHOW]],
                           "missed_total": len(miss), "note": note}


def compare(con: duckdb.DuckDBPyConnection, f: O.Facts, manifest: dict | None, p15d_rc: int | None) -> dict:
    out: dict = {"p15d_rc": p15d_rc, "oracle_counts": dict(f.counts), "recall": {}, "extra": {}, "bytes": {},
                 "unseen": {k: {"calls": f.unseen[k], "bytes": f.unseen_bytes[k]} for k in f.unseen},
                 "unix_connects": f.unix_connects, "opath_opens": len(f.opath), "root": f.root, "attack": None}
    T = sorted(f.procs)
    con.execute("CREATE TEMP TABLE wl(tgid UINTEGER)")
    if T:
        con.executemany("INSERT INTO wl VALUES (?)", [(t,) for t in T])

    # processes and their parents
    have_procs = {r[0] for r in con.execute("SELECT DISTINCT p.tgid FROM proc p JOIN wl USING (tgid)").fetchall()}
    recall("processes", set(T), have_procs, out)
    clones = set(con.execute("""SELECT ps.tgid, pd.tgid FROM edge e JOIN proc ps ON ps.node_id = e.src
                                JOIN proc pd ON pd.node_id = e.dst WHERE e.op = 'CLONE'
                                AND pd.tgid IN (SELECT tgid FROM wl)""").fetchall())
    recall("clone_edges", f.clones, clones, out)
    # extra processes: in the graph under the workload's root, unseen by strace
    rows = con.execute("SELECT node_id, tgid, parent_node FROM proc").fetchall()
    tg = {n: t for n, t, _ in rows}
    kids = defaultdict(list)
    for n, _, pn in rows:
        if pn is not None:
            kids[pn].append(n)
    under, stack = set(), [n for n, t, _ in rows if t == f.root]
    while stack:
        n = stack.pop()
        if n not in under:
            under.add(n)
            stack.extend(kids[n])
    extra_p = sorted({tg[n] for n in under} - set(T))
    out["extra"]["processes"] = {"n": len(extra_p), "first": extra_p[:SHOW]}

    # execs: the path as passed, or the same last component (a PATH lookup or a symlink)
    imgs = defaultdict(set)
    for t, fn in con.execute("""SELECT p.tgid, i.filename FROM proc_image i JOIN proc p USING (node_id)
                                 JOIN wl USING (tgid) WHERE i.seen_in = 'exec'""").fetchall():
        imgs[t].add(fn or "")
    exact = {(t, p) for t, p in f.execs if p in imgs.get(t, ())}
    base = {(t, p) for t, p in f.execs if (t, p) not in exact
            and os.path.basename(p) in {os.path.basename(x) for x in imgs.get(t, ())}}
    recall("execs", f.execs, exact | base, out, f"{len(base)} matched by last component only")

    # opens: the open file's own path (openfile.path, from the OPEN record), per process
    have_open = set(con.execute("""SELECT p.tgid, o.path FROM edge e JOIN proc p ON p.node_id = e.dst
                                   JOIN openfile o ON o.fid = e.fid JOIN wl ON wl.tgid = p.tgid
                                   WHERE e.op = 'OPEN' AND e.ok""").fetchall())
    recall("opens", f.opens, have_open, out)
    # the kernel opens an exec's program (the file of its EXECUTE edge, whatever path the exec was
    # given: /proc/self/fd/N for a memfd) and its ELF interpreter with no open call
    exec_files = set(con.execute("""SELECT p.tgid, f.path FROM edge e JOIN proc p ON p.node_id = e.dst
                                    JOIN file f ON f.node_id = e.src JOIN wl ON wl.tgid = p.tgid
                                    WHERE e.op = 'EXECUTE'""").fetchall())
    exec_paths = {os.path.realpath(p) for _, p in f.execs} | {p for _, p in f.execs}
    extra_o = sorted(have_open - f.opens - f.opath, key=str)
    expected = [x for x in extra_o if x in exec_files or x[1] in exec_paths
                or "/ld-linux" in (x[1] or "") or "/ld-musl" in (x[1] or "")]
    other = [x for x in extra_o if x not in set(expected)]
    out["extra"]["opens"] = {"n": len(extra_o), "exec_and_interpreter": len(expected),
                             "other": len(other), "other_first": [list(x) for x in other[:SHOW]]}

    # connects: each strace connect against the CONNECT edges' own NET records
    have_c = Counter(con.execute("""SELECT n.tgid, n.family, n.rport, n.ret FROM edge e
                                    JOIN raw_net n ON n.ring = e.ring AND n.seq = e.seq
                                    JOIN wl ON wl.tgid = n.tgid WHERE e.op = 'CONNECT'""").fetchall())
    want_c = Counter((t, FAM[fam], port, ret_of(res)) for t, fam, port, res in f.connects)
    miss_c = want_c - have_c
    out["recall"]["connects"] = {"oracle": sum(want_c.values()), "found": sum(want_c.values()) - sum(miss_c.values()),
                                 "ratio": round(1 - sum(miss_c.values()) / sum(want_c.values()), 6) if want_c else None,
                                 "missed": [list(k) + [v] for k, v in list(miss_c.items())[:SHOW]],
                                 "missed_total": sum(miss_c.values()), "note": "tgid, family, port, ret"}
    have_a = Counter(dict(con.execute("""SELECT p.tgid, count(*) FROM edge e JOIN proc p ON p.node_id = e.dst
                                         JOIN wl USING (tgid) WHERE e.op = 'ACCEPT' AND e.ok GROUP BY 1""").fetchall()))
    miss_a = f.accepts - have_a
    out["recall"]["accepts"] = {"oracle": sum(f.accepts.values()), "found": sum(f.accepts.values()) - sum(miss_a.values()),
                                "ratio": round(1 - sum(miss_a.values()) / sum(f.accepts.values()), 6) if f.accepts else None,
                                "missed": [[k, v] for k, v in list(miss_a.items())[:SHOW]],
                                "missed_total": sum(miss_a.values()), "note": "tgid, count"}

    # bytes, per process
    if f.full:
        g = defaultdict(Counter)
        for t, op, b in con.execute("""SELECT p.tgid, e.op, sum(e.bytes) FROM edge e
                                       JOIN proc p ON p.node_id = CASE WHEN e.op IN ('READ', 'RECV') THEN e.dst ELSE e.src END
                                       JOIN wl ON wl.tgid = p.tgid
                                       WHERE e.op IN ('READ', 'WRITE', 'RECV', 'SEND') GROUP BY 1, 2""").fetchall():
            g[t][{"READ": "file_read", "WRITE": "file_write", "RECV": "sock_recv", "SEND": "sock_send"}[op]] = int(b)
        for k in ("file_read", "file_write", "sock_recv", "sock_send"):
            want = sum(f.bytes[t][k] for t in T)
            have = sum(g[t][k] for t in T)
            off = sorted(((t, f.bytes[t][k], g[t][k]) for t in T if f.bytes[t][k] != g[t][k]),
                         key=lambda x: -abs(x[1] - x[2]))
            out["bytes"][k] = {"oracle": want, "graph": have, "exact_processes": len(T) - len(off),
                               "processes": len(T), "ratio": round(have / want, 6) if want else None,
                               "differ": [list(x) for x in off[:SHOW]]}

    if manifest:
        out["attack"] = attack(con, manifest, set(T))
    return out


def nodes_of(con: duckdb.DuckDBPyConnection, spec: dict, T: set) -> list[tuple[int, int]]:
    """(node_id, first moment) of the nodes a manifest end names: {"path": P} a file opened by that
    path (the node's own path, or one of its opens'), {"listener_port": N} the process that listened
    on port N, {"exe": NAME} a workload process that ran a program of that last component."""
    if "path" in spec:
        return con.execute("""SELECT node_id, min(first_ns) FROM (
                                  SELECT node_id, first_ns FROM file WHERE path = ?
                                  UNION ALL SELECT file_node, first_ns FROM openfile WHERE path = ?)
                              GROUP BY node_id""", [spec["path"], spec["path"]]).fetchall()
    if "listener_port" in spec:
        rows = con.execute("""SELECT e.src, min(e.ts_ns) FROM edge e JOIN sock s ON s.node_id = e.dst
                              WHERE e.op = 'LISTEN' AND e.ok AND s.lport = ? GROUP BY e.src""",
                           [spec["listener_port"]]).fetchall()
    else:
        rows = con.execute("""SELECT DISTINCT p.node_id, coalesce(p.fork_ns, p.start_ns) FROM proc p
                              JOIN proc_image i USING (node_id)
                              WHERE i.seen_in = 'exec' AND regexp_extract(i.filename, '[^/]*$') = ?""",
                           [spec["exe"]]).fetchall()
        rows = [r for r in rows if con.execute("SELECT tgid FROM proc WHERE node_id = ?", [r[0]]).fetchone()[0] in T]
    return rows


def attack(con: duckdb.DuckDBPyConnection, m: dict, T: set) -> dict:
    res: dict = {"reach": [], "rules": {}, "refused": {}, "comm": {}}
    alerts = RL.run(con)
    fired = Counter(a.rule for a in alerts)
    res["alerts"] = [{"rule": a.rule, "key": a.key, "detail": a.detail} for a in alerts][:SHOW]
    for r in m.get("rules", []):
        res["rules"][r] = fired.get(r, 0) > 0
    res["rules_fired"] = dict(fired)
    for c in m.get("reach", []):
        src = nodes_of(con, c["from"], T)
        dst = {n for n, _ in nodes_of(con, c["to"], T)}
        reached = any(any(x in dst for x in TR.forward(con, n, int(t or 0))) for n, t in src)
        item = {"name": c["name"], "from_nodes": len(src), "to_nodes": len(dst), "reached": reached,
                "expect": c.get("expect", True)}
        if "bytes" in c and "listener_port" in c["to"]:
            got = con.execute("""SELECT coalesce(sum(e.bytes), 0) FROM edge e JOIN sock s ON s.node_id = e.src
                                 WHERE e.op = 'RECV' AND s.lport = ? AND e.dst IN (SELECT unnest(?::BIGINT[]))""",
                              [c["to"]["listener_port"], sorted(dst)]).fetchone()[0]
            item.update(bytes_want=c["bytes"], bytes_got=int(got), bytes_ok=int(got) == c["bytes"])
        res["reach"].append(item)
    for port in m.get("refused", []):
        n = con.execute("""SELECT count(*) FROM edge e JOIN raw_net n ON n.ring = e.ring AND n.seq = e.seq
                           WHERE e.op = 'CONNECT' AND NOT e.ok AND n.rport = ?""", [port]).fetchone()[0]
        res["refused"][str(port)] = n > 0
    for name in m.get("comm", []):
        n = con.execute("SELECT count(*) FROM raw_rename WHERE p15_comm(new_comm) = ?", [name]).fetchone()[0]
        res["comm"][name] = n > 0
    return res


def has_fn(con, name: str) -> bool:
    try:
        return bool(con.execute("SELECT count(*) FROM duckdb_functions() WHERE function_name = ?", [name]).fetchone()[0])
    except duckdb.Error:
        return False


def verdict(r: dict) -> tuple[list[str], list[str]]:
    """(capture and graph checks that did not hold, detection rules that did not fire), one line each."""
    bad, gaps = [], []
    for k, v in r["recall"].items():
        if v["oracle"] and v["missed_total"]:
            bad.append(f"recall {k}: {v['found']} of {v['oracle']} (first missed: {v['missed'][:3]})")
    if r["extra"].get("processes", {}).get("n"):
        bad.append(f"extra processes under the root: {r['extra']['processes']['first'][:5]}")
    for k, v in r["bytes"].items():
        if v["oracle"] != v["graph"]:
            bad.append(f"bytes {k}: graph {v['graph']} vs strace {v['oracle']} (first: {v['differ'][:3]})")
    a = r.get("attack")
    if a:
        for c in a["reach"]:
            if c["reached"] != c["expect"]:
                bad.append(f"attack reach '{c['name']}': reached {c['reached']}, expected {c['expect']} "
                           f"(from {c['from_nodes']} node(s), to {c['to_nodes']})")
            if not c.get("bytes_ok", True):
                bad.append(f"attack bytes '{c['name']}': {c['bytes_got']} received, {c['bytes_want']} sent")
        miss = [k for k, ok in a["refused"].items() if not ok]
        if miss:
            bad.append(f"attack refused connects not in the graph: {len(miss)} of {len(a['refused'])} (first {miss[:3]})")
        bad += [f"attack rename to {k} not in the graph" for k, ok in a["comm"].items() if not ok]
        gaps += [f"rule {k} did not fire" for k, ok in a["rules"].items() if not ok]
    return bad, gaps


def text(r: dict) -> str:
    L = [f"p15d exit {r['p15d_rc']}; strace root pid {r['root']}"]
    for k, v in r["recall"].items():
        ratio = "-" if v["ratio"] is None else f"{100 * v['ratio']:.2f} %"
        L.append(f"  {k:<12} {v['found']:>7} of {v['oracle']:<7} {ratio:>9}  {v['note']}")
    for k, v in r["bytes"].items():
        ratio = "-" if v["ratio"] is None else f"{100 * v['ratio']:.4f} %"
        L.append(f"  bytes {k:<11} graph {v['graph']:>12} strace {v['oracle']:>12} {ratio:>11}  "
                 f"exact in {v['exact_processes']} of {v['processes']} processes")
    e = r["extra"]
    L.append(f"  extra: processes {e['processes']['n']}; opens {e['opens']['n']} "
             f"({e['opens']['exec_and_interpreter']} an exec's program or interpreter, {e['opens']['other']} other)")
    if r["unseen"]:
        L.append("  calls the flow programs do not hook (by design): "
                 + ", ".join(f"{k} {v['calls']} ({v['bytes']} B)" for k, v in r["unseen"].items()))
    L.append(f"  not compared: AF_UNIX connects {r['unix_connects']}, O_PATH opens {r['opath_opens']}, "
             f"oracle lines: " + ", ".join(f"{k} {v}" for k, v in sorted(r["oracle_counts"].items()) if v))
    a = r.get("attack")
    if a:
        for c in a["reach"]:
            b = f", bytes {c['bytes_got']} of {c['bytes_want']}" if "bytes_want" in c else ""
            L.append(f"  attack '{c['name']}': reached {c['reached']} (expected {c['expect']}){b}")
        L.append("  attack rules: " + ", ".join(f"{k} {'fired' if ok else 'NOT fired'}" for k, ok in a["rules"].items())
                 + f"; all fired: {a['rules_fired']}")
        if a["refused"]:
            L.append("  attack refused connects seen: " + ", ".join(f"{k} {ok}" for k, ok in a["refused"].items()))
        if a["comm"]:
            L.append("  attack renames seen: " + ", ".join(f"{k} {ok}" for k, ok in a["comm"].items()))
    bad, gaps = verdict(r)
    L.append("VERDICT: " + ("capture and graph checks hold" if not bad else f"{len(bad)} capture or graph check(s) do not hold")
             + ("" if not a else "; detection: " + ("every expected rule fired" if not gaps else "; ".join(gaps))))
    L += [f"  - {b}" for b in bad]
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="compare.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("graph", type=Path)
    ap.add_argument("strace", type=Path)
    ap.add_argument("--light", action="store_true", help="strace traced processes, opens and connects only")
    ap.add_argument("--manifest", type=Path)
    ap.add_argument("--p15d-rc", type=int)
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    try:
        f = O.load(a.strace, a.light)
        m = json.loads(a.manifest.read_text()) if a.manifest else None
        con = duckdb.connect(str(a.graph), read_only=True)
    except (OSError, ValueError, duckdb.Error) as e:
        print(f"compare.py: {e}", file=sys.stderr)
        return 2
    con.create_function("p15_comm", lambda b: R.comm(bytes(b)), ["BLOB"], "VARCHAR")   # as graph/build.py does
    r = compare(con, f, m, a.p15d_rc)
    r["verdict"], r["detection_gaps"] = verdict(r)
    if a.json:
        a.json.write_text(json.dumps(r, indent=1, default=str))
    print(text(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
