# SPDX-License-Identifier: MIT
"""The attack path around one node, readable: what led to it and what it led to.

    python3 -m p15.graph.story GRAPH.duckdb [NODE | --alert RULE] [--window S] [--html OUT.html]
                               [--json STORY.json] [--viewer STORY.html]

NODE is a node_id or key (`p:TGID:START_NS`). With `--alert R4` (or R1, R2, R3) an alert of that rule
(p15.graph.rules) is the start, or any alert if that rule did not fire; with neither, an R4 alert, else any. When several alerts of the
rule fired, the start is the one whose own process subtree holds the most other alerts (then whose
forward walk reaches the most alerts, then the most nodes). A web server that shells out for every
request fires R4 for each request; the one an attacker used is the one whose children did
something. The subtree, not the forward walk alone, decides: a harmless shell's output flows back
into the server, and from there forward to everything the server did later, the attack included.

How it is made (p15.graph.track does the walking):
  1. why: from the node, the most recent cause of each step, back until --window seconds before the
     node's first moment (why_chain). A web server that read many requests is explained by the one
     it read just before it started the shell, not by all of them;
  2. what it led to: the forward walk from the node at its first moment. Kept: every process and
     socket it reaches and the files that carry the story (executed, or written). Files only read
     on the way, such as shared libraries, the loader cache, locale and name-service files, are
     counted and left out; so is every earlier influence the full backward walk finds off the chain;
  3. the program each kept process ran;
  4. the edges between kept nodes from the node's first moment on, in time order, repeated transfers
     on one pair joined into one line with their count and bytes (an exec's OPEN of its own program
     left out beside its EXECUTE); and the TCP pairings between kept sockets.
Every alert of p15.graph.rules on a kept node is shown with the path.

--json writes the same path as a story document (p15.graph.viewer's format, doc() here), and
--viewer writes it as the storybook page that plays it edge by edge (p15.graph.viewer).

Nothing here decides what is malicious: it is the graph's own walk, trimmed for reading. The walk's
full result is p15.graph.track's.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path

import duckdb

from . import rules as RL
from . import track as T
from . import viewer as V
from .viewer import short

NOISE = re.compile(r"\.so(\.[0-9]+)*$|^/usr/lib/|^/lib(64)?/|^/etc/ld\.so|locale|^/usr/share/|^/proc/|^/sys/"
                   r"|^/dev/(null|zero|tty|urandom|random|pts/)|^/etc/(nsswitch\.conf|services|passwd|group|hosts"
                   r"|host\.conf|resolv\.conf|gai\.conf|localtime|ssl/|gnutls/|login\.defs|bash\.bashrc|profile)"
                   r"|^/usr/lib/python|__pycache__|\.pyc$")


SUBTREE = """
WITH RECURSIVE d(node) AS (
    SELECT ?::BIGINT
    UNION
    SELECT p.node_id FROM proc p JOIN d ON p.parent_node = d.node
)
SELECT node FROM d
"""


def pick_start(con: duckdb.DuckDBPyConnection, spec: str | None, alert: str | None) -> tuple[int, list[RL.Alert]]:
    alerts = RL.run(con)
    if spec:
        return T.resolve(con, spec), alerts
    pool = [a for a in alerts if a.rule == (alert or "R4")] or alerts
    if not pool:
        raise ValueError("no alert to start from: name a node, or use --alert with a rule that fired")
    if len(pool) == 1:
        return pool[0].node, alerts
    lo = T.span(con)[0] or 1
    alert_nodes = {a.node for a in alerts}
    best, score = pool[0].node, (-1, -1, -1)
    for a in pool[:50]:
        sub = {r[0] for r in con.execute(SUBTREE, [a.node]).fetchall()}
        got = T.forward(con, a.node, max(lo - 1, 0))
        sc = (len(alert_nodes & sub), len(alert_nodes & set(got)), len(got))
        if sc > score:
            best, score = a.node, sc
    return best, alerts


def why_chain(con: duckdb.DuckDBPyConnection, start: int, cut: int, carrying: set, paths: dict, kinds: dict) -> list:
    """Why `start` exists: from it, step back along the most recent cause, one at a time, until an
    input earlier than `cut` or none. A cause is an input that carries information: a CLONE from the
    parent, an ACCEPT, RECV or SEND on a socket, a READ or WRITE of a pipe or of a file some process
    wrote, an EXECUTE of such a file, and a TCP pairing (a relation: it keeps the time). Opens, and
    reads of files nobody wrote (libraries, configuration), are not causes here. Each step is
    (ts_ns or None, src, dst, op); the first step's dst is `start`."""
    first = con.execute("SELECT first_ns FROM node WHERE node_id = ?", [start]).fetchone()[0] or 0
    node, t, seen, out = start, int(first) + 1, {start}, []
    while len(out) < 40:
        if kinds.get(node) == "sock":
            pr = con.execute("SELECT client_node FROM sock_pair WHERE server_node = ?", [node]).fetchone()
            if pr and pr[0] not in seen:
                out.append((None, pr[0], node, "TCP"))
                node = pr[0]
                seen.add(node)
                continue
        rows = con.execute("""
            SELECT ts_ns, src, op FROM edge
            WHERE dst = ? AND ok AND ts_ns < ? AND ts_ns >= ? AND op IN ('CLONE', 'ACCEPT', 'RECV', 'SEND', 'READ',
                  'WRITE', 'EXECUTE', 'CONNECT')
            ORDER BY ts_ns DESC, edge_id DESC LIMIT 50""", [node, t, cut]).fetchall()
        step = None
        for ts, src, op in rows:
            if src in seen:
                continue
            if kinds.get(src) == "file":
                p = paths.get(src) or ""
                if op == "EXECUTE" and src not in carrying:
                    continue
                if op == "READ" and (src not in carrying or NOISE.search(p)):
                    continue
            step = (int(ts), src, node, op)
            break
        if step is None:
            break
        out.append(step)
        node, t = step[1], step[0]
        seen.add(node)
    return out


def build(con: duckdb.DuckDBPyConnection, start: int, window_s: float) -> dict:
    T.prepare(con)
    lo, hi = T.span(con)
    first = con.execute("SELECT first_ns FROM node WHERE node_id = ?", [start]).fetchone()[0] or lo or 0
    back = T.backward(con, start, (hi or 0) + 1)
    fwd = T.forward(con, start, max(int(first) - 1, 0))
    cut = int(first) - int(window_s * 1e9)
    kinds = dict(con.execute("SELECT node_id, kind FROM node").fetchall())
    carrying = {r[0] for r in con.execute(
        "SELECT src FROM edge WHERE op = 'EXECUTE' AND ok UNION SELECT dst FROM edge WHERE op = 'WRITE' AND ok "
        "UNION SELECT src FROM edge WHERE op = 'OPEN' AND ok AND access IN ('w', 'rw')").fetchall()}
    written = {r[0] for r in con.execute("SELECT dst FROM edge WHERE op = 'WRITE' AND ok "
                                         "UNION SELECT src FROM edge WHERE op = 'OPEN' AND ok AND access IN ('w', 'rw')").fetchall()}
    paths = dict(con.execute("SELECT node_id, coalesce(path, name, key) FROM file").fetchall())
    why = why_chain(con, start, cut, written, paths, kinds)
    on_chain = {start} | {st[1] for st in why}
    kept, noise = set(on_chain), set()
    for n in fwd:
        if kinds[n] == "file" and (n not in carrying or NOISE.search(paths.get(n) or "")):
            noise.add(n)
            continue
        kept.add(n)
    # the program each kept process ran: upstream of it, so a forward walk never reaches it. Only a
    # run inside the story (from the start's first moment): an earlier one is not among the edges
    # shown, so its program would be counted as shown and never appear
    for src, _dst in con.execute("SELECT src, dst FROM edge WHERE op = 'EXECUTE' AND ok AND ts_ns >= ? "
                                 "AND dst IN (SELECT unnest(?::BIGINT[]))", [int(first), sorted(kept)]).fetchall():
        kept.add(src)
        noise.discard(src)
    reached = set(back) | set(fwd) | kept   # programs of kept processes are added, not walked to
    hidden_off_chain = len([n for n in back if n not in kept and n not in fwd])
    labels = T.describe(con, sorted(kept))
    # a file with no path (a pipe, a socket file, an anonymous file) is named by its kind
    for n, kind, name, key in con.execute("SELECT node_id, kind, name, key FROM file WHERE path IS NULL AND node_id IN "
                                          "(SELECT unnest(?::BIGINT[]))", [sorted(kept)]).fetchall():
        labels[n] = f"file ({kind or 'no path'}) {name or key}"
    # what each exec was called as: a multi-call binary (Ubuntu 26.04's coreutils is one) runs as
    # chmod or id but is one file, which the graph names by one of its paths
    exec_as = {(n, int(ts)): fn for n, ts, fn in con.execute(
        "SELECT node_id, ts_ns, filename FROM proc_image WHERE seen_in = 'exec' AND filename IS NOT NULL AND node_id IN "
        "(SELECT unnest(?::BIGINT[]))", [sorted(kept)]).fetchall()}
    # what it led to: the edges between kept nodes from the start's first moment on
    edges = con.execute("""
        SELECT min(ts_ns), max(coalesce(end_ns, ts_ns)), src, dst, op, count(*), sum(coalesce(bytes, 0))
        FROM edge WHERE ok AND ts_ns >= ? AND src IN (SELECT unnest(?::BIGINT[])) AND dst IN (SELECT unnest(?::BIGINT[]))
        GROUP BY src, dst, op ORDER BY 1, 3, 4""", [int(first), sorted(kept), sorted(kept)]).fetchall()
    # an exec opens its program: that OPEN says nothing the EXECUTE beside it does not
    execs = {(e[2], e[3]) for e in edges if e[4] == "EXECUTE"}
    edges = [e for e in edges if not (e[4] == "OPEN" and (e[2], e[3]) in execs)]
    pairs = con.execute("SELECT client_node, server_node FROM sock_pair WHERE client_node IN (SELECT unnest(?::BIGINT[])) "
                        "AND server_node IN (SELECT unnest(?::BIGINT[]))", [sorted(kept), sorted(kept)]).fetchall()
    # the ancestors beyond the chain, as one line: the parent chain of its earliest process
    procs = [n for n in on_chain if kinds[n] == "proc"]
    chain = []
    if procs:
        top = min(procs, key=lambda n: con.execute("SELECT start_ns FROM proc WHERE node_id = ?", [n]).fetchone()[0])
        cur = con.execute("SELECT parent_node FROM proc WHERE node_id = ?", [top]).fetchone()[0]
        while cur is not None and len(chain) < 8:
            r = con.execute("SELECT parent_node, tgid, comm FROM proc WHERE node_id = ?", [cur]).fetchone()
            if r is None:
                break
            chain.append(f"{r[2] or '?'}({r[1]})")
            cur = r[0]
    return {"start": start, "t0": int(first), "kept": kept, "labels": labels, "why": why, "edges": edges, "pairs": pairs,
            "exec_as": exec_as,
            "hidden_noise": len(noise), "hidden_old": hidden_off_chain, "reached": len(reached), "ancestors": chain}


def called_as(s: dict, op: str, src: int, dst: int, ts: int) -> str:
    """For an EXECUTE whose file is named differently from what the exec was called with: 'as NAME'."""
    if op != "EXECUTE":
        return ""
    fn = s.get("exec_as", {}).get((dst, int(ts)))
    label = s["labels"].get(src, "")
    if not fn or fn.rsplit("/", 1)[-1] == label.rsplit("/", 1)[-1] or fn.startswith("/proc/self/fd/"):
        return ""
    return f"as {fn}"


def text(s: dict, alerts: list[RL.Alert]) -> str:
    L = []
    t0, lab = s["t0"], s["labels"]
    L.append(f"attack path around {lab.get(s['start'], s['start'])}")
    L.append(f"  {len(s['kept'])} nodes shown of {s['reached']} reached: {s['hidden_noise']} files only read on the way "
             f"(libraries, configuration) and {s['hidden_old']} earlier influences off the cause chain left out")
    if s["ancestors"]:
        L.append("  started under: " + " <- ".join(s["ancestors"]))
    mine = [a for a in alerts if a.node in s["kept"]]
    if mine:
        L.append("")
        L.append("alerts on this path:")
        for a in mine:
            L.append(f"  {(a.ts_ns - t0) / 1e9:+8.3f}s  {a.rule} {a.name:<12} {a.detail}")
    L.append("")
    L.append("why it happened: the most recent cause of each step, newest first:")
    L.append(f"  {'':>9}  {short(lab.get(s['start'], str(s['start'])))}")
    for ts, src, _dst, op in s["why"]:
        when = f"{(ts - t0) / 1e9:+8.3f}s" if ts is not None else f"{'':>9}"
        L.append(f"  {when}    <-{op}-- {short(lab.get(src, str(src)))}")
    L.append("")
    L.append("what it led to, in order (time from the start node's first moment):")
    for ts, _end, src, dst, op, n, b in s["edges"]:
        extra = f"  x{n}" if n > 1 else ""
        extra += f"  {b} bytes" if b else ""
        extra += f"  ({called_as(s, op, src, dst, ts)})" if called_as(s, op, src, dst, ts) else ""
        L.append(f"  {(ts - t0) / 1e9:+8.3f}s  {short(lab.get(src, str(src)))}  --{op}-->  {short(lab.get(dst, str(dst)))}{extra}")
    for c, sv in s["pairs"]:
        L.append(f"  {'':>9}  {short(lab.get(c, str(c)))}  ==TCP==  {short(lab.get(sv, str(sv)))}  (one connection, joined by sequence number)")
    L.append("")
    L.append("the processes, in full:")
    for n in sorted(s["kept"]):
        if lab.get(n, "").startswith("proc "):
            L.append(f"  {lab[n]}")
    return "\n".join(L)


CSS = """body{font-family:system-ui,sans-serif;margin:2rem;max-width:72rem;color:#1d2330}
h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.6rem}.muted{color:#667}
table{border-collapse:collapse;width:100%}td,th{padding:.3rem .5rem;border-bottom:1px solid #e3e6ec;text-align:left;
vertical-align:top;font-size:.92rem}th{background:#f4f6fa}.t{font-variant-numeric:tabular-nums;white-space:nowrap;color:#556}
.chip{display:inline-block;padding:.05rem .45rem;border-radius:.6rem;font-size:.85rem;white-space:nowrap}
.proc{background:#e6efff}.file{background:#fff2d9}.sock{background:#e3f6ec}.op{font-weight:600;color:#334;font-size:.8rem}
.alert{background:#fdecec;border-left:4px solid #c62828;padding:.4rem .7rem;margin:.3rem 0}
code{font-size:.85rem;word-break:break-all}"""


def chip(label: str) -> str:
    kind = label.split(" ", 1)[0] if label else "?"
    return f'<span class="chip {html.escape(kind)}">{html.escape(short(label))}</span>'


def page(s: dict, alerts: list[RL.Alert], title: str) -> str:
    t0, lab = s["t0"], s["labels"]
    H = [f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title><style>{CSS}</style></head><body>",
         f"<h1>{html.escape(title)}</h1>",
         f"<p class='muted'>Start: {chip(lab.get(s['start'], '?'))}. {len(s['kept'])} nodes shown of {s['reached']} the "
         f"walks reached; {s['hidden_noise']} files only read on the way and {s['hidden_old']} earlier influences off the cause chain left out."
         + (f" Started under: {html.escape(' ← '.join(s['ancestors']))}." if s["ancestors"] else "") + "</p>"]
    mine = [a for a in alerts if a.node in s["kept"]]
    H.append(f"<h2>Alerts on this path ({len(mine)})</h2>")
    for a in mine:
        H.append(f"<div class='alert'><b>{a.rule} {html.escape(a.name)}</b> <span class='t'>{(a.ts_ns - t0) / 1e9:+.3f} s</span>"
                 f"<br>{html.escape(a.detail)}</div>")
    H.append("<h2>Why it happened</h2><p class='muted'>From the start, the most recent cause of each step, "
             "newest first.</p><table><tr><th>time</th><th>caused by</th><th>how</th><th>this</th></tr>")
    for ts, src, dst, op in s["why"]:
        when = f"{(ts - t0) / 1e9:+.3f} s" if ts is not None else ""
        H.append(f"<tr><td class='t'>{when}</td><td>{chip(lab.get(src, '?'))}</td><td class='op'>{html.escape(op)}</td>"
                 f"<td>{chip(lab.get(dst, '?'))}</td></tr>")
    H.append("</table>")
    H.append("<h2>What it led to, in order</h2><table><tr><th>time</th><th>from</th><th>what</th><th>to</th><th></th></tr>")
    for ts, _end, src, dst, op, n, b in s["edges"]:
        extra = (f"×{n}" if n > 1 else "") + (f" {b} B" if b else "") + (" " + called_as(s, op, src, dst, ts))
        H.append(f"<tr><td class='t'>{(ts - t0) / 1e9:+.3f} s</td><td>{chip(lab.get(src, '?'))}</td>"
                 f"<td class='op'>{html.escape(op)}</td><td>{chip(lab.get(dst, '?'))}</td><td class='t'>{html.escape(extra)}</td></tr>")
    for c, sv in s["pairs"]:
        H.append(f"<tr><td></td><td>{chip(lab.get(c, '?'))}</td><td class='op'>TCP</td><td>{chip(lab.get(sv, '?'))}</td>"
                 f"<td class='t'>one connection</td></tr>")
    H.append("</table><h2>The processes</h2><table>")
    for n in sorted(s["kept"]):
        if lab.get(n, "").startswith("proc "):
            H.append(f"<tr><td><code>{html.escape(lab[n])}</code></td></tr>")
    H.append("</table><p class='muted'>Made by p15.graph.story from the capture's graph: the walks are "
             "BackTracker's rule over time-stamped edges (p15.graph.track); alerts are p15.graph.rules.</p></body></html>")
    return "\n".join(H)


def doc(s: dict, alerts: list[RL.Alert], graph: str | None = None) -> dict:
    """The path as a story document (p15.graph.viewer.SCHEMA): the same nodes, cause chain, edges,
    pairings and alerts as text() prints, times in seconds from the start's first moment. Every alert
    of the run is listed; those on a kept node are on the path."""
    t0, lab = s["t0"], s["labels"]

    def sec(ts):
        return None if ts is None else (int(ts) - t0) / 1e9

    out = {
        "schema": V.SCHEMA, "start": str(s["start"]),
        "counts": {"shown": len(s["kept"]), "reached": s["reached"], "hidden_noise": s["hidden_noise"],
                   "hidden_old": s["hidden_old"]},
        "ancestors": list(s["ancestors"]),
        "nodes": [V.node(str(n), lab[n]) for n in sorted(s["kept"])],
        "why": [{"t": sec(ts), "src": str(src), "dst": str(dst), "op": op} for ts, src, dst, op in s["why"]],
        "edges": [{"t": sec(ts), "t_end": sec(end), "src": str(src), "dst": str(dst), "op": op, "count": int(n),
                   "bytes": int(b or 0), "called_as": called_as(s, op, src, dst, ts) or None}
                  for ts, end, src, dst, op, n, b in s["edges"]],
        "pairs": [{"client": str(c), "server": str(sv)} for c, sv in s["pairs"]],
        "alerts": [{"rule": a.rule, "name": a.name, "t": sec(a.ts_ns), "detail": a.detail,
                    "node": str(a.node) if a.node in s["kept"] else None, "on_path": a.node in s["kept"],
                    "key": a.key} for a in alerts],
        "source": {"kind": "graph", "graph": graph},
    }
    return V.validate(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="p15.graph.story", description=__doc__.split("\n\n")[0])
    ap.add_argument("graph", type=Path)
    ap.add_argument("node", nargs="?")
    ap.add_argument("--alert", choices=sorted(RL.RULES), help="start from an alert of this rule (any alert if it did not fire)")
    ap.add_argument("--window", type=float, default=10.0, help="how far back the cause chain goes, in seconds (default 10)")
    ap.add_argument("--html", type=Path, help="also write the path as one HTML page")
    ap.add_argument("--json", type=Path, help="also write the path as a story document (p15.graph.viewer)")
    ap.add_argument("--viewer", type=Path, help="also write the storybook page that plays the path")
    a = ap.parse_args(argv)
    if not a.graph.exists():
        print(f"p15.graph.story: {a.graph}: no such file", file=sys.stderr)
        return 2
    con = duckdb.connect(str(a.graph), read_only=True)
    try:
        try:
            start, alerts = pick_start(con, a.node, a.alert)
        except ValueError as e:
            print(f"p15.graph.story: {e}", file=sys.stderr)
            return 1
        s = build(con, start, a.window)
    finally:
        con.close()
    print(text(s, alerts))
    if a.html:
        a.html.write_text(page(s, alerts, "Attack path: " + short(s["labels"].get(start, str(start)))))
        print(f"\nHTML: {a.html}")
    if a.json or a.viewer:
        d = doc(s, alerts, a.graph.name)
        if a.json:
            a.json.write_text(json.dumps(d, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"story: {a.json}")
        if a.viewer:
            a.viewer.write_text(V.render(d), encoding="utf-8")
            print(f"storybook: {a.viewer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
