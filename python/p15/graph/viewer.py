# SPDX-License-Identifier: MIT
"""The attack path as a story to step through: one self-contained HTML page (the storybook).

    python3 -m p15.graph.viewer STORY.json -o PAGE.html
    python3 -m p15.graph.viewer --from-text attack-path.txt [--rules rules.txt] [--manifest manifest.txt]
                                [--title T] -o PAGE.html [--json STORY.json]

The page shows the graph of p15.graph.story growing one edge at a time, in chapters: how the start
was reached (the cause chain), then one chapter per command the start process ran (a child it
forked; children forked within 2 ms of each other, such as the two ends of a pipe, share one), then
what happened afterwards. Alerts are flagged on the timeline at the edge that fired them. Clicking
a node lists all its edges. The page needs no network.

Two ways in, one format (SCHEMA, checked by validate):
  1. STORY.json, written by `python3 -m p15.graph.story GRAPH.duckdb --json STORY.json` from a live
     graph (story.doc);
  2. --from-text, which reads the text report story.py printed (attack-path.txt) back into the same
     format. That is how a recorded run whose graph was not kept, such as the VM evidence of
     2026-11-14, is shown. The parser is strict: a line it does not recognise is an error with its
     line number, never skipped. Times in the text have millisecond precision, and so do the page's.

Nothing here decides anything: every node, edge, time and alert on the page is one story.py
produced. The page only lays it out and plays it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA = "p15.story/1"
KINDS = ("proc", "file", "sock")
TEMPLATE = Path(__file__).with_name("viewer.html")
SLOT = "__P15_STORY_JSON__"


class StoryError(ValueError):
    """A story document or report that does not hold what the format says."""


def short(label: str) -> str:
    """A label without the long command line: 'proc 123 nc', 'file /tmp/x', 'sock a -> b'. A process
    whose argv[0] differs from its comm (a program run from /proc/self/fd/3 has comm '3') gets it
    in brackets: 'proc 422 3 [kworker]'."""
    if label.startswith("proc "):
        head, _, cmd = label.partition(" (")
        argv0 = cmd[:-1].split(" ", 1)[0].rsplit("/", 1)[-1] if cmd else ""
        comm = head.split(" ", 2)[2] if head.count(" ") >= 2 else ""
        return head + (f" [{argv0}]" if argv0 and argv0 != comm else "")
    return label


def kind_of(label: str) -> str:
    k = label.split(" ", 1)[0]
    if k not in KINDS:
        raise StoryError(f"node label {label!r}: kind {k!r} is none of {', '.join(KINDS)}")
    return k


def node(nid: str, label: str) -> dict:
    """One node: its id, kind, the full label, the short one, and a process's command line."""
    cmd = None
    if label.startswith("proc ") and " (" in label and label.endswith(")"):
        cmd = label.partition(" (")[2][:-1]
    return {"id": nid, "kind": kind_of(label), "label": label, "short": short(label), "cmd": cmd}


def validate(doc: dict) -> dict:
    """Check a story document against SCHEMA; raise StoryError naming the first thing wrong."""
    if doc.get("schema") != SCHEMA:
        raise StoryError(f"schema is {doc.get('schema')!r}, not {SCHEMA!r}")
    for k in ("start", "counts", "ancestors", "nodes", "why", "edges", "pairs", "alerts", "source"):
        if k not in doc:
            raise StoryError(f"missing {k!r}")
    ids = set()
    for n in doc["nodes"]:
        if n["id"] in ids:
            raise StoryError(f"node {n['id']!r} twice")
        if n["kind"] not in KINDS:
            raise StoryError(f"node {n['id']!r}: kind {n['kind']!r}")
        ids.add(n["id"])
    if doc["start"] not in ids:
        raise StoryError(f"start {doc['start']!r} is not a node")
    for where in ("why", "edges"):
        for i, e in enumerate(doc[where]):
            for end in ("src", "dst"):
                if e[end] not in ids:
                    raise StoryError(f"{where}[{i}].{end} {e[end]!r} is not a node")
            if not re.fullmatch(r"[A-Z]+", e["op"]):
                raise StoryError(f"{where}[{i}].op {e['op']!r}")
    times = [e["t"] for e in doc["edges"]]
    if times != sorted(times):
        raise StoryError("edges are not in time order")
    for i, p in enumerate(doc["pairs"]):
        if p["client"] not in ids or p["server"] not in ids:
            raise StoryError(f"pairs[{i}] names a node that is not in nodes")
    for i, a in enumerate(doc["alerts"]):
        if a["on_path"] and a["node"] not in ids:
            raise StoryError(f"alerts[{i}] is on the path but its node {a['node']!r} is not")
    for k in ("shown", "reached", "hidden_noise", "hidden_old"):
        if not isinstance(doc["counts"].get(k), int):
            raise StoryError(f"counts.{k} is not an integer")
    if doc["counts"]["shown"] != len(doc["nodes"]):
        raise StoryError(f"counts.shown {doc['counts']['shown']} but {len(doc['nodes'])} nodes")
    return doc


# --- the text report of p15.graph.story, read back -------------------------------------------------

HEAD = re.compile(r"attack path around (.+)")
COUNTS = re.compile(r"  (\d+) nodes shown of (\d+) reached: (\d+) files only read on the way "
                    r"\(libraries, configuration\) and (\d+) earlier influences off the cause chain left out")
ALERT = re.compile(r"  ( *[+-]\d+\.\d{3})s  (R\d) (\S+) +(.+)")
WHY = re.compile(r"  (.{9})    <-([A-Z]+)-- (.+)")
EDGE = re.compile(r"  ( *[+-]\d+\.\d{3})s  (.+?)  --([A-Z]+)-->  (.+)")
PAIR = re.compile(r" {13}(.+?)  ==TCP==  (.+?)  \(one connection, joined by sequence number\)")
RULE_LINE = re.compile(r"  \+ *(-?\d+\.\d{3})s  (R\d) (\S+) +(\S+)  (.+)")
ALERT_PID = (re.compile(r"as pid (\d+)$"), re.compile(r"^pid (\d+) ran "))


def _secs(s: str) -> float:
    return float(s.replace(" ", ""))


def from_text(text: str, rules_text: str | None = None, source: dict | None = None) -> dict:
    """The text report of p15.graph.story (its `text()`), as a story document. `rules_text` is the
    output of p15.graph.rules for the same graph: with it, alerts off the path are listed too."""
    lines = text.splitlines()
    pos = 0

    def fail(msg: str):
        raise StoryError(f"line {pos + 1}: {msg}: {lines[pos] if pos < len(lines) else '<end of report>'!r}")

    def expect(rx: re.Pattern):
        m = rx.fullmatch(lines[pos]) if pos < len(lines) else None
        if not m:
            fail(f"expected {rx.pattern[:40]!r}")
        return m

    def at() -> str | None:
        return lines[pos] if pos < len(lines) else None

    labels: dict[str, str] = {}      # short label -> the fullest label seen

    def see(lbl: str) -> str:
        lbl = lbl.strip()
        kind_of(lbl)
        labels.setdefault(lbl, lbl)
        return lbl

    m = expect(HEAD)
    start_full = m.group(1)
    start = short(start_full)
    labels[start] = start_full
    pos += 1
    c = expect(COUNTS)
    counts = {"shown": int(c.group(1)), "reached": int(c.group(2)),
              "hidden_noise": int(c.group(3)), "hidden_old": int(c.group(4))}
    pos += 1
    ancestors = []
    if pos < len(lines) and lines[pos].startswith("  started under: "):
        ancestors = lines[pos][len("  started under: "):].split(" <- ")
        pos += 1

    def blank():
        nonlocal pos
        if pos >= len(lines) or lines[pos] != "":
            fail("expected an empty line")
        pos += 1

    blank()
    path_alerts = []
    if at() == "alerts on this path:":
        pos += 1
        while pos < len(lines) and lines[pos] != "":
            a = expect(ALERT)
            path_alerts.append({"rule": a.group(2), "name": a.group(3), "t": _secs(a.group(1)),
                                "detail": a.group(4)})
            pos += 1
        blank()
    if at() != "why it happened: the most recent cause of each step, newest first:":
        fail("expected the cause chain")
    pos += 1
    if (at() or "").strip() != start:
        fail(f"the cause chain does not open with the start {start!r}")
    pos += 1
    why, prev = [], start
    while pos < len(lines) and lines[pos] != "":
        w = expect(WHY)
        when = w.group(1).strip()
        if when and not re.fullmatch(r"[+-]\d+\.\d{3}s", when):
            fail("the time of a cause")
        src = see(w.group(3))
        why.append({"t": _secs(when[:-1]) if when else None, "src": src, "dst": prev, "op": w.group(2)})
        prev = src
        pos += 1
    blank()
    if at() != "what it led to, in order (time from the start node's first moment):":
        fail("expected what it led to")
    pos += 1
    edges, pairs = [], []
    while pos < len(lines) and lines[pos] != "":
        p = PAIR.fullmatch(lines[pos])
        if p:
            pairs.append({"client": see(p.group(1)), "server": see(p.group(2))})
            pos += 1
            continue
        if pairs:
            fail("an edge after the TCP pairings")
        e = expect(EDGE)
        rest = e.group(4)
        called = count = None
        nbytes = 0
        if (m := re.search(r"  \((as .+)\)$", rest)):
            called, rest = m.group(1), rest[:m.start()]
        if (m := re.search(r"  (\d+) bytes$", rest)):
            nbytes, rest = int(m.group(1)), rest[:m.start()]
        if (m := re.search(r"  x(\d+)$", rest)):
            count, rest = int(m.group(1)), rest[:m.start()]
        if "  " in rest:
            fail("a destination label with two spaces in it")
        edges.append({"t": _secs(e.group(1)), "t_end": None, "src": see(e.group(2)), "dst": see(rest),
                      "op": e.group(3), "count": count or 1, "bytes": nbytes, "called_as": called})
        pos += 1
    blank()
    if at() != "the processes, in full:":
        fail("expected the processes")
    pos += 1
    while pos < len(lines) and lines[pos] != "":
        if not lines[pos].startswith("  proc "):
            fail("expected a process")
        full = lines[pos][2:]
        s = short(full)
        if s not in labels:
            fail(f"a process {s!r} that no edge or cause names")
        labels[s] = full
        pos += 1
    while pos < len(lines) and lines[pos] == "":
        pos += 1
    for trailer in ("HTML: ", "story: ", "storybook: "):     # story.py's own lines after the report
        if pos < len(lines) and lines[pos].startswith(trailer):
            pos += 1
    while pos < len(lines) and lines[pos] == "":
        pos += 1
    if pos < len(lines):
        fail("unexpected text after the report")

    listed = sum(1 for lbl in labels.values() if lbl.startswith("proc ") and lbl.endswith(")"))
    procs = sum(1 for k in labels if k.startswith("proc "))
    if listed != procs:      # story.py lists every process it kept: fewer means the report was cut
        raise StoryError(f"the processes, in full: {listed} listed of the {procs} the path names")
    nodes = [node(s, full) for s, full in labels.items()]
    procs_by_pid: dict[str, list[str]] = {}
    for n in nodes:
        if n["kind"] == "proc":
            procs_by_pid.setdefault(n["short"].split(" ")[1], []).append(n["id"])
    alerts = []
    for a in path_alerts:
        pid = next((m.group(1) for rx in ALERT_PID if (m := rx.search(a["detail"]))), None)
        hit = procs_by_pid.get(pid or "", [])
        if len(hit) != 1:
            raise StoryError(f"alert {a['rule']} {a['detail']!r}: names pid {pid}, which is {len(hit)} nodes on the path")
        alerts.append({**a, "node": hit[0], "on_path": True, "key": None})
    if rules_text is not None:
        on = {(a["rule"], a["detail"]) for a in path_alerts}
        matched = set()
        for i, ln in enumerate(rules_text.splitlines()):
            if i == 0:
                if not ln.startswith("rules: "):
                    raise StoryError(f"rules line 1: expected 'rules: ...': {ln!r}")
                continue
            r = RULE_LINE.fullmatch(ln)
            if not r:
                raise StoryError(f"rules line {i + 1}: not an alert line: {ln!r}")
            k = (r.group(2), r.group(5))
            if k in on:
                matched.add(k)
                continue
            alerts.append({"rule": r.group(2), "name": r.group(3), "t": None, "detail": r.group(5),
                           "node": None, "on_path": False, "key": r.group(4)})
        if matched != on:
            raise StoryError(f"alerts on the path that the rules output does not list: {sorted(on - matched)}")
    doc = {"schema": SCHEMA, "start": start, "counts": counts, "ancestors": ancestors, "nodes": nodes,
           "why": why, "edges": edges, "pairs": pairs, "alerts": alerts,
           "source": source or {"kind": "text"}}
    return validate(doc)


# --- the page --------------------------------------------------------------------------------------

def embed(doc: dict) -> str:
    """The document as JSON safe inside <script type="application/json">: no '<', '>' or '&'."""
    return (json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


def render(doc: dict, template: str | None = None) -> str:
    validate(doc)
    tpl = TEMPLATE.read_text(encoding="utf-8") if template is None else template
    if tpl.count(SLOT) != 1:
        raise StoryError(f"the template holds {tpl.count(SLOT)} data slots, not 1")
    return tpl.replace(SLOT, embed(doc))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="p15.graph.viewer", description=__doc__.split("\n\n")[0])
    ap.add_argument("story", nargs="?", type=Path, help="a story document (p15.graph.story --json)")
    ap.add_argument("--from-text", type=Path, metavar="TXT", help="the text report of p15.graph.story instead")
    ap.add_argument("--rules", type=Path, help="with --from-text: p15.graph.rules output, for alerts off the path")
    ap.add_argument("--manifest", type=Path, help="with --from-text: the run's manifest, shown with the source")
    ap.add_argument("--title", help="the page's heading (default: the start node)")
    ap.add_argument("-o", "--out", type=Path, required=True, help="the HTML page to write")
    ap.add_argument("--json", type=Path, help="with --from-text: also write the story document")
    a = ap.parse_args(argv)
    if (a.story is None) == (a.from_text is None):
        ap.error("give either STORY.json or --from-text TXT")
    for p in (a.story, a.from_text, a.rules, a.manifest):
        if p is not None and not p.exists():
            print(f"p15.graph.viewer: {p}: no such file", file=sys.stderr)
            return 2
    try:
        if a.story:
            doc = validate(json.loads(a.story.read_text(encoding="utf-8")))
        else:
            src = {"kind": "text", "file": a.from_text.name, "sha256": sha256(a.from_text)}
            if a.rules:
                src["rules"] = {"file": a.rules.name, "sha256": sha256(a.rules)}
            if a.manifest:
                src["manifest"] = a.manifest.read_text(encoding="utf-8").splitlines()
            doc = from_text(a.from_text.read_text(encoding="utf-8"),
                            a.rules.read_text(encoding="utf-8") if a.rules else None, src)
        if a.title:
            doc["title"] = a.title
        page = render(doc)
    except (StoryError, KeyError, TypeError, json.JSONDecodeError) as e:
        print(f"p15.graph.viewer: {e}", file=sys.stderr)
        return 1
    a.out.write_text(page, encoding="utf-8")
    if a.json and a.from_text:
        a.json.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"p15.graph.viewer: {len(doc['nodes'])} nodes, {len(doc['edges'])} edges, "
          f"{sum(a['on_path'] for a in doc['alerts'])} alerts on the path -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
