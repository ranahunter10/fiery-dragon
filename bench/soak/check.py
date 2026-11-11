# SPDX-License-Identifier: MIT
"""The soak's ground-truth checks (bench/soak/workload.py's log against the WAL and the graph).

Each record is credited to the step whose [t0, t1] window holds its timestamp (steps run one after
another), so a background program or a reused port never counts for a step.
  open_w / open_r: an OPEN of exactly that path, written for writing (O_WRONLY or O_RDWR) or not;
  exec: EXECs with that filename, at least n; argv0: EXECs whose argv[0] is the marker, at least n;
  accept / connect: NET ACCEPT on that local port / CONNECT to that remote port, at least n.
"""
from __future__ import annotations

import bisect
import json
from collections import Counter, defaultdict
from pathlib import Path

O_ACCMODE = 3
OP_CONNECT, OP_ACCEPT = 1, 2


class Truth:
    def __init__(self, steps: list[dict]):
        self.steps = sorted((s for s in steps if s.get("ok")), key=lambda s: s["t0"])
        self.failed = [s for s in steps if not s.get("ok")]
        self.t0 = [s["t0"] for s in self.steps]
        self.found = [defaultdict(Counter) for _ in self.steps]
        self.wanted = []
        for s in self.steps:
            e = s["expect"]
            self.wanted.append({"open_w": set(e.get("open_w", ())), "open_r": set(e.get("open_r", ())),
                                "exec": dict(e.get("exec", {})), "argv0": dict(e.get("argv0", {})),
                                "accept": {int(k): v for k, v in e.get("accept", {}).items()},
                                "connect": {int(k): v for k, v in e.get("connect", {}).items()}})

    @classmethod
    def load(cls, path: Path) -> "Truth":
        return cls([json.loads(x) for x in path.read_text().splitlines() if x.strip()])

    def _step(self, ts: int) -> int:
        k = bisect.bisect_right(self.t0, ts) - 1
        return k if k >= 0 and ts <= self.steps[k]["t1"] else -1

    def see(self, r) -> None:
        """One decoded record (p15.records.Record or alike: name, h, f, var)."""
        if r.name not in ("OPEN", "EXEC", "NET"):
            return
        k = self._step(r.h["ts_ns"])
        if k < 0:
            return
        w, f = self.wanted[k], self.found[k]
        if r.name == "OPEN":
            p = r.var["path"].decode(errors="replace")
            kind = "open_w" if r.f["f_flags"] & O_ACCMODE else "open_r"
            if p in w[kind]:
                f[kind][p] += 1
        elif r.name == "EXEC":
            fn = r.var["filename"].decode(errors="replace")
            if fn in w["exec"]:
                f["exec"][fn] += 1
            a0 = r.var["argv"].split(b"\0", 1)[0].decode(errors="replace")
            if a0 in w["argv0"]:
                f["argv0"][a0] += 1
        elif r.f["op"] == OP_ACCEPT and r.f["lport"] in w["accept"]:
            f["accept"][r.f["lport"]] += 1
        elif r.f["op"] == OP_CONNECT and r.f["rport"] in w["connect"]:
            f["connect"][r.f["rport"]] += 1

    def results(self) -> dict:
        """Per step kind: expected items, found items, and up to 5 missing ones."""
        out = defaultdict(lambda: {"steps": 0, "expected": 0, "found": 0, "missing": []})
        for s, w, f in zip(self.steps, self.wanted, self.found):
            o = out[s["step"]]
            o["steps"] += 1
            for kind in ("open_w", "open_r"):
                for p in w[kind]:
                    o["expected"] += 1
                    if f[kind][p]:
                        o["found"] += 1
                    elif len(o["missing"]) < 5:
                        o["missing"].append(f"{s['step']}-{s['i']} {kind} {p}")
            for kind in ("exec", "argv0", "accept", "connect"):
                for key, n in w[kind].items():
                    o["expected"] += 1
                    if f[kind][key] >= n:
                        o["found"] += 1
                    elif len(o["missing"]) < 5:
                        o["missing"].append(f"{s['step']}-{s['i']} {kind} {key}: {f[kind][key]} of {n}")
        return dict(out)


GRAPH_QUERIES = {
    # the compiled program: one file node written by a process and executed into another
    "dropper_chain": """
        SELECT count(DISTINCT f.node_id) FROM file f
        WHERE f.path = ANY(?)
          AND EXISTS (SELECT 1 FROM edge e WHERE e.src = f.node_id AND e.op = 'OPEN' AND e.access IN ('w', 'rw'))
          AND EXISTS (SELECT 1 FROM edge e WHERE e.src = f.node_id AND e.op = 'EXECUTE')""",
    # an http client's socket paired with the server's, by the TCP ISN (ADR-0022)
    "sock_pairs": "SELECT count(*) FROM sock_pair p JOIN sock s ON s.node_id = p.server_node WHERE s.lport = ANY(?)",
    # a process whose argv[0] is a memfd marker, with its EXECUTE edge
    "memfd_exec": """
        SELECT count(DISTINCT p.node_id) FROM proc p JOIN edge e ON e.dst = p.node_id AND e.op = 'EXECUTE'
        WHERE split_part(p.cmd, ' ', 1) = ANY(?)""",
}


def graph_wants(truth: Truth) -> dict:
    """What the graph must hold: the compiled programs, the http ports (M pairs each), the memfd markers."""
    progs, ports, markers = [], {}, []
    for s, w in zip(truth.steps, truth.wanted):
        if s["step"] == "compile":
            progs += [p for p in w["exec"] if p.endswith(f"/prog{s['i']}")]
        ports.update(w["accept"])
        markers += list(w["argv0"])
    return {"dropper_chain": (progs, len(progs)), "sock_pairs": (list(ports), sum(ports.values())),
            "memfd_exec": (markers, len(markers))}


def graph_check(db_path: Path, truth: Truth) -> dict:
    import duckdb
    con = duckdb.connect(str(db_path), read_only=True)
    out = {}
    try:
        for name, (vals, want) in graph_wants(truth).items():
            got = con.execute(GRAPH_QUERIES[name], [vals]).fetchone()[0] if vals else 0
            out[name] = (got, want)
    finally:
        con.close()
    return out
