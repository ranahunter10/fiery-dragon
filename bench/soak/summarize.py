#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize a soak (bench/soak/soak.py): gate 4 of STATE decision 28.

    python3 bench/soak/summarize.py soak.txt

PASS needs all of: p15d exited 0 with END state 0 (RUNNING) and its invariant closed, the WAL read
without an error or a torn stop; every item the workload logged found in the WAL (100 % per step
kind); the graph built (exit 0, its must-be-zero books 0) and every graph check complete (each
compiled program a written-then-executed file node, each http connection paired, each memfd
execution present); at most 10 % of the workload's steps failed. Also reported, not judged: CPU,
memory and WAL growth over the run, event rates, the walk's counters, the graph's books.
"""
from __future__ import annotations

import re
import statistics
import sys
from pathlib import Path

KV = re.compile(r"(\w+)=(\S+)")
MUST_BE_ZERO = ("edge_without_node", "obj_facts_conflict", "fid_two_objs")


class ParseError(Exception):
    pass


def kv(line: str) -> dict:
    return {k: v for k, v in KV.findall(line)}


def parse(text: str) -> dict:
    d = {"config": None, "samples": [], "end": None, "truth": [], "missing": [], "failed": [], "file_stats": None,
         "graph_out": [], "graph": None, "graph_truth": [], "errors": [], "workload": None}
    for line in text.splitlines():
        if not line.strip():
            continue
        tag, _, rest = line.partition(" ")
        if tag == "config":
            d["config"] = kv(rest)
        elif tag == "sample":
            s = kv(rest)
            d["samples"].append({k: float(v) for k, v in s.items()})
        elif tag == "workload":
            d["workload"] = kv(rest)
        elif tag == "end":
            if d["end"] is not None:
                raise ParseError("a second end line")
            d["end"] = {k: int(float(v)) for k, v in kv(rest).items()}
        elif tag == "truth":
            t = kv(rest)
            d["truth"].append({"step": t["step"], **{k: int(t[k]) for k in ("steps", "expected", "found")}})
        elif tag == "truth_missing":
            d["missing"].append(rest)
        elif tag == "step_failed":
            d["failed"].append(rest)
        elif tag == "file_stats":
            d["file_stats"] = {k: int(v) for k, v in kv(rest).items()}
        elif tag == "graph_out":
            d["graph_out"].append(rest)
        elif tag == "graph":
            d["graph"] = {k: float(v) for k, v in kv(rest).items()}
        elif tag == "graph_truth":
            name, *_ = rest.split()
            g = kv(rest)
            d["graph_truth"].append((name, int(g["found"]), int(g["expected"])))
        elif tag == "soak_error":
            d["errors"].append(rest)
        else:
            raise ParseError(f"unknown line: {line}")
    if d["config"] is None:
        raise ParseError("no config line")
    return d


def graph_books(lines: list[str]) -> dict[str, int]:
    out = {}
    for line in lines:
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("-").isdigit():
            out[parts[0]] = int(parts[1])
    return out


def report(text: str) -> tuple[str, int]:
    d = parse(text)
    fails, notes = list(d["errors"]), []
    out = ["# soak: p15d under real programs (gate 4)", ""]
    c = d["config"]
    out.append(f"Planned {float(c['duration']) / 60:.1f} min of workload, sampled every {c['sample']} s; "
               f"p15d options: {c['p15d_args']}; {c['ncpu']} CPUs.")
    e = d["end"]
    if e is None:
        fails.append("no end line: the soak did not finish")
    else:
        if not (e["exit"] == 0 and e["end"] == 1 and e["state"] == 0 and e["invariant"] == 1):
            fails.append(f"p15d's end: exit {e['exit']}, END {e['end']}, state {e['state']}, invariant {e['invariant']}")
        if e["read_errors"] or e["stops"]:
            fails.append(f"the WAL: {e['read_errors']} read errors, {e['stops']} torn stops")
        out.append(f"End: exit {e['exit']}, state {e['state']}, invariant {e['invariant']}; {e['records']:,} records read "
                   f"in {e['read_s']} s.")
    out.append("")
    s = d["samples"]
    if s:
        cpu = [x["cpu_ms_per_s"] for x in s]
        rss = [x["rss_kb"] for x in s]
        span_h = (s[-1]["t"] - s[0]["t"]) / 3600 if len(s) > 1 else 0
        wal_rate = (s[-1]["wal_bytes"] - s[0]["wal_bytes"]) / max(1.0, s[-1]["t"] - s[0]["t"])
        out += ["| over the run | median | max | first | last |", "|---|---|---|---|---|",
                f"| p15d CPU, ms/s | {statistics.median(cpu):.2f} | {max(cpu):.2f} | {cpu[0]:.2f} | {cpu[-1]:.2f} |",
                f"| drain thread, ms/s | {statistics.median(x['drain_ms_per_s'] for x in s):.2f} | "
                f"{max(x['drain_ms_per_s'] for x in s):.2f} | | |",
                f"| writer thread, ms/s | {statistics.median(x['writer_ms_per_s'] for x in s):.2f} | "
                f"{max(x['writer_ms_per_s'] for x in s):.2f} | | |",
                f"| resident memory, MiB | {statistics.median(rss) / 1024:.1f} | {max(rss) / 1024:.1f} | {rss[0] / 1024:.1f} | "
                f"{rss[-1] / 1024:.1f} |",
                f"| longest poll gap, s | {statistics.median(x['poll_gap_max_s'] for x in s):.3f} | "
                f"{max(x['poll_gap_max_s'] for x in s):.3f} | | |", "",
                f"WAL: {s[-1]['wal_bytes'] / 2**20:.1f} MiB, {wal_rate / 1024:.1f} KiB/s. Spine records drained: "
                f"{int(s[-1]['spine_drained']):,}; NET records written: {int(s[-1]['net_written']):,}; kernel skips: spine "
                f"{int(s[-1]['spine_skipped'])}, NET {int(s[-1]['net_skipped'])}; queue full {int(s[-1]['queue_full'])}; "
                f"GAP records {int(s[-1]['gaps'])}.", ""]
        if span_h >= 0.25 and rss[-1] > rss[0] * 1.5 and rss[-1] - rss[0] > 10 * 1024:
            notes.append(f"resident memory grew from {rss[0] / 1024:.1f} to {rss[-1] / 1024:.1f} MiB")
        if any(x["state"] for x in s):
            notes.append("the run state left RUNNING during the soak (see the samples)")
    else:
        fails.append("no sample lines")
    out += ["| step | steps | items expected | found | recall |", "|---|---|---|---|---|"]
    if not d["truth"]:
        fails.append("no truth lines: nothing was checked")
    nsteps = 0
    for t in d["truth"]:
        nsteps += t["steps"]
        rec = t["found"] / t["expected"] if t["expected"] else 1.0
        out.append(f"| {t['step']} | {t['steps']} | {t['expected']:,} | {t['found']:,} | {rec:.2%} |")
        if t["found"] != t["expected"]:
            fails.append(f"step {t['step']}: {t['expected'] - t['found']} of {t['expected']} items not in the WAL")
    out.append("")
    if d["missing"]:
        out += ["Missing (first 5 per step kind):", ""] + [f"- {m}" for m in d["missing"]] + [""]
    if d["failed"]:
        notes.append(f"{len(d['failed'])} workload steps failed (not checked): " + "; ".join(d["failed"][:3]))
        if len(d["failed"]) > 0.1 * (nsteps + len(d["failed"])):
            fails.append(f"{len(d['failed'])} workload steps failed: more than 10 %")
    if d["file_stats"]:
        f = d["file_stats"]
        out += [f"File identity: {f.get('open_emitted', 0):,} OPEN from the path program, {f.get('missing_emitted', 0):,} from "
                f"the session return ({f.get('walked', 0):,} walked, {f.get('walk_raced', 0)} raced, {f.get('walk_unnamed', 0)} "
                f"without a path); fentry skips {f.get('fentry_missed', 0):,}; lost: OPEN {f.get('open_lost', 0)}, CLOSE "
                f"{f.get('close_lost', 0)}; most open files {f.get('files_live_max', 0):,}, objects {f.get('objs_live_max', 0):,}.", ""]
    g = d["graph"]
    if g is None:
        fails.append("the graph was not built")
    else:
        books = graph_books(d["graph_out"])
        if g["rc"] != 0:
            fails.append(f"the graph build exited {int(g['rc'])}")
        for k in MUST_BE_ZERO:
            if books.get(k, 0):
                fails.append(f"graph book {k} = {books[k]} (must be 0)")
        out += [f"Graph: built in {int(g['build_s'])} s, {g['bytes'] / 2**20:.1f} MiB; " +
                ", ".join(f"{k} {v:,}" for k, v in sorted(books.items()) if k.startswith(("node_", "edge_"))) + ".", ""]
        out += ["| graph check | found | expected |", "|---|---|---|"]
        for name, got, want in d["graph_truth"]:
            out.append(f"| {name} | {got:,} | {want:,} |")
            if got != want:
                fails.append(f"graph check {name}: {got} of {want}")
        out.append("")
        if not d["graph_truth"]:
            fails.append("no graph checks")
    out += ["## Verdict", ""] + ([f"- FAIL: {x}" for x in fails] or ["- PASS"]) + [f"- note: {n}" for n in notes]
    return "\n".join(out + [""]), 1 if fails else 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        text, rc = report(Path(argv[1]).read_text())
    except (ParseError, ValueError, KeyError) as e:
        print(f"summarize: {e}", file=sys.stderr)
        return 1
    print(text)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
