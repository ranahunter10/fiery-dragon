#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize census.bt output into per-class event rates and a log-budget verdict.

Input is the JSON-lines output of ``bpftrace -f json census.bt``. Counters in
that output are cumulative; a ``T <ns>`` printf marker starts each snapshot.
This script turns consecutive snapshots into per-window rates and reports,
per record class:
    total, mean/s, p50/s, p99/s, max/s (over 100 ms windows), payload MB/s

It then estimates the write-ahead-log bandwidth that the *emitted* classes
would need, and compares it with the disk budget measured in phase 0 (P5).

Nothing is silently dropped. Unknown classes, unknown map names, unknown line
types and bpftrace "lost events" are counted and reported. A malformed line,
a counter going backwards, or time going backwards is an error.

Record sizes are ASSUMPTIONS (grade INF) until the schema exists (ADR-0008).
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass, field
from typing import Iterable, TextIO

# --- record classes (blueprint v1 §4.1) ------------------------------------

FAMILY = {
    "fork": "spine", "exec": "spine", "exit": "spine", "rename": "spine",
    "rename_exec": "info",  # comm change done by exec itself: part of the EXEC record
    "open": "open", "open_fail": "open",
    "rd_reg": "file", "wr_reg": "file", "rd_pipe": "file", "wr_pipe": "file",
    "rd_sock": "file-not-emitted", "wr_sock": "file-not-emitted",
    "rd_chr": "file-not-emitted", "wr_chr": "file-not-emitted",
    "rd_other": "file-not-emitted", "wr_other": "file-not-emitted",
    "splice": "xfer", "splice_direct": "xfer", "copy_range": "xfer",
    "snd": "sock", "rcv": "sock",
    "uring": "uring",
    "sys": "info",
}

FAMILY_ORDER = ("spine", "open", "file", "file-not-emitted", "xfer", "sock", "uring", "info")

# Classes the capture would emit as records. Socket I/O via read()/write() is
# emitted by the socket hooks (snd/rcv), so rd_sock/wr_sock are excluded here
# to avoid counting it twice. Character devices and other inode types are not
# FILE_FLOW sources in the v1 design.
EMITTED = tuple(k for k, fam in FAMILY.items() if fam not in ("file-not-emitted", "info"))

DEFAULT_RECORD_BYTES = 64                                       # INF: FLOW target, blueprint §4.3
DEFAULT_SIZE_OVERRIDES = {"exec": 256, "open": 128, "open_fail": 128}  # INF: carry a path/argv excerpt

MIN_WINDOW_NS = 50_000_000  # a window shorter than this is merged into the previous one


class CensusError(ValueError):
    """The input violates the census output contract."""


@dataclass
class Snapshot:
    t_ns: int
    counts: dict[str, int] = field(default_factory=dict)
    payload: dict[str, int] = field(default_factory=dict)


@dataclass
class Census:
    snapshots: list[Snapshot] = field(default_factory=list)
    attached_probes: int | None = None
    started: bool = False
    ended: bool = False
    lost_events: int = 0
    unknown_line_types: dict[str, int] = field(default_factory=dict)
    unknown_maps: dict[str, int] = field(default_factory=dict)


def parse(lines: Iterable[str]) -> Census:
    """Parse bpftrace JSON lines. Raises CensusError on contract violations."""
    c = Census()
    current: Snapshot | None = None
    for lineno, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            raise CensusError(f"line {lineno}: not JSON: {e.msg}") from None
        kind = obj.get("type")
        data = obj.get("data")
        if kind == "attached_probes":
            c.attached_probes = int(data["probes"])
        elif kind == "printf":
            text = str(data).strip()
            if text == "CENSUS v1 start":
                c.started = True
            elif text == "CENSUS end":
                c.ended = True
            elif text.startswith("T "):
                try:
                    t = int(text[2:])
                except ValueError:
                    raise CensusError(f"line {lineno}: bad time marker {text!r}") from None
                if c.snapshots and t <= c.snapshots[-1].t_ns:
                    raise CensusError(f"line {lineno}: time went backwards ({t} after {c.snapshots[-1].t_ns})")
                current = Snapshot(t_ns=t)
                c.snapshots.append(current)
            else:
                c.unknown_line_types["printf:" + text[:40]] = c.unknown_line_types.get("printf:" + text[:40], 0) + 1
        elif kind == "map":
            if current is None:
                raise CensusError(f"line {lineno}: map output before the first time marker")
            for name, values in data.items():
                if name == "@c":
                    target = current.counts
                elif name == "@b":
                    target = current.payload
                else:
                    c.unknown_maps[name] = c.unknown_maps.get(name, 0) + 1
                    continue
                for key, val in values.items():
                    target[str(key)] = int(val)
        elif kind == "lost_events":
            c.lost_events += int(data.get("events", 0)) if isinstance(data, dict) else int(data)
        else:
            c.unknown_line_types[str(kind)] = c.unknown_line_types.get(str(kind), 0) + 1

    # Cumulative counters may never decrease.
    for series in ("counts", "payload"):
        prev: dict[str, int] = {}
        for snap in c.snapshots:
            cur = getattr(snap, series)
            for key, val in prev.items():
                if cur.get(key, 0) < val:
                    raise CensusError(f"{series}[{key}] decreased at t={snap.t_ns}: {val} -> {cur.get(key, 0)}")
            prev = {**prev, **cur}
            setattr(snap, series, dict(prev))  # carry forward keys absent from this print
    return c


@dataclass
class Window:
    dt_ns: int
    counts: dict[str, int]
    payload: dict[str, int]


def windows(c: Census) -> list[Window]:
    """Deltas between consecutive snapshots; short windows merged backwards."""
    out: list[Window] = []
    prev = Snapshot(t_ns=0)
    for snap in c.snapshots:
        w = Window(
            dt_ns=snap.t_ns - prev.t_ns,
            counts={k: v - prev.counts.get(k, 0) for k, v in snap.counts.items()},
            payload={k: v - prev.payload.get(k, 0) for k, v in snap.payload.items()},
        )
        if w.dt_ns < MIN_WINDOW_NS and out:
            last = out[-1]
            last.dt_ns += w.dt_ns
            for k, v in w.counts.items():
                last.counts[k] = last.counts.get(k, 0) + v
            for k, v in w.payload.items():
                last.payload[k] = last.payload.get(k, 0) + v
        else:
            out.append(w)
        prev = snap
    return out


def percentile(values: list[float], p: float) -> float:
    """Nearest-rank percentile; 0.0 for an empty list."""
    if not values:
        return 0.0
    s = sorted(values)
    idx = max(0, math.ceil(p / 100.0 * len(s)) - 1)
    return s[idx]


def record_size(cls: str, sizes: dict[str, int], default: int) -> int:
    return sizes.get(cls, default)


def summarize(c: Census, *, label: str, disk_mbps: float, headroom: float,
              sizes: dict[str, int], default_size: int) -> dict:
    if not c.snapshots:
        raise CensusError("no time markers: the census produced no data")
    ws = windows(c)
    duration_s = c.snapshots[-1].t_ns / 1e9
    final = c.snapshots[-1]
    classes = sorted(set(final.counts) | set(FAMILY),
                     key=lambda k: (FAMILY_ORDER.index(FAMILY[k]) if k in FAMILY else len(FAMILY_ORDER), k))

    rows = []
    for cls in classes:
        rates = [w.counts.get(cls, 0) / (w.dt_ns / 1e9) for w in ws]
        total = final.counts.get(cls, 0)
        rows.append({
            "class": cls,
            "family": FAMILY.get(cls, "UNKNOWN"),
            "emitted": cls in EMITTED,
            "total": total,
            "mean_per_s": total / duration_s if duration_s else 0.0,
            "p50_per_s": percentile(rates, 50),
            "p99_per_s": percentile(rates, 99),
            "max_per_s": max(rates) if rates else 0.0,
            "payload_mb_per_s": final.payload.get(cls, 0) / duration_s / 1e6 if duration_s else 0.0,
        })

    rec_rates, byte_rates = [], []
    for w in ws:
        dt = w.dt_ns / 1e9
        rec_rates.append(sum(w.counts.get(k, 0) for k in EMITTED) / dt)
        byte_rates.append(sum(w.counts.get(k, 0) * record_size(k, sizes, default_size) for k in EMITTED) / dt)

    emitted_total = sum(final.counts.get(k, 0) for k in EMITTED)
    sys_total = final.counts.get("sys", 0)
    budget_bps = disk_mbps * 1e6 / headroom
    p99_bps = percentile(byte_rates, 99)
    return {
        "label": label,
        "duration_s": duration_s,
        "windows": len(ws),
        "attached_probes": c.attached_probes,
        "complete": c.started and c.ended,
        "lost_events": c.lost_events,
        "unknown_classes": sorted(k for k in final.counts if k not in FAMILY),
        "unknown_maps": c.unknown_maps,
        "unknown_line_types": c.unknown_line_types,
        "rows": rows,
        "emitted_records_mean_per_s": emitted_total / duration_s if duration_s else 0.0,
        "emitted_records_p99_per_s": percentile(rec_rates, 99),
        "emitted_records_max_per_s": max(rec_rates) if rec_rates else 0.0,
        "log_bytes_mean_per_s": sum(final.counts.get(k, 0) * record_size(k, sizes, default_size) for k in EMITTED) / duration_s if duration_s else 0.0,
        "log_bytes_p99_per_s": p99_bps,
        "log_bytes_max_per_s": max(byte_rates) if byte_rates else 0.0,
        "selectivity": emitted_total / sys_total if sys_total else None,
        "budget_bytes_per_s": budget_bps,
        "assumptions": {"disk_mbps": disk_mbps, "headroom": headroom,
                        "default_record_bytes": default_size, "record_bytes": sizes},
        "verdict": "WITHIN BUDGET" if p99_bps <= budget_bps else "EXCEEDS BUDGET",
    }


def to_markdown(s: dict) -> str:
    out = [f"## Census: {s['label']}", ""]
    flags = []
    if not s["complete"]:
        flags.append("**INCOMPLETE**: start or end marker missing (run interrupted?)")
    if s["lost_events"]:
        flags.append(f"**bpftrace lost {s['lost_events']} output events**: counts are a lower bound")
    if s["unknown_classes"]:
        flags.append(f"unknown classes: {', '.join(s['unknown_classes'])}")
    if s["unknown_maps"] or s["unknown_line_types"]:
        flags.append(f"unrecognised output: maps {s['unknown_maps']}, lines {s['unknown_line_types']}")
    out += [f"- {f}" for f in flags] or ["- output complete, no losses reported by bpftrace"]
    out += ["", f"Duration {s['duration_s']:.1f} s, {s['windows']} windows, {s['attached_probes']} probes attached.", "",
            "| class | family | emitted | total | mean/s | p50/s | p99/s | max/s | payload MB/s |",
            "|---|---|---|---:|---:|---:|---:|---:|---:|"]
    for r in s["rows"]:
        out.append(f"| {r['class']} | {r['family']} | {'yes' if r['emitted'] else 'no'} | {r['total']:,} | "
                   f"{r['mean_per_s']:,.0f} | {r['p50_per_s']:,.0f} | {r['p99_per_s']:,.0f} | {r['max_per_s']:,.0f} | "
                   f"{r['payload_mb_per_s']:.2f} |")
    sel = f"{s['selectivity']:.3f}" if s["selectivity"] is not None else "n/a"
    a = s["assumptions"]
    out += ["",
            f"- Emitted records/s: mean {s['emitted_records_mean_per_s']:,.0f}, p99 {s['emitted_records_p99_per_s']:,.0f}, "
            f"max {s['emitted_records_max_per_s']:,.0f}",
            f"- Estimated log bandwidth: mean {s['log_bytes_mean_per_s']/1e6:.2f} MB/s, p99 {s['log_bytes_p99_per_s']/1e6:.2f} MB/s, "
            f"max {s['log_bytes_max_per_s']/1e6:.2f} MB/s",
            f"- Budget: {a['disk_mbps']} MB/s disk / {a['headroom']}x headroom = {s['budget_bytes_per_s']/1e6:.2f} MB/s",
            f"- Selectivity (emitted records per syscall): {sel}",
            f"- **Verdict (p99 vs budget): {s['verdict']}**",
            f"- Assumed record sizes (INF until ADR-0008): default {a['default_record_bytes']} B, overrides {a['record_bytes']}",
            ""]
    return "\n".join(out)


def parse_sizes(items: list[str]) -> dict[str, int]:
    sizes = dict(DEFAULT_SIZE_OVERRIDES)
    for item in items:
        key, sep, val = item.partition("=")
        if not sep or not val.isdigit():
            raise argparse.ArgumentTypeError(f"--size expects CLASS=BYTES, got {item!r}")
        sizes[key] = int(val)
    return sizes


def main(argv: list[str] | None = None, stdout: TextIO = sys.stdout) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("input", help="bpftrace -f json output of census.bt")
    ap.add_argument("--label", default=None, help="workload name for the report")
    ap.add_argument("--disk-mbps", type=float, default=63.7,
                    help="sustained disk write MB/s (default: phase-0 P5 minimum, docs/evidence/phase0/05-p5-disk.txt)")
    ap.add_argument("--headroom", type=float, default=3.0, help="required headroom factor (blueprint §6.1)")
    ap.add_argument("--record-bytes", type=int, default=DEFAULT_RECORD_BYTES, help="assumed size of a record")
    ap.add_argument("--size", action="append", default=[], metavar="CLASS=BYTES", help="per-class size override")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    args = ap.parse_args(argv)
    try:
        sizes = parse_sizes(args.size)
    except argparse.ArgumentTypeError as e:
        ap.error(str(e))  # usage message and exit status 2, not a traceback

    with open(args.input, encoding="utf-8") as f:
        census = parse(f)
    s = summarize(census, label=args.label or args.input, disk_mbps=args.disk_mbps, headroom=args.headroom,
                  sizes=sizes, default_size=args.record_bytes)
    stdout.write(json.dumps(s, indent=2) + "\n" if args.format == "json" else to_markdown(s))
    return 0 if s["complete"] and not s["lost_events"] else 2


if __name__ == "__main__":
    sys.exit(main())
