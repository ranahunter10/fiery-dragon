#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize open_sections output (bench/open_sections/open_sections.c).

    python3 bench/open_sections/summarize.py open_sections.txt [--ref-nullsys-ns NS]

single: per section, the median over the timed rounds of its ns per sample, with the cheapest and
dearest round, and net of the empty bracket's cost in the same round. Every round must have exactly
N samples of each whole-program section (this process's opens only): otherwise no time is reported.
The host-speed control is bench/prim_cost's (E-0181): SLOW or UNSTEADY means not quotable.
contend: how many opens the path program was skipped for (OPEN written with PATH_MISSING), against
the opens all tasks made while the workers ran, with a 95 % upper bound when none was skipped.
Exit 1 if the books did not close, a line does not parse, or a check fails.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from collections import defaultdict
from pathlib import Path


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# bench/prim_cost's report, for its host-speed rule (E-0181); loaded by path, as both files are summarize.py
PC = _load("p15_prim_cost_summarize", Path(__file__).resolve().parents[1] / "prim_cost" / "summarize.py")
P = PC.P
SECS = ("empty", "open_all", "open_claim", "open_hdr", "open_facts", "open_obj", "open_file", "open_dpath",
        "open_output", "sess_entry", "sess_file", "sess_return", "free_all", "free_lookup", "free_ring", "free_delete")
WHOLE = ("open_all", "sess_entry", "sess_return", "free_all")   # one sample per open+close of this process
INNER = {"open_all": ("open_claim", "open_hdr", "open_facts", "open_obj", "open_file", "open_dpath", "open_output"),
         "sess_entry": ("sess_file",), "free_all": ("free_lookup", "free_ring", "free_delete")}
CONFIG = re.compile(r"^config mode=(single|contend) (rounds|workers)=(\d+) n=(\d+) ncpu=(\d+) dir=(\S+)$")
ROW = re.compile(r"^row round=(-?\d+) sec=(\w+) n=(\d+) ns=(\d+)$")
WKEYS = ("walked", "walk_unnamed", "walk_raced", "walk_truncated", "rec_walked", "target", "target_wrong")
WALK = re.compile(r"^walk " + " ".join(f"{k}=(\\d+)" for k in WKEYS) + "$")
BOOKS = re.compile(r"^books (ok|FAIL) open=(\d+) close=(\d+) other=(\d+)$")
CONTEND = re.compile(r"^contend " + " ".join(f"{k}=(\\d+)" for k in (
    "workers", "n", "opens", "fentry_run", "session_entry", "session_no_inode", "missing", "open_emitted",
    "open_lost", "missing_lost", "close_emitted", "close_lost", "rmiss_path", "rmiss_session", "rmiss_free",
    "lmiss_session", "lmiss_free")) + "$")
CKEYS = ("workers", "n", "opens", "fentry_run", "session_entry", "session_no_inode", "missing", "open_emitted",
         "open_lost", "missing_lost", "close_emitted", "close_lost", "rmiss_path", "rmiss_session", "rmiss_free",
         "lmiss_session", "lmiss_free")


class ParseError(Exception):
    pass


def parse(text: str) -> dict:
    out = {"rows": defaultdict(dict), "host": {}, "config": None, "books": None, "contend": None, "walk": None, "bad": []}
    for line in text.splitlines():
        if line.startswith("config "):
            m = CONFIG.match(line)
            if not m:
                raise ParseError(f"unparsed config: {line}")
            out["config"] = {"mode": m[1], "count": int(m[3]), "n": int(m[4]), "ncpu": int(m[5])}
        elif line.startswith("row "):
            m = ROW.match(line)
            if not m:
                raise ParseError(f"unparsed row: {line}")
            r, sec = int(m[1]), m[2]
            if sec not in SECS:
                raise ParseError(f"unknown section: {line}")
            if sec in out["rows"][r]:
                raise ParseError(f"round {r}: {sec} twice")
            out["rows"][r][sec] = (int(m[3]), int(m[4]))
        elif line.startswith("host "):
            m = PC.HOST.match(line)
            if not m:
                raise ParseError(f"unparsed host line: {line}")
            if int(m[1]) in out["host"]:
                raise ParseError(f"round {m[1]}: two host lines")
            if int(m[2]) <= 0 or int(m[3]) <= 0:
                out["bad"].append(f"round {m[1]}: the host line measured nothing")
            else:
                out["host"][int(m[1])] = int(m[3]) / int(m[2])
        elif line.startswith("contend "):
            m = CONTEND.match(line)
            if not m:
                raise ParseError(f"unparsed contend line: {line}")
            out["contend"] = dict(zip(CKEYS, (int(x) for x in m.groups())))
        elif line.startswith("walk "):
            m = WALK.match(line)
            if not m or out["walk"] is not None:
                raise ParseError(f"unparsed or second walk line: {line}")
            out["walk"] = dict(zip(WKEYS, (int(x) for x in m.groups())))
        elif line.startswith("books "):
            m = BOOKS.match(line)
            if not m:
                raise ParseError(f"unparsed books line: {line}")
            out["books"] = m[1]
            if m[1] != "ok":
                out["bad"].append(f"the books did not close: {line}")
        elif line.strip():
            raise ParseError(f"unknown line: {line}")
    if out["config"] is None:
        raise ParseError("no config line")
    if out["books"] is None:
        out["bad"].append("no books line: the run did not finish")
    return out


def single(d: dict, ref: float | None) -> tuple[list[str], int]:
    cfg, rows, bad = d["config"], d["rows"], list(d["bad"])
    for r in sorted(rows):
        missing = [s for s in SECS if s not in rows[r]]
        if missing:
            raise ParseError(f"round {r}: missing {', '.join(missing)}")
        if r not in d["host"]:
            raise ParseError(f"round {r}: no host line")
        for s in WHOLE:
            if rows[r][s][0] != cfg["n"]:
                bad.append(f"round {r}: {s} has {rows[r][s][0]} samples for {cfg['n']} opens")
    timed = [r for r in sorted(rows) if r >= 0]
    if not timed:
        raise ParseError("no timed rounds")
    out = [f"Run: {cfg['count']} rounds of {cfg['n']:,} open+close, pinned.", ""]
    if bad:
        return out + ["## Checks that failed: no time is reported", ""] + [f"- {b}" for b in bad] + [""], 1
    out += PC.host_lines([d["host"][r] for r in timed], ref)[0]

    def per(r, s):
        n, ns = rows[r][s]
        return ns / n if n else None

    out += ["| section | samples per open | ns per sample (median) | cheapest to dearest round | net of the bracket |",
            "|---|---|---|---|---|"]
    med = {}
    for s in SECS:
        vals = [per(r, s) for r in timed]
        if any(v is None for v in vals):
            out.append(f"| {s} | 0 | | | |")
            continue
        net = [per(r, s) - per(r, "empty") for r in timed]
        med[s] = P.median(vals)
        spp = P.median([rows[r][s][0] / cfg["n"] for r in timed])
        out.append(f"| {s} | {spp:.3f} | {med[s]:.1f} | {min(vals):.1f} to {max(vals):.1f} |"
                   f" {'' if s == 'empty' else f'{P.median(net):.1f}'} |")
    out.append("")
    for whole, parts in INNER.items():
        if whole in med and all(p in med for p in parts):
            rest = med[whole] - sum(med[p] for p in parts)
            out.append(f"- {whole}: {med[whole]:.1f} ns, of which its {len(parts)} timed sections {med[whole] - rest:.1f};"
                       f" the rest, {rest:.1f} ns, is untimed code and the inner brackets' own cost.")
    return out + [""], 0


def contend(d: dict) -> tuple[list[str], int]:
    c, bad = d["contend"], list(d["bad"])
    out = [f"Run: {c['workers']} processes, not pinned, {c['n']:,} open+close each ({c['opens']:,}), on "
           f"{d['config']['ncpu']} CPUs.", ""]
    if bad:
        return out + ["## Checks that failed: no rate is reported", ""] + [f"- {b}" for b in bad] + [""], 1
    if c["fentry_run"] + c["missing"] < c["opens"]:
        bad.append(f"fewer opens seen ({c['fentry_run']} path runs + {c['missing']} skipped) than the workers made ({c['opens']})")
        return out + ["## Checks that failed: no rate is reported", ""] + [f"- {b}" for b in bad] + [""], 1
    seen = c["fentry_run"] + c["missing"]
    out += [f"- Opens seen by the session program while the workers ran (all tasks): {c['session_entry']:,}; "
            f"path program runs: {c['fentry_run']:,}.",
            f"- **Path program skipped: {c['missing']:,} opens** (OPEN written by the session return), "
            f"{c['missing'] / seen:.2e} of {seen:,}."
            + ("" if c["missing"] else f" None skipped: below {3 / seen:.2e} at 95 % (rule of three)."),
            f"- The kernel's own counts: recursion_misses path {c['rmiss_path']}, session {c['rmiss_session']}, "
            f"close {c['rmiss_free']}; kprobe_multi.missed session {c['lmiss_session']}, close {c['lmiss_free']}.",
            f"- Records lost to a full ring: OPEN {c['open_lost']}, PATH_MISSING {c['missing_lost']}, CLOSE {c['close_lost']}.",
            ""]
    w = d["walk"]
    if w is None:
        out += ["No walk line: a run from before ADR-0029, when a skipped open had no path.", ""]
        return out, 0
    out += [f"- **The session return walked {w['walked']:,} of the {c['missing']:,} skipped opens** (PATH_WALKED, ADR-0029); "
            f"{w['walk_unnamed']:,} without a path; {w['walk_raced']:,} RACED, {w['walk_truncated']:,} TRUNCATED.",
            f"- Walked OPENs read from the ring: {w['rec_walked']:,}; of those naming a file called `same`, "
            f"{w['target']:,}, **{w['target_wrong']:,} with another path than DIR/same**.", ""]
    if w["walked"] + w["walk_unnamed"] != c["missing"]:
        bad.append(f"walked {w['walked']} + without a path {w['walk_unnamed']} != the return's OPENs {c['missing']}")
    if w["rec_walked"] != w["walked"]:
        bad.append(f"walked OPENs read {w['rec_walked']} != the WALKED counter {w['walked']}")
    if w["target_wrong"]:
        bad.append(f"{w['target_wrong']} walked OPENs of DIR/same with another path")
    if c["missing"] and not w["target"]:
        bad.append("opens were skipped but no walked OPEN of DIR/same was read")
    if bad:
        return out + ["## Checks that failed", ""] + [f"- {b}" for b in bad] + [""], 1
    return out, 0


def report(text: str, ref: float | None = None) -> tuple[str, int]:
    d = parse(text)
    head = ["# open_sections: where the file programs' time goes", ""]
    if d["config"]["mode"] == "single":
        if d["contend"] is not None or d["walk"] is not None:
            raise ParseError("a contend line in a single run")
        body, rc = single(d, ref)
    else:
        if d["rows"] or d["contend"] is None:
            raise ParseError("a contend run needs one contend line and no rows")
        body, rc = contend(d)
    return "\n".join(head + body), rc


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 4) or (len(argv) == 4 and argv[2] != "--ref-nullsys-ns"):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        ref = float(argv[3]) if len(argv) == 4 else None
        if ref is not None and ref <= 0:
            raise ValueError("--ref-nullsys-ns must be positive")
        text, rc = report(Path(argv[1]).read_text(), ref)
    except (ParseError, ValueError) as e:
        print(f"summarize: {e}", file=sys.stderr)
        return 1
    print(text)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
