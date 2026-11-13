#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Find the guest's stalls in its kernel log and name the matrix steps they touched (E-0250).

    python3 tools/vm/stalls.py KERNEL_LOG STEPS_TXT

KERNEL_LOG is `journalctl -k -o short-unix` for the run's window: each line starts with its time in
seconds since the epoch. STEPS_TXT is measure_capture.sh's steps.txt, whose lines carry start= and
end= in the same clock.

The VM's host can stop running the guest for minutes (E-0088, E-0250). When the guest runs again,
its kernel says so, at the moment it wakes:
- `clocksource: Long readout interval, skipping watchdog check: cs_nsec: N`: N ns passed between
  two of the clocksource watchdog's reads, which are normally 0.5 s apart;
- `watchdog: BUG: soft lockup - CPU#k stuck for Ns!`: a CPU did not schedule its watchdog for N s;
- `rcu: ... self-detected stall` or `rcu: ... detected stalls`: an RCU grace period took more than
  its 21 s timeout (length not stated).
A sign whose stated length is at least MIN_S, or an RCU stall, is a stall ending at its line's time.
Signs less than WINDOW_S apart are one stall; its length is the longest stated. A step is touched
when its [start, end] overlaps the stall's [end - length, end].

Output, one fact per line: `stall end=T gap_s=G signs=...` per stall, then `touched STEP gap_s=G`
per touched step, then `stalls N`. A stall says nothing about correctness (the books still close);
it makes the touched steps' rates and timings not quotable (STATE decision 30).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

MIN_S = 1.0
WINDOW_S = 5.0
CLOCKSOURCE = re.compile(r"clocksource: Long readout interval.*cs_nsec: (\d+)")
LOCKUP = re.compile(r"soft lockup - CPU#\d+ stuck for (\d+)s")
RCU = re.compile(r"rcu: .*(self-detected stall|detected stalls)")
KV = re.compile(r"(\w+)=(\S+)")


def signs(log: str) -> list[tuple[float, float, str]]:
    """(time, stated length in s or 0, kind) for every stall sign in the log."""
    out = []
    for line in log.splitlines():
        head, _, rest = line.partition(" ")
        try:
            t = float(head)
        except ValueError:
            continue                    # journalctl's "-- No entries --" and the like
        m = CLOCKSOURCE.search(rest)
        if m:
            out.append((t, int(m.group(1)) / 1e9, "clocksource"))
            continue
        m = LOCKUP.search(rest)
        if m:
            out.append((t, float(m.group(1)), "soft_lockup"))
            continue
        if RCU.search(rest):
            out.append((t, 0.0, "rcu_stall"))
    return out


def stalls(found: list[tuple[float, float, str]]) -> list[dict]:
    """Group the signs into stalls: each {end, gap_s, signs}."""
    keep = sorted(s for s in found if s[1] >= MIN_S or s[2] == "rcu_stall")
    out: list[dict] = []
    for t, gap, kind in keep:
        if out and t - out[-1]["end"] <= WINDOW_S:
            out[-1]["end"] = max(out[-1]["end"], t)
            out[-1]["gap_s"] = max(out[-1]["gap_s"], gap)
            out[-1]["signs"].append(kind)
        else:
            out.append({"end": t, "gap_s": gap, "signs": [kind]})
    return out


def steps(text: str) -> list[dict]:
    """measure_capture's steps.txt: {name, start, end} for each line that has both times."""
    out = []
    for line in text.splitlines():
        name, _, rest = line.partition(" ")
        f = dict(KV.findall(rest))
        if "start" in f and "end" in f:
            out.append({"name": name, "start": float(f["start"]), "end": float(f["end"])})
    return out


def touched(st: list[dict], sp: list[dict]) -> list[tuple[str, float]]:
    """(step, the longest stall that overlapped it) for every step a stall overlapped."""
    out = []
    for s in sp:
        gaps = [x["gap_s"] for x in st if s["start"] <= x["end"] and x["end"] - x["gap_s"] <= s["end"]]
        if gaps:
            out.append((s["name"], max(gaps)))
    return out


def report(log: str, steps_text: str) -> str:
    st = stalls(signs(log))
    lines = [f"stall end={x['end']:.3f} gap_s={x['gap_s']:.1f} signs={','.join(x['signs'])}" for x in st]
    lines += [f"touched {n} gap_s={g:.1f}" for n, g in touched(st, steps(steps_text))]
    lines.append(f"stalls {len(st)}")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    sys.stdout.write(report(Path(argv[1]).read_text(errors="replace"), Path(argv[2]).read_text()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
