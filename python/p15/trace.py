# SPDX-License-Identifier: MIT
"""p15-trace: what happened on a port, from one capture run (STATE 19.4).

    PYTHONPATH=python python3 -m p15.trace --port 18077 /var/lib/p15/<run-id> [--html report.html]

It prints, and with --html also writes as one self-contained page:

- the run and how far to trust it: the capture's verdict (END), network capture on or off,
  NET records lost, GAP windows;
- the listeners on the port, with the process that listened and its lineage;
- every connection accepted on the port, joined to its listener by socket cookie (exact), and to
  the client process by endpoints when the client is on this host (an inference, labelled);
- every connect to the port, and every refused one;
- every process involved, with its program, arguments, parent chain and exit.

Exit 0 when the report was made (even if nothing happened on the port), 1 if the run can't be
read, 2 on bad usage.
"""

from __future__ import annotations

import argparse
import bisect
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import net as N
from . import proctree as P
from . import records as R
from . import wal as W


@dataclass
class Context:
    run: W.Run
    tree: P.Tree
    events: list[N.Event]
    end: R.Record | None
    stats: R.Record | None          # the last STATS
    net_stats: R.Record | None      # the last NET_STATS
    start_ns: int                   # the capture's start, CLOCK_BOOTTIME (segment 0's header)
    anchors: list[tuple[int, int]]  # (boottime, realtime) pairs: segment headers and CLOCK_SYNC
    net_on: bool
    record_errors: list

    def wall(self, ts: int) -> str:
        """CLOCK_BOOTTIME -> UTC wall time, through the nearest earlier clock anchor (ADR-0007 L5)."""
        i = max(0, bisect.bisect_right(self.anchors, (ts, 1 << 64)) - 1)
        bt, rt = self.anchors[i]
        t = rt + (ts - bt)
        return time.strftime("%H:%M:%S", time.gmtime(t // 1_000_000_000)) + f".{t // 1_000_000 % 1000:03d}"

    def rel(self, ts: int) -> str:
        return f"t+{(ts - self.start_ns) / 1e9:.3f}s"

    def when(self, ts: int) -> str:
        return f"{self.wall(ts)} ({self.rel(ts)})"

    def skip_lines(self) -> list[str]:
        """Events the kernel skipped before our programs ran (ADR-0020), from the last STATS and
        NET_STATS. A run written before v2 of those records didn't count them, and says so."""
        if self.stats is None:
            return ["no STATS record: the kernel's skipped events are unknown"]
        if self.stats.h["version"] < 2:
            return ["this run predates ADR-0020: events the kernel skipped (recursion misses) were not counted"]
        f = self.stats.f
        sk = {t: f[f"{t}_missed"] for t in ("fork", "exec", "exit", "rename")}
        net = self.net_stats.f["net_missed"] if self.net_stats is not None and self.net_stats.h["version"] >= 2 else 0
        if not any(sk.values()) and not net:
            return ["kernel-skipped events: none (every hook ran for every event)"]
        return ["KERNEL-SKIPPED EVENTS: " + ", ".join(f"{t} {n}" for t, n in sk.items()) + f", network {net}"
                + " (recursion misses, ADR-0020): processes alive then may lack records"]

    def verdict(self) -> list[str]:
        """How far the run can be trusted, in plain words; first line is the headline."""
        out = []
        if self.end is None:
            out.append("the run did not end in order: no END record (crashed, killed, or still running)")
        else:
            st = R.RUN_STATES.get(self.end.f["run_state"], str(self.end.f["run_state"]))
            inv = R.INVARIANT.get(self.end.f["invariant"], str(self.end.f["invariant"]))
            out.append(f"capture {st}, accounting invariant {inv}, exit {self.end.f['exit_code']}"
                       f" ({self.end.var['reason'].decode('utf-8', 'replace')})")
        if not self.net_on:
            out.append("NETWORK CAPTURE WAS OFF in this run (--no-net): no NET record means nothing is known, "
                       "not that nothing happened")
        out += self.skip_lines()
        if self.net_stats is not None:
            ns = self.net_stats.f
            out.append(f"NET records: {ns['net_emitted']} captured, {ns['net_reserve_failed']} lost to a full ring, "
                       f"{ns['net_excluded']} excluded by policy (failed accepts, non-IP sockets)")
        if self.tree.gaps:
            lost = sum(g.lost for g in self.tree.gaps)
            out.append(f"{len(self.tree.gaps)} GAP window(s), {lost} spine records lost: processes alive then may be "
                       "missing records")
        if self.run.stops:
            out += [f"{s.path.name}: {st.describe()}" for s, st in self.run.stops]
        if self.record_errors:
            out.append(f"{len(self.record_errors)} record(s) failed their check and were left out")
        return out


# header keys the report needs: the writer's clock anchor, and the daemon's (p15d.c)
NEEDED = ("clock.boottime_ns", "clock.realtime_ns", "config.net", "hostname", "kernel.release")


def load(path: Path) -> Context:
    run = W.read_run(path)
    missing = [k for k in NEEDED if k not in run.meta]
    if missing:
        raise W.RunError(f"not a p15d run: no {', '.join(missing)} in the header")
    errors: list = []
    spine = list(run.ring_records(0, errors))
    bulk = list(run.ring_records(1, errors))
    daemon = list(run.ring_records(2, errors))
    start = int(run.meta["clock.boottime_ns"])
    anchors = sorted({(int(s.meta["clock.boottime_ns"]), int(s.meta["clock.realtime_ns"])) for s in run.segments} |
                     {(r.f["boottime_ns"], r.f["realtime_ns"]) for r in daemon if r.name == "CLOCK_SYNC"})
    tree = P.build(spine + [r for r in daemon if r.name == "GAP"], start)
    events = sorted((N.event(r) for r in bulk if r.name == "NET"), key=lambda e: (e.ts_ns, e.seq))
    last = {}
    for r in daemon:
        last[r.name] = r
    return Context(run, tree, events, last.get("END"), last.get("STATS"), last.get("NET_STATS"), start, anchors,
                   run.meta["config.net"] == "yes", errors)


def proc_line(ctx: Context, key) -> str:
    p = ctx.tree.get(key)
    return f"{p.name} (pid {p.pid})"


def chain(ctx: Context, key) -> str:
    """The lineage on one line, nearest first: 'nc (640) ← sh (630) ← python3 (600) ← pid 500'."""
    parts = []
    for p in ctx.tree.lineage(key):
        parts.append(f"{p.name} ({p.pid})" if p.images or p.comm else f"pid {p.pid}")
        if p.parent is None and p.fork_ns is None:
            parts[-1] += " [started before the capture]" if p.origin.startswith("started before") else \
                " [FORK not in the run]"
    return " ← ".join(parts)


def involved(ctx: Context, rep: N.PortReport) -> list:
    """Every process the report names, and their ancestors, in order of first appearance."""
    seen: dict = {}
    for e in rep.events:
        for p in ctx.tree.lineage(e.proc) or [ctx.tree.get(e.proc)]:
            seen.setdefault(p.key, p)
    return list(seen.values())


def proc_block(ctx: Context, p: P.Proc) -> list[str]:
    life = [f"started {ctx.rel(p.fork_ns)}" if p.fork_ns is not None else p.origin]
    life.append(p.exit_text() + (f" at {ctx.rel(p.exit_ns)}" if p.exit_ns is not None else ""))
    out = [f"  pid {p.pid:<7} {p.cmdline if p.images else (p.comm or '(no program recorded)')}",
           f"            {'; '.join(life)}"]
    for im in p.images[:-1]:
        out.append(f"            earlier image at {ctx.rel(im.ts_ns)}: {' '.join(im.argv) or im.filename}")
    if p.parent is not None:
        out.append(f"            parent: {chain(ctx, p.parent)}")
    if p.in_gap:
        out.append("            alive during a GAP window: some of its records may be missing")
    return out


def text_report(ctx: Context, rep: N.PortReport) -> str:
    m = ctx.run.meta
    L = [f"p15-trace: port {rep.port}",
         f"run {m['run.id']} on {m['hostname']}, kernel {m['kernel.release']}, "
         f"captured from {ctx.wall(ctx.start_ns)} UTC", ""]
    L += ["Trust"] + [f"  {x}" for x in ctx.verdict()] + [""]
    clients = sum(1 for c in rep.accepted if c.connect)
    L.append(f"Summary: {len(rep.listeners)} listener(s); {len(rep.accepted)} connection(s) accepted, "
             f"{clients} of them from a process on this host; {len(rep.outbound)} connect(s) to the port, "
             f"{len(rep.refused)} refused or failed")
    L.append("")
    L.append(f"Listeners on port {rep.port}")
    for lst in rep.listeners:
        L.append(f"  {lst.endpoint} {lst.listen.proto}  cookie {lst.cookie}  listening from {ctx.when(lst.listen.ts_ns)}"
                 f"  by {chain(ctx, lst.proc)}")
    if not rep.listeners:
        L.append("  none in this run")
    L.append("")
    L.append(f"Connections accepted on port {rep.port}")
    for c in rep.accepted:
        a = c.accept
        via = f"listener cookie {c.listener.cookie}" if c.listener else "listener not in the run"
        L.append(f"  {ctx.when(a.ts_ns)}  {a.remote} -> {a.local}  accepted by {proc_line(ctx, a.proc)}  ({via})")
        if c.connect:
            L.append(f"      client: {chain(ctx, c.connect.proc)}  (matched by endpoints, connect at "
                     f"{ctx.rel(c.connect.ts_ns)})")
        else:
            L.append("      client: not on this host, or its connect is not in the run")
    if not rep.accepted:
        L.append("  none in this run")
    L.append("")
    L.append(f"Connects to port {rep.port}")
    for e in rep.outbound + rep.refused:
        L.append(f"  {ctx.when(e.ts_ns)}  {e.local} -> {e.remote} {e.proto}  {e.ret_text():<22}  by {chain(ctx, e.proc)}")
    if not rep.outbound + rep.refused:
        L.append("  none in this run")
    for title, evs in ((f"Binds to port {rep.port} with no listen (UDP, or failed)", rep.binds),
                       (f"Connects made from local port {rep.port}", rep.other)):
        if evs:
            L += ["", title]
            L += [f"  {ctx.when(e.ts_ns)}  {e.local} -> {e.remote} {e.proto}  {e.ret_text()}  by {chain(ctx, e.proc)}"
                  for e in evs]
    ps = involved(ctx, rep)
    L += ["", f"Processes involved ({len(ps)}, with their ancestors)"]
    for p in ps:
        L += proc_block(ctx, p)
    if not rep.events:
        L += ["", f"Nothing in this run names port {rep.port}" +
              (": network capture was off, so this says nothing." if not ctx.net_on else ".")]
    c, t = rep.counts, ctx.tree.counts
    L += ["", "How the joins were made",
          "  listener <- accept: by socket cookie (exact, ADR-0004 rule 5)",
          f"  client -> accept: by endpoints on this host (an inference): {c['client_by_endpoints']} matched, "
          f"{c['endpoint_ambiguous']} of them with more than one candidate (the nearest earlier connect taken), "
          f"{c['client_not_found']} not found",
          f"  process tree: {len(ctx.tree.procs)} processes, {t['pre_existing']} started before the capture "
          f"(their parents come with the snapshot, step 4c), {t['fork_missing']} with a missing FORK; "
          f"ADR-0009 checks: {t['exit_twice']} double exits, {t['fork_twice']} double forks (must be 0)"]
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="p15-trace", description="What happened on a port, from one capture run.")
    ap.add_argument("run_dir", type=Path, help="a p15d run directory (<wal-dir>/<run-id>)")
    ap.add_argument("--port", type=int, required=True, help="the TCP or UDP port, 1-65535")
    ap.add_argument("--html", type=Path, help="also write a self-contained HTML report here")
    a = ap.parse_args(argv)
    if not 1 <= a.port <= 65535:
        ap.error("--port must be 1-65535")
    try:
        ctx = load(a.run_dir)
    except (OSError, W.HeaderError, W.RunError, R.RecordError) as e:
        print(f"p15-trace: cannot read {a.run_dir}: {e}", file=sys.stderr)
        return 1
    rep = N.port_report(ctx.events, a.port)
    sys.stdout.write(text_report(ctx, rep))
    if a.html:
        from . import report_html
        a.html.write_text(report_html.render(ctx, rep), encoding="utf-8")
        print(f"HTML report: {a.html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
