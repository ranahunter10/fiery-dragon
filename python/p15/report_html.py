# SPDX-License-Identifier: MIT
"""The HTML form of p15-trace's port report: one self-contained page (no scripts, fonts or
images from anywhere else), so it can be mailed, archived next to the evidence and opened
offline. Everything on it comes from the same PortReport and process tree as the text form.

Layout: the port and how far to trust the run; a connection map (who connected, the port, who
listened and accepted); a timeline of every event on the port, one lane per process; the
processes with their lineage; every event in a table; how each join was made.
"""

from __future__ import annotations

from html import escape

from . import net as N
from . import proctree as P

CSS = """
:root{--bg:#eef1f4;--panel:#ffffff;--ink:#1c2430;--muted:#5b6675;--rule:#d5dbe2;
--connect:#0f766e;--accept:#4338ca;--listen:#a15c07;--refused:#b42318;--remote:#6b7280;--life:#c9d1da}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#121821;--panel:#1a222d;--ink:#dce3ea;
--muted:#93a0ae;--rule:#2c3644;--connect:#2dd4bf;--accept:#a5b4fc;--listen:#f0b45a;--refused:#f87171;--remote:#9ca3af;--life:#334155}}
:root[data-theme="dark"]{--bg:#121821;--panel:#1a222d;--ink:#dce3ea;--muted:#93a0ae;--rule:#2c3644;--connect:#2dd4bf;
--accept:#a5b4fc;--listen:#f0b45a;--refused:#f87171;--remote:#9ca3af;--life:#334155}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1080px;margin:0 auto;padding:32px 16px 64px}
code,.ep{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:.92em}
header.hero{display:grid;grid-template-columns:auto 1fr;gap:8px 32px;align-items:end;padding-bottom:20px;
border-bottom:2px solid var(--ink)}
.port{font-size:clamp(64px,13vw,128px);line-height:.85;font-weight:800;letter-spacing:-.04em;font-variant-numeric:tabular-nums}
.port small{display:block;font-size:15px;font-weight:600;letter-spacing:0;color:var(--muted);margin-bottom:10px}
.lede{font-size:18px;max-width:60ch;margin:0}
.run{grid-column:1/-1;color:var(--muted);font-size:13.5px;margin:0}
.trust{margin:20px 0 0;padding:14px 18px;border-left:5px solid var(--state);background:var(--panel)}
.trust p{margin:2px 0}.trust .head{font-weight:650}
h2{font-size:20px;margin:44px 0 6px;letter-spacing:-.01em}
h2+p.note{margin:0 0 14px;color:var(--muted);max-width:75ch}
.panel{background:var(--panel);border:1px solid var(--rule);border-radius:6px;padding:12px;overflow-x:auto}
svg{display:block;width:100%;height:auto;min-width:720px}
.sub{color:var(--muted);font-size:12.5px}
svg text{fill:var(--ink);font:13px system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
svg .sub{fill:var(--muted);font-size:11.5px}
svg .mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.key{display:flex;flex-wrap:wrap;gap:6px 18px;margin:10px 2px 0;color:var(--muted);font-size:13px}
.key span::before{content:"";display:inline-block;width:18px;height:3px;margin-right:6px;vertical-align:middle;background:var(--c)}
.procs{list-style:none;margin:0;padding:0}
.procs li{padding:10px 0;border-top:1px solid var(--rule)}
.procs li:first-child{border-top:0}
.procs .who{font-weight:650}.procs .cmd{display:block;margin:2px 0}
.procs .meta{color:var(--muted);font-size:13.5px}
table{border-collapse:collapse;width:100%;font-size:13.5px;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--rule);vertical-align:top}
th{font-weight:600;color:var(--muted)}
.op{font-weight:650}.op.CONNECT{color:var(--connect)}.op.ACCEPT{color:var(--accept)}
.op.LISTEN,.op.BIND{color:var(--listen)}.bad{color:var(--refused);font-weight:650}
dl.how{display:grid;grid-template-columns:minmax(150px,max-content) 1fr;gap:8px 20px;margin:0}
dl.how dt{font-weight:650}dl.how dd{margin:0;color:var(--ink)}
footer{margin-top:48px;color:var(--muted);font-size:13px}
@media (max-width:640px){header.hero{grid-template-columns:1fr}}
"""


def _e(s) -> str:
    return escape(str(s), quote=True)


def _short(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def _who(p: P.Proc) -> str:
    """'curl 610', or 'pid 500' when no record says what the process runs."""
    return f"{p.name} {p.pid}" if p.images or p.comm else f"pid {p.pid}"


def _n(k: int, one: str, many: str) -> str:
    return f"{k} {one if k == 1 else many}"


def _label(ctx, key) -> tuple[str, str]:
    p = ctx.tree.get(key)
    lin = ctx.tree.lineage(key)[1:]
    sub = ("child of " + " ← ".join(_who(a) for a in lin)) if lin else (p.origin if p.parent is None else "")
    return _who(p), sub


def _node(x, y, w, h, title, sub, colour) -> str:
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="5" fill="var(--panel)" stroke="{colour}" '
            f'stroke-width="1.5"/><rect x="{x}" y="{y}" width="5" height="{h}" rx="2" fill="{colour}"/>'
            f'<text x="{x + 14}" y="{y + 21}" font-weight="650">{_e(_short(title, 40))}</text>'
            f'<text x="{x + 14}" y="{y + 39}" class="sub">{_e(_short(sub, 48))}</text>')


def connection_map(ctx, rep: N.PortReport) -> str:
    """Left: who connected (processes on this host, and off-host peers). Middle: the port.
    Right: who listened and accepted. One edge per (client, outcome), labelled with its count."""
    left: dict = {}        # node id -> [title, sub, colour, count, outcome]
    for c in rep.accepted:
        if c.connect is None:
            nid = ("remote", c.accept.raddr)
            left.setdefault(nid, [c.accept.raddr, "off this host, or its connect isn't in the run", "var(--remote)", 0,
                                  "accepted"])[3] += 1
    for e in rep.outbound + rep.refused:
        nid = ("proc", e.proc, e.ok)
        t, s = _label(ctx, e.proc)
        left.setdefault(nid, [t, s, "var(--connect)" if e.ok else "var(--refused)", 0,
                              "connected" if e.ok else e.ret_text().split(" ")[0]])[3] += 1
    right: dict = {}
    for lst in rep.listeners:
        t, s = _label(ctx, lst.proc)
        right.setdefault(lst.proc, [t, s, "var(--accept)", 0, "listening"])
    for c in rep.accepted:
        t, s = _label(ctx, c.accept.proc)
        right.setdefault(c.accept.proc, [t, s, "var(--accept)", 0, "accepted"])[3] += 1
    rows = max(len(left), len(right), 1)
    W, RH, NW, NH = 1000, 66, 300, 50
    H = max(rows * RH + 40, 180)        # the port circle (r 62) always fits
    cx, cy = W / 2, H / 2
    out = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="Connection map for port {rep.port}">',
           '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
           'orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="context-stroke"/></marker></defs>']

    def ys(n):
        top = (H - n * RH) / 2
        return [top + i * RH + (RH - NH) / 2 for i in range(n)]

    for (nid, (t, s, col, n, outcome)), y in zip(left.items(), ys(len(left))):
        x1, y1 = 20 + NW, y + NH / 2
        dash = ' stroke-dasharray="6 5"' if col == "var(--refused)" else ""
        end = cx - 64
        out.append(f'<path d="M{x1},{y1} C{x1 + 130},{y1} {end - 70},{cy} {end},{cy}" fill="none" stroke="{col}" '
                   f'stroke-width="2"{dash} marker-end="url(#arr)"/>')
        out.append(f'<text x="{x1 + 10}" y="{y1 - 7}" class="sub">{_e(outcome)} ×{n}</text>')
        out.append(_node(20, y, NW, NH, t, s, col))
    for (key, (t, s, col, n, _)), y in zip(right.items(), ys(len(right))):
        x0, y0 = W - 20 - NW, y + NH / 2
        lbl = f"accepted ×{n}" if n else "listening"
        out.append(f'<path d="M{cx + 64},{cy} C{cx + 140},{cy} {x0 - 80},{y0} {x0},{y0}" fill="none" stroke="{col}" '
                   f'stroke-width="2" marker-end="url(#arr)"/>')
        out.append(f'<text x="{x0 - 10}" y="{y0 - 7}" class="sub" text-anchor="end">{_e(lbl)}</text>')
        out.append(_node(x0, y, NW, NH, t, s, col))
    ep = rep.listeners[0].endpoint if rep.listeners else f":{rep.port}"
    out.append(f'<circle cx="{cx}" cy="{cy}" r="62" fill="var(--panel)" stroke="var(--ink)" stroke-width="2.5"/>'
               f'<text x="{cx}" y="{cy + 2}" text-anchor="middle" font-size="26" font-weight="800">{rep.port}</text>'
               f'<text x="{cx}" y="{cy + 22}" text-anchor="middle" class="sub mono">{_e(_short(ep, 22))}</text>')
    if not left and not right:
        out.append(f'<text x="{cx}" y="{cy + 90}" text-anchor="middle" class="sub">nothing in this run names this port</text>')
    out.append("</svg>")
    return "".join(out)


MARK = {"CONNECT": "var(--connect)", "ACCEPT": "var(--accept)", "LISTEN": "var(--listen)", "BIND": "var(--listen)"}


def timeline(ctx, rep: N.PortReport, procs: list[P.Proc]) -> str:
    evs = rep.events
    if not evs:
        return '<p class="note">No events on this port.</p>'
    lanes = [p for p in procs if any(e.proc == p.key for e in evs)]
    t0, t1 = evs[0].ts_ns, evs[-1].ts_ns
    for p in lanes:
        if p.fork_ns is not None:
            t0 = min(t0, p.fork_ns)
        if p.exit_ns is not None:
            t1 = max(t1, p.exit_ns)
    span = max(t1 - t0, 1)
    t0 = max(t0 - span * 0.03, ctx.start_ns)
    t1 += span * 0.03
    span = t1 - t0
    W, LX, LH, TOP = 1000, 230, 34, 30
    H = TOP + len(lanes) * LH + 34

    def x(t):
        return LX + (W - LX - 20) * (t - t0) / span

    out = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="Timeline of port {rep.port}">']
    for i in range(6):
        t = t0 + span * i / 5
        anchor = "start" if i == 0 else "end" if i == 5 else "middle"
        out.append(f'<line x1="{x(t):.1f}" y1="{TOP - 8}" x2="{x(t):.1f}" y2="{H - 26}" stroke="var(--rule)"/>'
                   f'<text x="{x(t):.1f}" y="{H - 10}" text-anchor="{anchor}" class="sub">{_e(ctx.rel(int(t)))}</text>')
    ylane = {}
    for i, p in enumerate(lanes):
        y = TOP + i * LH + LH / 2
        ylane[p.key] = y
        a = x(p.fork_ns) if p.fork_ns is not None and p.fork_ns >= t0 else LX
        b = x(p.exit_ns) if p.exit_ns is not None else W - 20
        out.append(f'<text x="{LX - 12}" y="{y + 4}" text-anchor="end">{_e(_short(p.name, 18))} '
                   f'<tspan class="sub">{p.pid}</tspan></text>'
                   f'<line x1="{a:.1f}" y1="{y}" x2="{b:.1f}" y2="{y}" stroke="var(--life)" stroke-width="8" '
                   f'stroke-linecap="round"><title>{_e(p.cmdline)}: {_e(p.exit_text())}</title></line>')
    for c in rep.accepted:
        if c.connect and c.connect.proc in ylane:
            out.append(f'<line x1="{x(c.connect.ts_ns):.1f}" y1="{ylane[c.connect.proc]}" x2="{x(c.accept.ts_ns):.1f}" '
                       f'y2="{ylane[c.accept.proc]}" stroke="var(--accept)" stroke-width="1.5" stroke-dasharray="3 3"/>')
    for e in evs:
        cx_, cy_ = x(e.ts_ns), ylane[e.proc]
        tip = f"{e.op} {e.local} → {e.remote} {e.ret_text()} at {ctx.when(e.ts_ns)}"
        if not e.ok:
            out.append(f'<g stroke="var(--refused)" stroke-width="3"><title>{_e(tip)}</title>'
                       f'<line x1="{cx_ - 6}" y1="{cy_ - 6}" x2="{cx_ + 6}" y2="{cy_ + 6}"/>'
                       f'<line x1="{cx_ - 6}" y1="{cy_ + 6}" x2="{cx_ + 6}" y2="{cy_ - 6}"/></g>')
        elif e.op == "ACCEPT":
            out.append(f'<rect x="{cx_ - 6}" y="{cy_ - 6}" width="12" height="12" fill="{MARK[e.op]}"><title>{_e(tip)}'
                       '</title></rect>')
        elif e.op == "CONNECT":
            out.append(f'<circle cx="{cx_}" cy="{cy_}" r="6.5" fill="{MARK[e.op]}"><title>{_e(tip)}</title></circle>')
        else:
            out.append(f'<path d="M{cx_},{cy_ - 8}L{cx_ + 8},{cy_}L{cx_},{cy_ + 8}L{cx_ - 8},{cy_}z" fill="{MARK[e.op]}">'
                       f'<title>{_e(tip)}</title></path>')
    out.append("</svg>")
    return "".join(out)


def render(ctx, rep: N.PortReport) -> str:
    from .trace import involved   # the same process list as the text form

    m = ctx.run.meta
    procs = involved(ctx, rep)
    verdict = ctx.verdict()
    state = "var(--connect)"
    if ctx.end is None or ctx.end.f["run_state"] == 2 or not ctx.net_on:
        state = "var(--refused)"
    elif ctx.end.f["run_state"] == 1 or ctx.tree.gaps:
        state = "var(--listen)"
    who = ", ".join(sorted({_who(ctx.tree.get(lst.proc)) for lst in rep.listeners}))
    clients = sum(1 for c in rep.accepted if c.connect)
    lede = (f"{_e(who)} listened here. " if who else "No process listened here in this run. ") + \
        (f"{_n(len(rep.accepted), 'connection was', 'connections were')} accepted, {clients} of them from a process on "
         f"this host. " if rep.accepted else "") + \
        f"{_n(len(rep.outbound), 'connect', 'connects')} to the port succeeded and {len(rep.refused)} failed."
    if not rep.events:
        lede = "Nothing in this run names this port."
    rows = []
    for e in rep.events:
        p = ctx.tree.get(e.proc)
        rows.append(f'<tr><td>{_e(ctx.wall(e.ts_ns))}<br><span class="sub">{_e(ctx.rel(e.ts_ns))}</span></td>'
                    f'<td class="op {e.op}">{e.op.lower()}</td><td>{_e(e.proto)}</td>'
                    f'<td class="ep">{_e(e.local)}</td><td class="ep">{_e(e.remote if e.op in ("CONNECT", "ACCEPT") else "—")}</td>'
                    f'<td class="{"" if e.ok else "bad"}">{_e(e.ret_text())}</td>'
                    f'<td>{_e(_who(p))}</td><td>{e.cookie}{(" ← " + str(e.peer_cookie)) if e.peer_cookie else ""}'
                    f'</td></tr>')
    plist = []
    for p in procs:
        life = (f"started {ctx.rel(p.fork_ns)}" if p.fork_ns is not None else p.origin) + "; " + p.exit_text() + \
            (f" at {ctx.rel(p.exit_ns)}" if p.exit_ns is not None else "")
        parent = ""
        if p.parent is not None:
            pp = ctx.tree.get(p.parent)
            parent = f"; child of {_who(pp)}"
        gap = "; alive during a GAP window, so some of its records may be missing" if p.in_gap else ""
        plist.append(f'<li><span class="who">{_e(p.name if p.images or p.comm else "unknown program")} '
                     f'<span class="meta">pid {p.pid}</span></span>'
                     f'<code class="cmd">{_e(p.cmdline if p.images else "(no program recorded)")}</code>'
                     f'<span class="meta">{_e(life + parent + gap)}</span></li>')
    c, t = rep.counts, ctx.tree.counts
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Port {rep.port} trace</title><style>{CSS}</style></head>
<body><main>
<header class="hero">
  <div class="port"><small>Port</small>{rep.port}</div>
  <p class="lede">{lede}</p>
  <p class="run">Run <code>{_e(m['run.id'])}</code> on {_e(m['hostname'])}, kernel {_e(m['kernel.release'])},
  captured from {_e(ctx.wall(ctx.start_ns))} UTC. Times are UTC, and t+ is from the start of the capture.</p>
</header>
<section class="trust" style="--state:{state}">
  <p class="head">{_e(verdict[0])}</p>{"".join(f"<p>{_e(v)}</p>" for v in verdict[1:])}
</section>

<h2>Connection map</h2>
<p class="note">Who connected, on the left; who listened and accepted, on the right. A dashed red edge is a
connect that failed.</p>
<div class="panel">{connection_map(ctx, rep)}</div>
<div class="key"><span style="--c:var(--connect)">connect</span><span style="--c:var(--accept)">accept</span>
<span style="--c:var(--listen)">listen or bind</span><span style="--c:var(--refused)">failed</span>
<span style="--c:var(--remote)">peer off this host</span></div>

<h2>Timeline</h2>
<p class="note">One lane per process, drawn from its start to its exit. Diamonds are listens and binds, circles
connects, squares accepts, and crosses failures. A dotted line joins a connect to the accept it became.</p>
<div class="panel">{timeline(ctx, rep, procs)}</div>

<h2>Processes</h2>
<p class="note">Every process that touched the port, and its ancestors, in order of first appearance.</p>
<div class="panel"><ul class="procs">{"".join(plist) or "<li>none</li>"}</ul></div>

<h2>Events</h2>
<p class="note">Every NET record that names port {rep.port}. The cookie column gives the socket cookie, then
← the listener's cookie for an accept.</p>
<div class="panel"><table><thead><tr><th>Time</th><th>Op</th><th>Proto</th><th>Local</th><th>Remote</th>
<th>Result</th><th>Process</th><th>Cookie</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>

<h2>How this was put together</h2>
<div class="panel"><dl class="how">
<dt>Listener to accept</dt><dd>By socket cookie, which is exact (ADR-0004 rule 5): an accept's peer cookie is
its listener's cookie.</dd>
<dt>Client to accept</dt><dd>Exact when both sides carry the TCP client sequence number (ADR-0022): the
connect and the accept with the same endpoints and the same number are one connection.
{c['client_by_isn']} matched that way. Otherwise by endpoints, which is an inference: a connect on this host whose
local endpoint is the accept's remote one, nearest in time within {N.JOIN_WINDOW_NS // 10**9} s on either side.
{c['client_by_endpoints']} matched that way, {c['endpoint_ambiguous']} of them with more than one candidate.
{c['isn_mismatch']} same-endpoint connect(s) were set aside as a different connection, {c['connect_after_accept']}
connect(s) returned after their accept, {c['client_not_found']} accept(s) have no client here, and
{c['tcp_without_isn']} TCP record(s) carry no sequence number.</dd>
<dt>Process identity</dt><dd>(tgid, the thread-group leader's start time), within this boot (ADR-0009). The
run holds {len(ctx.tree.procs)} processes. {t['pre_existing']} of them started before the capture, so their
parents are unknown until the start-up snapshot (Phase 1 step 4c). The ADR-0009 checks found
{t['exit_twice']} double exits and {t['fork_twice']} double forks; both must be 0.</dd>
</dl></div>
<footer>Made by p15-trace (Fiery Dragon) from the run's WAL. Nothing on this page is estimated except the
client-by-endpoints join, which is labelled where it is used.</footer>
</main></body></html>
"""
