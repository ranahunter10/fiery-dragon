# SPDX-License-Identifier: MIT
"""Network intent of a run (ADR-0004): the NET records, and what happened on one port.

Two joins, and each says which it is:

- **by cookie** (exact, ADR-0004 rule 5): an ACCEPT's peer_cookie is the listening socket's
  cookie, so every accepted connection names its listener;
- **by endpoints** (an inference): a CONNECT on this host whose local endpoint is an ACCEPT's
  remote endpoint, to the same address and port, in the same network namespace, within
  JOIN_WINDOW_NS of the accept on **either side**. Each record is stamped when its call
  returns, and the two calls finish concurrently: on the VM an accept returned 12 µs before its
  own connect (E-0092). Ports are reused, so the connect nearest in time is taken; a match whose
  connect came after the accept is counted, and the report labels every match as an inference.

A connect that failed (ret < 0, other than -EINPROGRESS) is a refusal, not a connection.
"""

from __future__ import annotations

import errno
from dataclasses import dataclass, field

from . import records as R

EINPROGRESS = errno.EINPROGRESS
PROTO = {6: "tcp", 17: "udp"}
# How far apart an accept and its connect may be stamped. A heuristic bound, not a guarantee: a reused port
# inside it is still a candidate, and then `endpoint_ambiguous` counts the accept (E-0092).
JOIN_WINDOW_NS = 5_000_000_000


@dataclass
class Event:
    """One NET record, flattened for queries and reports."""
    ts_ns: int
    op: str
    proto: str
    ret: int
    proc: tuple[int, int]
    tid: int
    cookie: int
    peer_cookie: int
    local: str
    remote: str
    lport: int
    rport: int
    laddr: str
    raddr: str
    netns: int
    seq: int

    @property
    def ok(self) -> bool:
        return self.ret == 0 or (self.op == "CONNECT" and self.ret == -EINPROGRESS)

    def ret_text(self) -> str:
        if self.ret == 0:
            return "ok"
        if self.ret == -EINPROGRESS:
            return "in progress (non-blocking)"
        name = errno.errorcode.get(-self.ret, f"errno {-self.ret}")
        return f"{name} ({self.ret})"


def event(r: R.Record) -> Event:
    return Event(r.h["ts_ns"], R.NET_OPS[r.f["op"]], PROTO.get(r.f["proto"], str(r.f["proto"])), r.f["ret"],
                 r.proc, r.h["tid"], r.f["sock_cookie"], r.f["peer_cookie"], R.endpoint(r, "l"),
                 R.endpoint(r, "r"), r.f["lport"], r.f["rport"], R.net_addr(r, "laddr"), R.net_addr(r, "raddr"),
                 r.f["netns"], r.seq)


@dataclass
class Listener:
    cookie: int
    proc: tuple[int, int]
    bind: Event | None
    listen: Event | None
    accepts: list["Conn"] = field(default_factory=list)

    @property
    def endpoint(self) -> str:
        return (self.listen or self.bind).local


@dataclass
class Conn:
    """An accepted connection, and the connect that made it if this host made it."""
    accept: Event
    listener: Listener | None
    connect: Event | None = None
    match: str = ""                 # how `connect` was found: "endpoints" or ""


@dataclass
class PortReport:
    port: int
    listeners: list[Listener]
    accepted: list[Conn]               # every accept on the port, joined
    outbound: list[Event]              # connects to the port, ok or in progress
    refused: list[Event]               # connects to the port that failed
    binds: list[Event]                 # binds to the port with no listen (UDP, or failed)
    other: list[Event]                 # anything else that names the port (e.g. a connect FROM it)
    counts: dict[str, int]

    @property
    def procs(self) -> set[tuple[int, int]]:
        ps = {lst.proc for lst in self.listeners}
        ps |= {c.accept.proc for c in self.accepted} | {c.connect.proc for c in self.accepted if c.connect}
        ps |= {e.proc for e in self.outbound + self.refused + self.binds + self.other}
        return ps

    @property
    def events(self) -> list[Event]:
        evs = {id(e): e for e in self.outbound + self.refused + self.binds + self.other}
        for lst in self.listeners:
            for e in (lst.bind, lst.listen):
                if e:
                    evs[id(e)] = e
        for c in self.accepted:
            evs[id(c.accept)] = c.accept
            if c.connect:
                evs[id(c.connect)] = c.connect
        return sorted(evs.values(), key=lambda e: (e.ts_ns, e.seq))


def port_report(events: list[Event], port: int) -> PortReport:
    """Everything the run holds about `port`: listeners on it, connections accepted on it (joined
    to their listener by cookie and to their client by endpoints), and connects to it."""
    counts = dict.fromkeys(("net_events", "accept_no_listener", "client_by_endpoints", "client_not_found",
                            "endpoint_ambiguous", "connect_after_accept"), 0)
    counts["net_events"] = len(events)
    by_cookie: dict[int, Listener] = {}
    for e in events:
        if e.op in ("BIND", "LISTEN") and e.lport == port and e.ok:
            lst = by_cookie.setdefault(e.cookie, Listener(e.cookie, e.proc, None, None))
            if e.op == "BIND":
                lst.bind = e
            else:
                lst.listen = e
    listeners = [lst for lst in by_cookie.values() if lst.listen]
    binds = [lst.bind for lst in by_cookie.values() if not lst.listen and lst.bind]
    binds += [e for e in events if e.op in ("BIND", "LISTEN") and e.lport == port and not e.ok]
    connects = [e for e in events if e.op == "CONNECT"]
    accepted: list[Conn] = []
    for e in events:
        if e.op != "ACCEPT":
            continue
        lst = by_cookie.get(e.peer_cookie)
        if not (e.lport == port or lst is not None and lst.listen and lst.listen.lport == port):
            continue
        if lst is None:
            counts["accept_no_listener"] += 1     # the listen came before the capture started
        c = Conn(e, lst)
        cands = [k for k in connects if k.ok and k.local == e.remote and k.remote == e.local
                 and k.netns == e.netns and abs(k.ts_ns - e.ts_ns) <= JOIN_WINDOW_NS]
        if cands:
            c.connect = min(cands, key=lambda k: (abs(k.ts_ns - e.ts_ns), k.seq))
            c.match = "endpoints"
            counts["client_by_endpoints"] += 1
            counts["endpoint_ambiguous"] += len(cands) > 1
            counts["connect_after_accept"] += c.connect.ts_ns > e.ts_ns
        else:
            counts["client_not_found"] += 1        # remote host, or a connect before the capture
        if lst is not None:
            lst.accepts.append(c)
        accepted.append(c)
    outbound = [e for e in connects if e.rport == port and e.ok]
    refused = [e for e in connects if e.rport == port and not e.ok]
    other = [e for e in events if e.lport == port and e.op == "CONNECT"]
    return PortReport(port, listeners, accepted, outbound, refused, binds, other, counts)
