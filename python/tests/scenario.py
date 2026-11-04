# SPDX-License-Identifier: MIT
"""Test helper: a small synthetic p15d run with a known story, for the process tree, the port
query and the reports. Every value is chosen here; nothing comes from a real capture (real runs
are checked in CI and on the VM by it_p15d.sh case 5).

The story (times from the capture's start at boottime 1 s, 2026-11-02T10:00:00Z):
  bash (pid 500, started before the capture)
  ├─ python3 -m http.server 18077 (600): binds and listens on 127.0.0.1:18077 (cookie 9001)
  │    accepts 127.0.0.1:41000 (cookie 9003), 127.0.0.1:41002 (9005), 10.0.0.7:52000 (9006)
  │    └─ sh -c 'nc 127.0.0.1 4444' (630)
  │         └─ nc 127.0.0.1 4444 (640): connect to 127.0.0.1:4444 refused (ECONNREFUSED)
  ├─ curl http://127.0.0.1:18077/ (610): connect from 127.0.0.1:41000, exits 0
  └─ curl http://127.0.0.1:18077/x (620): connect from 127.0.0.1:41002, exits 0
"""

import socket
from pathlib import Path

from p15w_build import batch, header, meta_for, rec, write_run

S = 1_000_000_000
START = 1 * S
WALL = 1793613600 * S     # 2026-11-02T10:00:00Z
NETNS = 4026531840
BASH = (500, 100)


def _ip(a: str) -> bytes:
    fam = socket.AF_INET6 if ":" in a else socket.AF_INET
    return socket.inet_pton(fam, a).ljust(16, b"\0")


def fork(t, parent, child, kind=1):
    return rec("FORK", h_ts_ns=t, h_tgid=parent[0], h_tid=parent[0], h_start_ns=parent[1],
               child_tgid=child[0], child_tid=child[0], child_start_ns=child[1], child_task_start_ns=child[1], kind=kind)


def exe(t, p, path, argv):
    a = b"\0".join(x.encode() for x in argv) + b"\0"
    return rec("EXEC", var={"filename": path.encode(), "argv": a}, h_ts_ns=t, h_tgid=p[0], h_tid=p[0],
               h_start_ns=p[1], exe_ino=1000 + p[0], exe_dev=(8 << 20) | 1, old_tid=p[0])


def ren(t, p, old, new):
    return rec("RENAME", h_ts_ns=t, h_tgid=p[0], h_tid=p[0], h_start_ns=p[1], old_comm=old.encode(),
               new_comm=new.encode())


def ex(t, p, code=0):
    return rec("EXIT", h_ts_ns=t, h_tgid=p[0], h_tid=p[0], h_start_ns=p[1], exit_code=code, group_dead=1)


def net(t, p, op, cookie, local, remote="0.0.0.0:0", ret=0, peer=0, proto=6):
    la, lp = local.rsplit(":", 1)
    ra, rp = remote.rsplit(":", 1)
    return rec("NET", h_ts_ns=t, h_tgid=p[0], h_tid=p[0], h_start_ns=p[1], sock_cookie=cookie, peer_cookie=peer,
               laddr=_ip(la), raddr=_ip(ra), lport=int(lp), rport=int(rp), netns=NETNS, ret=ret,
               op={"CONNECT": 1, "ACCEPT": 2, "LISTEN": 3, "BIND": 4}[op], family=2, proto=proto)


SRV, C1, C2, SH, NC = (600, START + 500), (610, START + 2 * S), (620, START + 3 * S), (630, START + 4 * S), \
    (640, START + 4 * S + 10)


def build(d: Path, *, net_on=True, end=True, gap=False, skipped=0, stats_v1=False) -> Path:
    ms = 1_000_000
    spine = [
        fork(START + 500, BASH, SRV), exe(START + 600, SRV, "/usr/bin/python3", ["python3", "-m", "http.server", "18077"]),
        ren(START + 601, SRV, "bash", "python3"),
        fork(START + 2 * S, BASH, C1), exe(START + 2 * S + ms, C1, "/usr/bin/curl", ["curl", "http://127.0.0.1:18077/"]),
        ren(START + 2 * S + ms, C1, "bash", "curl"),
        fork(START + 3 * S, BASH, C2), exe(START + 3 * S + ms, C2, "/usr/bin/curl", ["curl", "http://127.0.0.1:18077/x"]),
        ex(START + 3 * S + 50 * ms, C1, 0),
        fork(START + 4 * S, SRV, SH), exe(START + 4 * S + 5, SH, "/bin/sh", ["sh", "-c", "nc 127.0.0.1 4444"]),
        fork(START + 4 * S + 10, SH, NC), exe(START + 4 * S + 20, NC, "/usr/bin/nc", ["nc", "127.0.0.1", "4444"]),
        ex(START + 4 * S + 30 * ms, NC, 1 << 8), ex(START + 4 * S + 31 * ms, SH, 1 << 8),
        ex(START + 3 * S + 60 * ms, C2, 0),
    ]
    bulk = [
        net(START + S, SRV, "BIND", 9001, "127.0.0.1:18077"),
        net(START + S + 1, SRV, "LISTEN", 9001, "127.0.0.1:18077"),
        net(START + 2 * S + 2 * ms, C1, "CONNECT", 9002, "127.0.0.1:41000", "127.0.0.1:18077"),
        net(START + 2 * S + 3 * ms, SRV, "ACCEPT", 9003, "127.0.0.1:18077", "127.0.0.1:41000", peer=9001),
        net(START + 3 * S + 2 * ms, C2, "CONNECT", 9004, "127.0.0.1:41002", "127.0.0.1:18077"),
        net(START + 3 * S + 3 * ms, SRV, "ACCEPT", 9005, "127.0.0.1:18077", "127.0.0.1:41002", peer=9001),
        net(START + 3 * S + 500 * ms, SRV, "ACCEPT", 9006, "127.0.0.1:18077", "10.0.0.7:52000", peer=9001),
        net(START + 4 * S + 25 * ms, NC, "CONNECT", 9007, "127.0.0.1:0", "127.0.0.1:4444", ret=-111),
    ] if net_on else []
    daemon = [rec("CLOCK_SYNC", h_ts_ns=START + 5 * S, boottime_ns=START + 5 * S, monotonic_ns=START + 5 * S,
                  realtime_ns=WALL + 5 * S)]
    if gap:
        daemon.append(rec("GAP", h_ts_ns=START + 4 * S + 40 * ms, from_ns=START + 4 * S, to_ns=START + 4 * S + 40 * ms,
                          spine_seq=len(spine), exec_reserve_failed=2, exit_missed=1))
    if stats_v1:
        daemon.append(rec("STATS", version=1, h_ts_ns=START + 6 * S, run_state=0))
    else:
        daemon.append(rec("STATS", h_ts_ns=START + 6 * S, run_state=2 if skipped else 0, exec_missed=skipped))
    daemon.append(rec("NET_STATS", h_ts_ns=START + 6 * S, net_seen=len(bulk), net_emitted=len(bulk),
                      net_drained=len(bulk), net_written=len(bulk)))
    if end:
        daemon.append(rec("END", var={"reason": b"stop requested"}, h_ts_ns=START + 6 * S + 1, exit_code=0,
                          run_state=0, invariant=1))
    m = meta_for(**{"clock.boottime_ns": str(START), "clock.realtime_ns": str(WALL), "clock.monotonic_ns": str(START),
                    "config.net": "yes" if net_on else "no", "hostname": "p15-demo", "kernel.release": "7.0.0-38-generic",
                    "run.id": "20261102T100000Z-scenario"})
    seg = header(0, m) + batch(0, 0, spine) + (batch(1, 0, bulk) if bulk else b"") + batch(2, 0, daemon)
    return write_run(d, [seg])
