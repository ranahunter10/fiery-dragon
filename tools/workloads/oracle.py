# SPDX-License-Identifier: MIT
"""The independent witness of a workload: what `strace -f -yy -ttt` saw, as facts to compare with
p15d's graph (tools/workloads/compare.py).

strace watches through ptrace, a mechanism p15d does not use, so a fact strace saw and the graph
lacks is a miss of the capture or the graph, never of a shared blind spot. strace is run by
tools/workloads/run.sh as

    strace -f -yy -qq -ttt -s 0 -e signal=none -e trace=<TRACE> -o strace.txt <workload>

and this module reads that file. Every line it cannot use is counted by reason (`counts`), never
silently skipped.

The facts, each keyed by the thread group (tgid) that made the call:
  procs     every thread group strace followed (tids are mapped to their group through the
            CLONE_THREAD clones strace saw)
  clones    (parent tgid, child tgid) for every process (not thread) a clone, fork or vfork made
  execs     (tgid, path as passed) for every execve/execveat that returned 0
  opens     (tgid, path) for every open/openat/openat2/creat that returned a descriptor, with the
            path strace resolved for it (-yy); O_PATH opens are kept apart (`opath`): the kernel
            never calls security_file_open for them (fs/open.c do_dentry_open), so no OPEN exists
  connects  (tgid, family, port, result) for AF_INET/AF_INET6 connects; AF_UNIX apart
  bytes     per tgid: bytes read and written on files, pipes and devices (read, pread64, readv,
            preadv, preadv2, write, pwrite64, writev, pwritev, pwritev2 with a result > 0) and
            received and sent on sockets (the same calls on a socket descriptor, and the recv/send
            families)
  unseen    calls that move data without vfs_read/vfs_write or the socket tracepoints, which the
            flow programs do not hook by design (sendfile, splice, tee, vmsplice, copy_file_range,
            io_uring_enter): counted with the bytes they reported, so a byte mismatch they explain
            is told apart from a capture miss
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

LINE = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+(.*)$")
CALL = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(.*)$")
RESUMED = re.compile(r"^<\.\.\. (\w+) resumed>(.*)$")
FD_DECOR = re.compile(r"^(-?\d+)<(.*)>$")

READS = {"read", "pread64", "readv", "preadv", "preadv2"}
WRITES = {"write", "pwrite64", "writev", "pwritev", "pwritev2"}
RECVS = {"recvfrom", "recvmsg", "recvmmsg"}
SENDS = {"sendto", "sendmsg", "sendmmsg"}
OPENS = {"open", "openat", "openat2", "creat"}
FORKS = {"clone", "clone3", "fork", "vfork"}
EXECS = {"execve", "execveat"}
UNSEEN = {"sendfile", "sendfile64", "splice", "tee", "vmsplice", "copy_file_range", "io_uring_enter"}
SOCK_PREFIX = ("TCP:", "TCPv6:", "UDP:", "UDPv6:", "UNIX", "NETLINK:", "socket:", "RAW:", "RAWv6:", "UDPLITE")

TRACE = ",".join(sorted(READS | WRITES | RECVS | SENDS | OPENS | FORKS | EXECS | UNSEEN
                        | {"connect", "accept", "accept4"}))
TRACE_LIGHT = ",".join(sorted(OPENS | FORKS | EXECS | {"connect", "accept", "accept4"}))


@dataclass
class Facts:
    root: int | None = None
    procs: set = field(default_factory=set)
    clones: set = field(default_factory=set)
    execs: set = field(default_factory=set)
    opens: set = field(default_factory=set)
    opath: set = field(default_factory=set)
    connects: list = field(default_factory=list)
    unix_connects: int = 0
    accepts: Counter = field(default_factory=Counter)
    bytes: dict = field(default_factory=lambda: defaultdict(Counter))   # tgid -> {file_read, file_write, sock_recv, sock_send}
    unseen: Counter = field(default_factory=Counter)                     # call -> number of calls
    unseen_bytes: Counter = field(default_factory=Counter)               # call -> bytes it reported
    counts: Counter = field(default_factory=Counter)                     # lines by what was done with them
    full: bool = False                                                    # read/write were traced


def split_first_arg(args: str) -> tuple[str, str]:
    """The first argument and the rest, splitting at the first ', ' outside <...>, [...], {...} and
    "...". Angle brackets inside [...] are not counted: a socket's '->' (TCP:[a:1->b:2]) is text."""
    square, angle, quote, i = 0, 0, False, 0
    while i < len(args):
        c = args[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == '"':
                quote = False
        elif c == '"':
            quote = True
        elif c in "[{":
            square += 1
        elif c in "]}":
            square -= 1
        elif c == "<" and square == 0:
            angle += 1
        elif c == ">" and square == 0:
            angle -= 1
        elif c == "," and square == 0 and angle == 0:
            return args[:i], args[i + 1:].lstrip()
        i += 1
    return args, ""


def fd_target(arg: str) -> str | None:
    """'3</tmp/x>' -> '/tmp/x'; '1</dev/null<char 1:3>>' -> '/dev/null'; '3<TCP:[...]>' -> 'TCP:[...]'."""
    m = FD_DECOR.match(arg.strip())
    if not m:
        return None
    t = m.group(2)
    dev = re.match(r"^(.*)<(?:char|block) \d+:\d+>$", t)
    return dev.group(1) if dev else t


def is_sock(target: str | None) -> bool:
    return target is not None and target.startswith(SOCK_PREFIX)


def calls(lines, f: Facts):
    """Yield (tid, name, args, ret, after) for every completed call, joining unfinished/resumed pairs."""
    pending: dict[int, tuple[str, str]] = {}
    for raw in lines:
        m = LINE.match(raw.rstrip("\n"))
        if not m:
            f.counts["line_unparsed"] += 1
            continue
        tid, rest = int(m.group(1)), m.group(3)
        if f.root is None:
            f.root = tid
        if rest.endswith("<unfinished ...>"):
            name = rest.split("(", 1)[0]
            pending[tid] = (name, rest[len(name) + 1:-len("<unfinished ...>")].rstrip())
            f.counts["unfinished"] += 1
            continue
        r = RESUMED.match(rest)
        if r:
            name, tail = r.group(1), r.group(2)
            p = pending.pop(tid, None)
            if p is None or p[0] != name:
                f.counts["resumed_without_start"] += 1
                continue
            rest = f"{name}({p[1]}{tail}"
        if rest.startswith("+++") or rest.startswith("---"):
            f.counts["exit_or_signal"] += 1
            continue
        c = CALL.match(rest)
        if not c:
            f.counts["call_unparsed"] += 1
            continue
        if c.group(3) == "?":
            f.counts["no_result"] += 1     # the call did not return (an exit, or an exec that replaced the thread)
            continue
        yield tid, c.group(1), c.group(2), int(c.group(3)), c.group(4)
    f.counts["unfinished_never_resumed"] += len(pending)


def parse(lines, light: bool = False) -> Facts:
    """Two passes: a child's first calls can be printed before its parent's clone returns, so the
    thread-to-group map is complete before any call is assigned to a group."""
    f = Facts(full=not light)
    evs = list(calls(lines, f))
    thread_of: dict[int, int] = {}            # thread tid -> the tid that created it
    for tid, name, args, ret, _ in evs:
        if name in FORKS and ret > 0 and "CLONE_THREAD" in args:
            thread_of[ret] = tid

    def group(tid: int) -> int:
        seen = set()
        while tid in thread_of and tid not in seen:
            seen.add(tid)
            tid = thread_of[tid]
        return tid

    if f.root is not None:
        f.procs.add(f.root)
    for tid, name, args, ret, after in evs:
        g = group(tid)
        f.procs.add(g)
        if name in FORKS:
            if ret <= 0:
                f.counts["fork_failed"] += 1
            elif "CLONE_THREAD" in args:
                f.counts["thread"] += 1
            else:
                f.procs.add(ret)
                if re.search(r"CLONE_PARENT(?![_A-Z])", args):
                    f.counts["clone_parent"] += 1   # its parent is the caller's parent: not compared as a pair
                else:
                    f.clones.add((g, ret))
            continue
        if name in EXECS:
            if ret == 0:
                path = re.match(r'^(?:\w+<[^>]*>,\s*)?"((?:[^"\\]|\\.)*)"', args)
                f.execs.add((g, path.group(1) if path else "?"))
            else:
                f.counts["exec_failed"] += 1
            continue
        if name in OPENS:
            if ret < 0:
                f.counts["open_failed"] += 1    # lookup and permission failures never reach security_file_open
                continue
            target = fd_target(f"{ret}{after.strip()}")
            if target is None:
                f.counts["open_undecorated"] += 1
                continue
            (f.opath if "O_PATH" in args else f.opens).add((g, target))
            continue
        if name == "connect":
            _, rest_args = split_first_arg(args)
            fam = re.search(r"sa_family=(AF_\w+)", rest_args)
            port = re.search(r"sin6?_port=htons\((\d+)\)", rest_args)
            if not fam or fam.group(1) not in ("AF_INET", "AF_INET6") or not port:
                f.unix_connects += 1
                continue
            err = re.search(r"^\s*(E[A-Z]+)", after)
            result = "ok" if ret == 0 else (err.group(1) if err else str(ret))
            f.connects.append((g, fam.group(1), int(port.group(1)), result))
            continue
        if name in ("accept", "accept4"):
            if ret >= 0:
                f.accepts[g] += 1
            continue
        if not f.full or ret <= 0:
            continue
        if name in UNSEEN:
            f.unseen[name] += 1
            f.unseen_bytes[name] += ret
            continue
        first, _ = split_first_arg(args)
        sock = is_sock(fd_target(first))
        if name in READS:
            f.bytes[g]["sock_recv" if sock else "file_read"] += ret
        elif name in WRITES:
            f.bytes[g]["sock_send" if sock else "file_write"] += ret
        elif name in ("recvmmsg", "sendmmsg"):
            f.counts["mmsg_call"] += 1          # the result is a number of messages, not bytes: not compared
        elif name in RECVS:
            f.bytes[g]["sock_recv"] += ret
        elif name in SENDS:
            f.bytes[g]["sock_send"] += ret
    return f


def load(path, light: bool = False) -> Facts:
    """strace's log, plain or gzipped (run.sh keeps it gzipped)."""
    import gzip
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", errors="backslashreplace") as fh:
        return parse(fh, light)
