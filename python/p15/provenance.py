# SPDX-License-Identifier: MIT
"""Code provenance (ADR-0025): where a program's code came from, and what its standard streams
are connected to, derived from the raw facts on an EXEC v2 or PROC v2 record.

No policy lives in the capture layer; the classes are derived here, in the reader, so a rule can
change without a new record version. Everything below is a function of the raw fields.
"""

from __future__ import annotations

from . import records as R

# Filesystem magic numbers (v7.0 include/uapi/linux/magic.h), low 32 bits of s_magic.
TMPFS = 0x01021994
HUGETLBFS = 0x958458F6
OVERLAYFS = 0x794C7630
PIPEFS = 0x50495045
SOCKFS = 0x534F434B

# i_mode file-type bits (S_IFMT = 0o170000).
S_IFMT = 0o170000
_KIND = {0o140000: "socket", 0o120000: "symlink", 0o100000: "file", 0o060000: "block",
         0o040000: "dir", 0o020000: "char", 0o010000: "pipe"}

# Mode permission bits.
_WOTH, _WGRP, _WUSR = 0o002, 0o020, 0o200


def stream_kind(mode: int) -> str:
    """The kind of a standard stream from its inode mode: socket, pipe, tty/char, file, ... or
    'closed' when the descriptor was closed (all fields zero)."""
    if mode == 0:
        return "closed"
    return _KIND.get(mode & S_IFMT, "other")


def backing(rec: R.Record) -> str:
    """Where the executable's code lives, from exe_nlink and exe_fs_magic (EXEC v2 / PROC v2):
    'memory' (memfd or an anonymous tmpfs/hugetlbfs file), 'deleted' (unlinked on a normal fs),
    'tmpfs', 'overlay' (a container upper/merged layer), or 'disk'. A kernel thread has no
    executable and returns 'none'."""
    magic = rec.f.get("exe_fs_magic", 0)
    nlink = rec.f.get("exe_nlink", 0)
    if rec.name == "PROC" and rec.f["pflags"] & R.PROC_KTHREAD:
        return "none"
    if magic in (TMPFS, HUGETLBFS):
        # the dentry name "memfd:<n>" (EXEC's exe_name) tells memfd from an ordinary tmpfs file
        name = rec.var.get("exe_name", b"") if rec.name == "EXEC" else b""
        return "memory" if nlink == 0 or name.startswith(b"memfd:") else "tmpfs"
    if nlink == 0:
        return "deleted"
    if magic == OVERLAYFS:
        return "overlay"
    return "disk"


def runner_can_write(rec: R.Record) -> bool:
    """True when the process could write its own executable: the file's write bits allow the
    process's fsuid/fsgid or others, not counting the ordinary root-owns-and-runs case. ACLs and
    capabilities are not considered (stated in ADR-0025)."""
    mode = rec.f.get("exe_mode", 0)
    if mode == 0:
        return False
    fsuid = rec.f["fsuid"]
    if mode & _WOTH:
        return True
    if (mode & _WUSR) and rec.f["exe_uid"] == fsuid and not (fsuid == 0 and rec.f["exe_uid"] == 0):
        return True
    if (mode & _WGRP) and rec.f["exe_gid"] == rec.f["fsgid"]:
        return True
    return False


def unusual(rec: R.Record) -> list[str]:
    """The provenance facts worth surfacing for one exec/process, most pointed first. Empty for an
    ordinary on-disk program with ordinary streams. This is description, not a verdict."""
    out: list[str] = []
    b = backing(rec)
    if b in ("memory", "deleted", "tmpfs", "overlay"):
        out.append({"memory": "runs from memory (no file on disk)", "deleted": "runs a deleted binary",
                    "tmpfs": "runs from a RAM filesystem", "overlay": "runs from a container layer"}[b])
    if runner_can_write(rec):
        out.append("executable is writable by its runner")
    euid = rec.f.get("euid")
    uid = rec.f.get("uid")
    if euid is not None and uid is not None and euid != uid:
        out.append(f"runs as a different user (uid {uid} -> euid {euid})")
    if rec.name == "EXEC":
        sin, sout = stream_kind(rec.f["stdin_mode"]), stream_kind(rec.f["stdout_mode"])
        if sin == "socket" and sout == "socket":
            out.append("stdin and stdout are a socket (a shell wired to the network)")
        elif sin == "socket":
            out.append("stdin is a socket")
        if sin == "pipe":
            out.append("stdin is a pipe (fed by another process)")
    return out


def pipe_links(execs) -> list[tuple[R.Record, R.Record]]:
    """Pairs (writer, reader) of EXEC records whose stdout and stdin are the same pipe inode: a
    producer piped into an interpreter, matched by identity (ADR-0025 rule 5). Both inodes must be
    non-zero pipes on the same device."""
    writers: dict[tuple[int, int], R.Record] = {}
    for e in execs:
        if stream_kind(e.f["stdout_mode"]) == "pipe" and e.f["stdout_ino"]:
            writers[(e.f["stdout_dev"], e.f["stdout_ino"])] = e
    out = []
    for e in execs:
        if stream_kind(e.f["stdin_mode"]) == "pipe" and e.f["stdin_ino"]:
            w = writers.get((e.f["stdin_dev"], e.f["stdin_ino"]))
            if w is not None and w is not e:
                out.append((w, e))
    return out
