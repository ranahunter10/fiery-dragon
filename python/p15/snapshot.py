# SPDX-License-Identifier: MIT
"""Process snapshots in a run (ADR-0007 rule 3, ADR-0023): the PROC records of each snapshot, its FD
rows (the open descriptors, ADR-0015 rule 7, SNAP_DONE v2) and its SNAP_DONE books.

p15d takes an opening snapshot at every segment open and, at an orderly stop, a closing one while
the hooks are still attached. Each is a set of live thread groups keyed (tgid, start_ns)
(ADR-0009), with the parent's key, the program's path and argv.

A snapshot is `complete` only when its books close exactly as p15d checked them
(daemon/snapshot_frame.c p15_snap_books_close) and every record it counted is here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import records as R

Key = tuple[int, int]


@dataclass
class Snapshot:
    snap_id: int
    kind: str                                   # "opening" or "closing"
    procs: dict[Key, R.Record] = field(default_factory=dict)
    done: R.Record | None = None
    duplicates: int = 0                         # PROC records with a key already seen in this snapshot
    fds: list[R.Record] = field(default_factory=list)   # FD rows, in the order written

    @property
    def start_ns(self) -> int | None:
        """When the iteration began: SNAP_DONE's time minus its duration."""
        return None if self.done is None else self.done.h["ts_ns"] - self.done.f["duration_ns"]

    @property
    def end_ns(self) -> int | None:
        return None if self.done is None else self.done.h["ts_ns"]

    def problems(self) -> list[str]:
        """Why this snapshot can't be used as a balance; empty when it is complete."""
        if self.done is None:
            return [f"snapshot {self.snap_id} ({self.kind}) has no SNAP_DONE: cut short"]
        d, out = self.done.f, []
        if d["error"]:
            out.append(f"reading the iterator failed ({d['error']})")
        if d["tasks"] != d["threads"] + d["emitted"] + d["write_failed"]:
            out.append(f"books open: tasks {d['tasks']} != threads {d['threads']} + emitted {d['emitted']} "
                       f"+ write_failed {d['write_failed']}")
        if d["emitted"] != d["entries"] + d["invalid"] + d["unwritten"]:
            out.append(f"books open: emitted {d['emitted']} != entries {d['entries']} + invalid {d['invalid']} "
                       f"+ unwritten {d['unwritten']}")
        if d["write_failed"] or d["invalid"] or d["unwritten"]:
            out.append(f"{d['write_failed']} not written by the program, {d['invalid']} invalid, "
                       f"{d['unwritten']} refused by the WAL")
        if d["entries"] != len(self.procs) + self.duplicates:
            out.append(f"SNAP_DONE counts {d['entries']} entries, the WAL holds {len(self.procs) + self.duplicates}")
        if self.duplicates:
            out.append(f"{self.duplicates} process(es) listed twice")
        if d.get("fd_pass"):
            if d["fd_error"]:
                out.append(f"reading the FD iterator failed ({d['fd_error']})")
            if d["fd_files"] != d["fd_no_inode"] + d["fd_emitted"] + d["fd_write_failed"]:
                out.append(f"FD books open: fd_files {d['fd_files']} != fd_no_inode {d['fd_no_inode']} + fd_emitted "
                           f"{d['fd_emitted']} + fd_write_failed {d['fd_write_failed']}")
            if d["fd_emitted"] != d["fd_entries"] + d["fd_invalid"] + d["fd_unwritten"]:
                out.append(f"FD books open: fd_emitted {d['fd_emitted']} != fd_entries {d['fd_entries']} + fd_invalid "
                           f"{d['fd_invalid']} + fd_unwritten {d['fd_unwritten']}")
            if d["fd_emitted"] != d["fd_known"] + d["fd_registered"] + d["fd_map_full"]:
                out.append(f"FD books open: fd_emitted {d['fd_emitted']} != fd_known {d['fd_known']} + fd_registered "
                           f"{d['fd_registered']} + fd_map_full {d['fd_map_full']}")
            if d["fd_write_failed"] or d["fd_invalid"] or d["fd_unwritten"]:
                out.append(f"FD rows: {d['fd_write_failed']} not written by the program, {d['fd_invalid']} invalid, "
                           f"{d['fd_unwritten']} refused by the WAL")
            if d["fd_entries"] != len(self.fds):
                out.append(f"SNAP_DONE counts {d['fd_entries']} FD rows, the WAL holds {len(self.fds)}")
        elif self.fds:
            out.append(f"{len(self.fds)} FD rows without an FD pass in SNAP_DONE")
        return [f"snapshot {self.snap_id} ({self.kind}): {x}" for x in out]

    @property
    def complete(self) -> bool:
        return not self.problems()


def collect(daemon_records) -> list[Snapshot]:
    """The snapshots of a run, in the order taken, from its daemon-ring records."""
    snaps: dict[int, Snapshot] = {}
    for r in daemon_records:
        if r.name not in ("PROC", "FD", "SNAP_DONE"):
            continue
        sid = r.f["snap_id"]
        if r.name == "FD":                      # FD rows carry no kind: the snapshot's PROC rows came first
            snaps.setdefault(sid, Snapshot(sid, "unknown")).fds.append(r)
            continue
        s = snaps.setdefault(sid, Snapshot(sid, R.SNAP_KINDS[r.f["kind"]]))
        s.kind = R.SNAP_KINDS[r.f["kind"]]
        if r.name == "PROC":
            if r.proc in s.procs:
                s.duplicates += 1
            else:
                s.procs[r.proc] = r
        else:
            s.done = r
    return [snaps[k] for k in sorted(snaps)]


def parent_key(p: R.Record) -> Key | None:
    """The parent's key from a PROC record; None for the kernel's own roots (parent tgid 0)."""
    return None if p.f["parent_tgid"] == 0 else (p.f["parent_tgid"], p.f["parent_start_ns"])


def is_kthread(p: R.Record) -> bool:
    return bool(p.f["pflags"] & R.PROC_KTHREAD)
