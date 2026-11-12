# SPDX-License-Identifier: MIT
"""The process tree of a run, from the spine records (ADR-0003, ADR-0009).

A process is (tgid, start_ns) within the run's boot (ADR-0009): the key every record header
carries, stable across exec. The tree is built from:

- FORK kind 1: a new process, whose parent is the header's process;
- EXEC: a new program image of the same process;
- RENAME of the thread-group leader (tid = tgid): the process's comm after it (every exec renames,
  and an exec makes the execing thread the leader before it renames: fs/exec.c v7.0, de_thread
  before __set_task_comm). A rename of another thread names that thread only: counted
  (`rename_thread`) and left to the graph's `thread_name` table;
- EXIT with group_dead = 1: the process ended (E-0066; one EXIT per thread, only the last one
  ends the process).

- the opening process snapshot (ADR-0007 rule 3): every thread group alive when the capture
  began, with its parent's key, its program and argv. Those processes, whose FORK came before
  the capture, get their parent from it.

Nothing is guessed: a process whose FORK the run doesn't hold and that the opening snapshot
doesn't list either has `parent = None`, and `origin` says why. Every case the builder can't
place is counted in `Tree.counts`. The closing snapshot is for the reconciliation
(p15/reconcile.py, ADR-0023), which may repair a parent and says so in `origin`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import provenance as PV
from . import records as R
from . import snapshot as S

Key = tuple[int, int]   # (tgid, start_ns)


@dataclass
class Image:
    ts_ns: int
    filename: str
    argv: list[str]
    truncated: bool
    exe: tuple[int, int, int]     # (major, minor, inode) of the file that was executed
    seen_in: str = "exec"         # "exec": an EXEC record; "snapshot": what the opening snapshot showed
    backing: str = "disk"         # where the code came from (provenance.backing); "disk" for v1 records
    notes: list[str] = field(default_factory=list)   # provenance.unusual() for this image


@dataclass
class Proc:
    key: Key
    parent: Key | None = None
    fork_ns: int | None = None             # when the FORK that made it ran
    images: list[Image] = field(default_factory=list)
    comm: str | None = None                # the leader's last comm (a thread's own name is not the process's)
    exit_ns: int | None = None
    exit_code: int | None = None           # the wait status (task->exit_code)
    children: list[Key] = field(default_factory=list)
    origin: str = "forked in the run"
    in_gap: bool = False                   # alive during a GAP window: records may be missing
    kthread: bool = False                  # a kernel thread (from a snapshot)

    @property
    def pid(self) -> int:
        return self.key[0]

    @property
    def name(self) -> str:
        """What a person calls it: the last program's base name, else the comm, else '?'."""
        if self.images:
            return self.images[-1].filename.rsplit("/", 1)[-1] or self.images[-1].filename
        return self.comm or "?"

    @property
    def cmdline(self) -> str:
        if self.images and self.images[-1].argv:
            return " ".join(self.images[-1].argv) + (" …" if self.images[-1].truncated else "")
        return self.name

    def exit_text(self) -> str:
        if self.exit_ns is None:
            return "still running at the end of the run"
        st = self.exit_code
        if st & 0x7F == 0:
            return f"exited {st >> 8}"
        return f"killed by signal {st & 0x7F}" + (" (core dumped)" if st & 0x80 else "")


@dataclass
class Gap:
    from_ns: int
    to_ns: int
    lost: int


@dataclass
class Tree:
    procs: dict[Key, Proc]
    gaps: list[Gap]
    counts: dict[str, int]

    def lineage(self, key: Key) -> list[Proc]:
        """The process and its ancestors, nearest first, up to the first one with no known parent."""
        out, seen = [], set()
        k: Key | None = key
        while k is not None and k in self.procs and k not in seen:
            seen.add(k)
            out.append(self.procs[k])
            k = self.procs[k].parent
        return out

    def get(self, key: Key) -> Proc:
        """The process for a key, creating a placeholder for one with no spine record at all
        (it did nothing the spine records during the run, but a NET record names it)."""
        if key not in self.procs:
            self.procs[key] = Proc(key, origin="no spine record in the run")
            self.counts["placeholder"] += 1
        return self.procs[key]


def _snapshot_image(p: R.Record) -> Image | None:
    """A process's program as the snapshot saw it; None for a kernel thread or when nothing was read."""
    path = p.var["exe_path"].decode("utf-8", "backslashreplace")
    args = R.argv(p)
    if S.is_kthread(p) or (not path and not args):
        return None
    k0, k1 = R.kdev(p.f["exe_dev"])
    return Image(p.h["ts_ns"], path or (args[0] if args else ""), args, bool(p.h["flags"] & R.F_TRUNCATED),
                 (k0, k1, p.f["exe_ino"]), seen_in="snapshot", backing=PV.backing(p), notes=PV.unusual(p))


def build(recs, run_start_ns: int | None = None, opening: S.Snapshot | None = None) -> Tree:
    """Build the tree from records in ring order (spine) or time order. `run_start_ns`: the
    capture's start (the first record's time if None): a process with no FORK whose start_ns is
    before it started before the capture. `opening`: the run's first opening snapshot, whose
    processes join the tree with their parents and programs."""
    counts = dict.fromkeys(("fork_process", "fork_thread", "exec", "rename", "exit_thread", "exit_process",
                            "exit_twice", "fork_twice", "placeholder", "pre_existing", "fork_missing",
                            "from_snapshot", "pre_existing_unlisted", "rename_thread"), 0)
    procs: dict[Key, Proc] = {}
    gaps: list[Gap] = []
    first_ts = None

    def proc(k: Key) -> Proc:
        if k not in procs:
            procs[k] = Proc(k, origin="")
        return procs[k]

    for r in recs:
        if first_ts is None and r.ring == 0:
            first_ts = r.h["ts_ns"]
        n = r.name
        if n == "FORK":
            if r.f["kind"] != 1:
                counts["fork_thread"] += 1
                continue
            counts["fork_process"] += 1
            ck = (r.f["child_tgid"], r.f["child_start_ns"])
            c = proc(ck)
            if c.fork_ns is not None:
                counts["fork_twice"] += 1      # ADR-0009 falsifier: one key, two births
                continue
            c.parent, c.fork_ns = r.proc, r.h["ts_ns"]
            p = proc(r.proc)
            p.children.append(ck)
        elif n == "EXEC":
            counts["exec"] += 1
            k0, k1 = R.kdev(r.f["exe_dev"])
            proc(r.proc).images.append(Image(
                r.h["ts_ns"], r.var["filename"].decode("utf-8", "backslashreplace"), R.argv(r),
                bool(r.h["flags"] & R.F_TRUNCATED), (k0, k1, r.f["exe_ino"]),
                backing=PV.backing(r), notes=PV.unusual(r)))
        elif n == "RENAME":
            if r.h["tid"] != r.h["tgid"]:
                counts["rename_thread"] += 1     # a thread's name (prctl, /proc/.../comm), not the process's
                continue
            counts["rename"] += 1
            proc(r.proc).comm = R.comm(r.f["new_comm"])
        elif n == "EXIT":
            if not r.f["group_dead"]:
                counts["exit_thread"] += 1
                continue
            counts["exit_process"] += 1
            p = proc(r.proc)
            if p.exit_ns is not None:
                counts["exit_twice"] += 1      # ADR-0009 confirmation: never twice per key
                continue
            p.exit_ns, p.exit_code = r.h["ts_ns"], r.f["exit_code"]
        elif n == "GAP":
            # ring losses, and from GAP v2 on, events the kernel skipped (ADR-0020)
            lost = sum(v for k, v in r.f.items() if k.endswith(("_reserve_failed", "_build_failed", "_missed")))
            gaps.append(Gap(r.f["from_ns"], r.f["to_ns"], lost))
    start = run_start_ns if run_start_ns is not None else first_ts
    listed = opening.procs if opening is not None else {}
    for k, pr in listed.items():
        p = proc(k)
        p.kthread = S.is_kthread(pr)
        p.comm = p.comm or R.comm(pr.f["comm"])
        im = _snapshot_image(pr)
        if im is not None:
            p.images.insert(0, im)
            p.images.sort(key=lambda i: i.ts_ns)
        if p.fork_ns is None:
            p.parent = S.parent_key(pr)
            if p.parent is not None:
                proc(p.parent).children.append(k)
            p.origin = "started before the capture (parent and program from the opening snapshot)"
            counts["from_snapshot"] += 1
    for p in procs.values():
        if p.fork_ns is not None or p.key in listed:
            continue
        if start is not None and p.key[1] < start:
            p.origin = "started before the capture, and not in the opening snapshot"
            counts["pre_existing_unlisted"] += 1
        else:
            p.origin = "started during the run, but its FORK is not in the run"
            counts["fork_missing"] += 1
    counts["pre_existing"] = counts["from_snapshot"] + counts["pre_existing_unlisted"]
    for p in procs.values():
        born = p.key[1]
        died = p.exit_ns if p.exit_ns is not None else float("inf")
        p.in_gap = any(g.from_ns <= died and born <= g.to_ns for g in gaps)
    return Tree(procs, gaps, counts)
