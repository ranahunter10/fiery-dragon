# SPDX-License-Identifier: MIT
"""The process tree of a run, from the spine records (ADR-0003, ADR-0009).

A process is (tgid, start_ns) within the run's boot (ADR-0009): the key every record header
carries, stable across exec. The tree is built from:

- FORK kind 1: a new process, whose parent is the header's process;
- EXEC: a new program image of the same process;
- RENAME: the comm after it (every exec renames);
- EXIT with group_dead = 1: the process ended (E-0066; one EXIT per thread, only the last one
  ends the process).

Nothing is guessed: a process whose FORK the run doesn't hold (it started before the capture,
or its FORK was lost in a GAP) has `parent = None`, and `origin` says which of the two it is.
The bpf_iter snapshot (step 4c) will give pre-existing processes their parents. Every case the
builder can't place is counted in `Tree.counts`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import records as R

Key = tuple[int, int]   # (tgid, start_ns)


@dataclass
class Image:
    ts_ns: int
    filename: str
    argv: list[str]
    truncated: bool
    exe: tuple[int, int, int]     # (major, minor, inode) of the file that was executed


@dataclass
class Proc:
    key: Key
    parent: Key | None = None
    fork_ns: int | None = None             # when the FORK that made it ran
    images: list[Image] = field(default_factory=list)
    comm: str | None = None                # the last comm seen
    exit_ns: int | None = None
    exit_code: int | None = None           # the wait status (task->exit_code)
    children: list[Key] = field(default_factory=list)
    origin: str = "forked in the run"
    in_gap: bool = False                   # alive during a GAP window: records may be missing

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


def build(recs, run_start_ns: int | None = None) -> Tree:
    """Build the tree from records in ring order (spine) or time order. `run_start_ns`: the
    capture's start (the first record's time if None): a process with no FORK whose start_ns is
    before it started before the capture."""
    counts = dict.fromkeys(("fork_process", "fork_thread", "exec", "rename", "exit_thread", "exit_process",
                            "exit_twice", "fork_twice", "placeholder", "pre_existing", "fork_missing"), 0)
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
                bool(r.h["flags"] & R.F_TRUNCATED), (k0, k1, r.f["exe_ino"])))
        elif n == "RENAME":
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
    for p in procs.values():
        if p.fork_ns is not None:
            continue
        if start is not None and p.key[1] < start:
            p.origin = "started before the capture (its parent comes with the snapshot, step 4c)"
            counts["pre_existing"] += 1
        else:
            p.origin = "started during the run, but its FORK is not in the run"
            counts["fork_missing"] += 1
    for p in procs.values():
        born = p.key[1]
        died = p.exit_ns if p.exit_ns is not None else float("inf")
        p.in_gap = any(g.from_ns <= died and born <= g.to_ns for g in gaps)
    return Tree(procs, gaps, counts)
