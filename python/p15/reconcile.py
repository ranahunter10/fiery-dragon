# SPDX-License-Identifier: MIT
"""Reconcile the process tree against the run's closing snapshot (ADR-0023 rule 2).

Bookkeeping: the opening balance (the first opening snapshot) plus the transactions (FORK and
EXIT records) must equal the closing balance (the closing snapshot). Every process is keyed
(tgid, start_ns) (ADR-0009).

- Alive at the end (in the closing snapshot): it must be in the opening snapshot or have a FORK.
  Otherwise its FORK is lost: counted `fork_unexplained`, and the tree is repaired with the
  parent the closing snapshot gives, labelled as a repair.
- Gone by the end (in the opening snapshot, or forked before the closing snapshot began, and not
  in the closing one): it must have an EXIT. Otherwise `exit_unexplained`. A process forked once
  the closing snapshot had begun may simply have been missed by it, so it is set aside, counted.
- The counters must agree: each unexplained count is at most the losses the run counted for that
  record type (ring full, build failed, skipped by the kernel). More means a loss that nothing
  counted, and the run is INVALID.

Processes born and gone between two snapshots are outside this check (ADR-0023, consequences).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import proctree as P
from . import snapshot as S


@dataclass
class Reconciliation:
    verdict: str                     # "complete", "repaired" (losses located, within the counted ones),
                                     # "not possible", "INVALID"
    reasons: list[str] = field(default_factory=list)
    fork_unexplained: list[P.Key] = field(default_factory=list)
    exit_unexplained: list[P.Key] = field(default_factory=list)
    born_during_closing: int = 0     # set aside: forked after the closing snapshot began
    fork_losses: int | None = None   # counted by the run, from the last STATS
    exit_losses: int | None = None

    def line(self) -> str:
        """One line for the Trust block."""
        if self.verdict == "not possible":
            return "process tree check (ADR-0023): not possible: " + "; ".join(self.reasons)
        if self.verdict == "complete":
            head = "complete: every process alive at the end is explained, and every one gone has its exit"
        elif self.verdict == "INVALID":
            head = "INVALID: more unexplained processes than the run counted as lost"
        else:
            parts = []
            if self.fork_unexplained:
                parts.append(f"{len(self.fork_unexplained)} lost FORK(s) located, parents repaired from the closing snapshot")
            if self.exit_unexplained:
                parts.append(f"{len(self.exit_unexplained)} lost EXIT(s) located to their processes (when is unknown)")
            head = "repaired: " + "; ".join(parts)
        tail = (f" ({len(self.fork_unexplained)} fork(s) and {len(self.exit_unexplained)} exit(s) unexplained; "
                f"counted losses: fork {self.fork_losses}, exit {self.exit_losses})")
        return "process tree check (ADR-0023): " + head + tail + ("; " + "; ".join(self.reasons) if self.reasons else "")


def _losses(stats, kind: str) -> int | None:
    """Losses the run counted for one spine type, from the last STATS (v2 has the kernel's skips)."""
    if stats is None:
        return None
    f = stats.f
    n = f[f"{kind}_reserve_failed"] + f[f"{kind}_build_failed"]
    if stats.h["version"] >= 2:
        n += f[f"{kind}_missed"]
    return n


def reconcile(tree: P.Tree, snapshots: list[S.Snapshot], stats, end) -> Reconciliation:
    """Check `tree` (built with the first opening snapshot) against the closing snapshot. `stats` is
    the run's last STATS record and `end` its END record (or None). Repairs the tree in place."""
    opening = next((s for s in snapshots if s.kind == "opening"), None)
    closing = next((s for s in reversed(snapshots) if s.kind == "closing"), None)
    why = []
    if end is None:
        why.append("the run did not end in order (no END), so there is no closing snapshot")
    elif end.h["version"] < 2:
        why.append("this run predates ADR-0023: no closing snapshot was taken")
    elif end.f["closing_snapshot"] != 1:
        why.append(f"END says the closing snapshot was not taken ({end.f['closing_snapshot']})")
    if opening is None:
        why.append("no opening snapshot")
    if closing is None and not why:
        why.append("END says the closing snapshot was taken, but it is not in the run")
    for s in (opening, closing):
        if s is not None:
            why += s.problems()
    if why:
        return Reconciliation("not possible", why)

    fork_l, exit_l = _losses(stats, "fork"), _losses(stats, "exit")
    rec = Reconciliation("complete", fork_losses=fork_l, exit_losses=exit_l)
    began = closing.start_ns
    for k, pr in closing.procs.items():
        p = tree.procs.get(k)
        if k in opening.procs or (p is not None and p.fork_ns is not None):
            continue
        rec.fork_unexplained.append(k)
        p = tree.get(k)
        p.parent = S.parent_key(pr)
        if p.parent is not None:
            tree.get(p.parent).children.append(k)
        p.origin = "its FORK is missing: parent repaired from the closing snapshot (ADR-0023)"
    for k, p in tree.procs.items():
        if k in closing.procs:
            continue
        if k not in opening.procs and p.fork_ns is None:
            continue                                  # neither balance nor transaction names it
        if p.fork_ns is not None and p.fork_ns >= began:
            rec.born_during_closing += 1
            continue
        if p.exit_ns is None:
            rec.exit_unexplained.append(k)
    if fork_l is None or exit_l is None:
        rec.reasons.append("no STATS record: the counted losses are unknown")
    over = []
    if fork_l is not None and len(rec.fork_unexplained) > fork_l:
        over.append(f"{len(rec.fork_unexplained)} forks unexplained but {fork_l} counted lost")
    if exit_l is not None and len(rec.exit_unexplained) > exit_l:
        over.append(f"{len(rec.exit_unexplained)} exits unexplained but {exit_l} counted lost")
    if over:
        rec.verdict = "INVALID"
        rec.reasons += over
    elif rec.fork_unexplained:
        rec.verdict = "repaired"
    elif rec.exit_unexplained:
        rec.verdict = "repaired"
    return rec
