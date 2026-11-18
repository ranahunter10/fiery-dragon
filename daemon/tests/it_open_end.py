#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cases 18 and 19 of it_p15d.sh: opens in flight when the open path's session detaches
(bpf/include/p15_file.h; docs/research/2026-11-14-open-session-end-count.md).

    it_open_end.py hold OUTDIR NAME      write OUTDIR/NAME.pid, then wait. On SIGUSR1 open three
                                         files and keep them open (then mkdir OUTDIR/NAME.opened);
                                         on SIGUSR2 open two more (then mkdir OUTDIR/NAME.late);
                                         on SIGTERM exit.
    it_open_end.py check RUNDIR OUTDIR NAME MODE
                                         MODE lost:    the three opens were counted at the end;
                                         MODE claimed: they were counted and their returns ran
                                                       after the count; the two late opens were
                                                       gated, and still have their OPEN records.
                                         Prints one "ok"/"FAIL" line per check.

No task can be held inside security_file_open from user space (on 7.0 it is the LSM hooks and
nothing that waits), so the two states are staged by p15d's test switch for this process alone
(--test-open-end-mode with --test-open-end-tgid, bpf/include/p15_file.h P15_TEST_OPEN_*):
  mode 1 (lost):    the session's entry marks the open and asks for no return, which is what a
                    detach in flight leaves behind. The end's iterator must count it.
  mode 2 (claimed): the entry marks the open as already counted by the iterator, so its return
                    runs the returned-after-the-count branch.
Under mode 1 an open of this process that is closed again leaves the map with its mark, which is a
return lost for good and breaks the book, as it should. So between SIGUSR1 and the end this
process opens nothing but the three files and closes nothing: its markers are directories.
"""
import os
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))

FIRST = ("open-end-a", "open-end-b", "open-end-c")
LATE = ("open-end-late-a", "open-end-late-b")


def hold(out: Path, name: str) -> int:
    kept = []
    paths = {n: str(out / f"{name}.{n}").encode() for n in FIRST + LATE}
    opened, late, done = str(out / f"{name}.opened"), str(out / f"{name}.late"), []

    def first(*_):
        if not kept:
            for n in FIRST:
                kept.append(os.open(paths[n], os.O_WRONLY | os.O_CREAT, 0o600))
            os.mkdir(opened)

    def later(*_):
        if not done:
            for n in LATE:
                kept.append(os.open(paths[n], os.O_WRONLY | os.O_CREAT, 0o600))
            done.append(1)
            os.mkdir(late)

    signal.signal(signal.SIGUSR1, first)
    signal.signal(signal.SIGUSR2, later)
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    (out / f"{name}.pid").write_text(str(os.getpid()))     # before p15d starts: not an open it sees
    while True:
        signal.pause()


def check(rundir: Path, out: Path, name: str, mode: str) -> int:
    from p15 import wal

    bad = 0

    def say(ok: bool, what: str) -> None:
        nonlocal bad
        bad += not ok
        print(f"{'ok' if ok else 'FAIL'} {what}")

    me = int((out / f"{name}.pid").read_text())
    run = wal.read_run(rundir)
    stats = [x for x in run.ring_records(2) if x.name == "FILE_STATS"]
    say(bool(stats) and stats[-1].h["version"] == 3, "FILE_STATS version 3 records are written")
    if not stats:
        return 1
    s = stats[-1].f
    opens = [x for x in run.ring_records(1) if x.name == "OPEN" and x.h["tgid"] == me]

    def named(names) -> int:
        return sum(1 for n in names if any(x.var["path"].rstrip(b"\0").endswith(f"{name}.{n}".encode()) for x in opens))

    say(named(FIRST) == 3, f"the three opens have their OPEN records ({named(FIRST)} of 3)")
    say(s["session_open_at_end"] >= 3,
        f"the end's count holds the three opens (session_open_at_end {s['session_open_at_end']} >= 3)")
    say((s["session_claim_race"], s["session_noslot_entry"], s["session_noslot_return"]) == (0, 0, 0),
        f"the iterator gave up on no entry and every open had its open-file entry ({s['session_claim_race']}, "
        f"{s['session_noslot_entry']}, {s['session_noslot_return']})")
    if mode == "lost":
        say(s["session_returned_after_count"] <= s["session_open_at_end"] - 3,
            f"none of the three returned (session_returned_after_count {s['session_returned_after_count']})")
    else:
        say(s["session_returned_after_count"] >= 3,
            f"their returns found the claim (session_returned_after_count {s['session_returned_after_count']} >= 3)")
        say(s["session_gated"] >= 2, f"the two opens after the gate were gated (session_gated {s['session_gated']} >= 2)")
        say(named(LATE) == 2, f"... and still have their OPEN records, from the path program ({named(LATE)} of 2)")
    return 1 if bad else 0


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "hold":
        return hold(Path(sys.argv[2]), sys.argv[3])
    if len(sys.argv) == 6 and sys.argv[1] == "check":
        return check(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5])
    print(__doc__, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main())
