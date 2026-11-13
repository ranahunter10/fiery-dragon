#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cases 16 and 17 of it_p15d.sh: vfs calls still open when the flow programs detach
(bpf/include/p15_flow.h; docs/research/2026-11-13-detach-fault-design.md).

    it_flow_open.py hold OUTDIR          start three children, each blocked in one call, write
                                         OUTDIR/c16-hold.json (their pids), and wait. On SIGUSR1
                                         the read child's pipe is fed READ_SZ bytes, so its read
                                         returns, and a fourth child starts a read that blocks
                                         (a call that enters after the gate has shut); on SIGTERM
                                         the children are killed.
    it_flow_open.py check RUNDIR OUTDIR MODE
                                         MODE held: the three calls were open at the end;
                                         MODE released: one of them returned after the count.
                                         Prints one "ok"/"FAIL" line per check.

The three children, started while p15d is capturing so that each call's entry is seen:
  - read:   read(2) on an empty pipe (vfs_read);
  - write:  write(2) on a pipe that is full (vfs_write);
  - readv:  readv(2) on an empty pipe (vfs_readv).
On Linux 7.0 a call inside one of these when its kprobe.session is detached never runs its return,
so before the fix book B1 broke by one for each. Harmless calls only: pipes of this process.
"""
import fcntl
import json
import os
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))

READ_SZ = 4201          # what the released read returns: a size of its own, so its FLOW is found


def child(fn) -> int:
    pid = os.fork()
    if pid == 0:
        try:
            fn()
        finally:
            os._exit(0)
    return pid


def hold(out: Path) -> int:
    r1, w1 = os.pipe()                 # the read child blocks on r1; this process keeps w1
    r2, w2 = os.pipe()                 # the write child blocks on w2; this process keeps r2 and never reads
    r3, w3 = os.pipe()                 # the readv child blocks on r3; this process keeps w3
    r4, w4 = os.pipe()                 # the late child blocks on r4, entering after the gate has shut
    fl = fcntl.fcntl(w2, fcntl.F_GETFL)
    fcntl.fcntl(w2, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    try:
        while True:
            os.write(w2, b"f" * 4096)  # fill the pipe: these writes return, and are FLOWs of this process
    except BlockingIOError:
        pass
    fcntl.fcntl(w2, fcntl.F_SETFL, fl)
    pids = {"read": child(lambda: os.read(r1, READ_SZ)),
            "write": child(lambda: os.write(w2, b"w" * 4096)),
            "readv": child(lambda: os.readv(r3, [bytearray(64)]))}
    released = []

    def release(*_):
        if not released:
            released.append(os.write(w1, b"r" * READ_SZ))
            pids["late"] = child(lambda: os.read(r4, 1))

    def stop(*_):
        for p in pids.values():
            try:
                os.kill(p, signal.SIGKILL)
            except ProcessLookupError:
                pass
        os._exit(0)

    signal.signal(signal.SIGUSR1, release)
    signal.signal(signal.SIGTERM, stop)
    time.sleep(0.5)                    # the three children are inside their calls before the file says so
    (out / "c16-hold.json").write_text(json.dumps({"pids": pids, "holder": os.getpid()}))
    while True:
        signal.pause()


def check(rundir: Path, out: Path, mode: str) -> int:
    from p15 import records as R
    from p15 import wal

    bad = 0

    def say(ok: bool, what: str) -> None:
        nonlocal bad
        bad += not ok
        print(f"{'ok' if ok else 'FAIL'} {what}")

    pids = json.loads((out / "c16-hold.json").read_text())["pids"]
    run = wal.read_run(rundir)
    stats = [x for x in run.ring_records(2) if x.name == "FLOW_STATS"]
    say(bool(stats), "FLOW_STATS records are written")
    if not stats:
        return 1
    s = stats[-1].f
    want = 3                # all three were open at the count, whatever returned after it
    say(s["open_at_end"] >= want, f"the end's count found the held calls open (open_at_end {s['open_at_end']} >= {want})")
    say((s["v_release_failed"], s["v_claim_race"]) == (0, 0),
        f"no release failed and the iterator gave up on no task ({s['v_release_failed']}, {s['v_claim_race']})")
    say(s["v_no_slot_entry"] == 0 and s["v_no_slot_return"] == 0,
        f"every task had its slot ({s['v_no_slot_entry']} entries without one)")
    # book B1 itself is p15d's to check, on absolute counters (END's invariant, checked by the caller):
    # FLOW_STATS counts from the run's start, and a call that was open then returns inside the run
    reads = [x for x in run.ring_records(1) if x.name == "FLOW" and x.h["tgid"] == pids["read"]
             and x.f["kind"] == R.gen.FLOW_KIND_READ and x.f["bytes"] == READ_SZ]
    if mode == "held":
        say(not reads, "the held read has no FLOW: it never returned in the run")
    else:
        say(s["v_gated"] >= 1, f"a call that entered after the gate is counted, and opens nothing (v_gated {s['v_gated']} >= 1)")
        say(s["returned_after_count"] >= 1,
            f"the call released after the count is counted (returned_after_count {s['returned_after_count']} >= 1)")
        say(len(reads) == 1, f"  ... and its FLOW of {READ_SZ} bytes is in the WAL ({len(reads)})")
        if reads:
            say(reads[0].f["first_ts"] < reads[0].f["last_ts"] and not reads[0].f["fflags"] & R.gen.FF_START_UNKNOWN,
                "  ... with the start time of its entry, taken long before the count")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "hold":
        return hold(Path(argv[2]))
    if len(argv) == 5 and argv[1] == "check" and argv[4] in ("held", "released"):
        return check(Path(argv[2]), Path(argv[3]), argv[4])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
