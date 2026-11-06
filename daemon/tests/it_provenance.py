#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Case 6 of it_p15d.sh: code provenance in a real run (ADR-0025 confirmation 2).

    it_provenance.py workload OUTDIR     while p15d runs: start the programs below, write
                                         OUTDIR/c6-expect.json with what their records must say
    it_provenance.py check RUNDIR OUTDIR read the run, print one "ok"/"FAIL" line per check

The workload, all with argv[0] markers so the checks find their own records and nothing else:
  - p15-it-memfd:   /bin/true's bytes copied into a memfd and executed from it;
  - p15-it-streams: /bin/true with stdin a pipe, stdout a regular file, stderr a socket;
  - p15-it-writer | p15-it-reader: /bin/echo piped into /bin/cat;
  - p15-it-live:    /bin/sleep, still running at p15d's closing snapshot (its pid is in
                    OUTDIR/c6-live.pid; the caller kills it after p15d stops).
Expected identities come from fstat(2) of the same objects, devices in the kernel's encoding.
"""
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))
from p15 import provenance as PV  # noqa: E402
from p15 import snapshot as SN  # noqa: E402
from p15 import trace  # noqa: E402
from p15 import wal  # noqa: E402

S_IFMT, S_IFIFO, S_IFREG, S_IFSOCK = 0o170000, 0o010000, 0o100000, 0o140000
# the facts PROC v2 and EXEC v2 share for one process (ADR-0025 rule 6)
SHARED = ("exe_ino", "exe_dev", "exe_gen", "exe_nlink", "exe_fs_magic", "exe_mode", "exe_uid", "exe_gid",
          "exe_ctime_ns", "exe_mtime_ns", "uid", "euid", "gid", "egid", "fsuid", "fsgid", "self_exec_id")


def kdev(d: int) -> int:
    return os.major(d) << 20 | os.minor(d)


def ident(fd: int) -> dict:
    st = os.fstat(fd)
    return {"ino": st.st_ino, "dev": kdev(st.st_dev), "mode": st.st_mode}


def workload(out: Path) -> None:
    exp: dict = {}
    # the live process first, so it is certainly running when the closing snapshot is taken
    live = subprocess.Popen(["p15-it-live", "30"], executable="/bin/sleep", start_new_session=True)
    (out / "c6-live.pid").write_text(str(live.pid))

    # exec from memory: the child execs its memfd (no CLOEXEC: the kernel reads the ELF by fd)
    try:
        noexec = Path("/proc/sys/vm/memfd_noexec").read_text().strip()
    except OSError:
        noexec = "absent"
    exp["memfd_noexec"] = noexec
    pid = os.fork()
    if pid == 0:
        try:
            fd = os.memfd_create("p15-it", 0)
            os.write(fd, Path("/bin/true").read_bytes())
            os.execve(fd, ["p15-it-memfd"], {})
        finally:
            os._exit(127)
    _, st = os.waitpid(pid, 0)
    exp["memfd_exit"] = os.waitstatus_to_exitcode(st)

    # the three stream kinds on one exec
    r, w = os.pipe()
    f = open(out / "c6-stdout", "wb")
    s1, s2 = socket.socketpair()
    exp["streams"] = {"stdin": ident(r), "stdout": ident(f.fileno()), "stderr": ident(s1.fileno())}
    p = subprocess.Popen(["p15-it-streams"], executable="/bin/true", stdin=r, stdout=f, stderr=s1)
    exp["streams_exit"] = p.wait()
    for x in (r, w):
        os.close(x)
    f.close(); s1.close(); s2.close()

    # a producer piped into a reader
    wr = subprocess.Popen(["p15-it-writer", "p15"], executable="/bin/echo", stdout=subprocess.PIPE)
    rd = subprocess.Popen(["p15-it-reader"], executable="/bin/cat", stdin=wr.stdout, stdout=subprocess.DEVNULL)
    wr.stdout.close()
    exp["pipe_exit"] = [wr.wait(), rd.wait()]
    exp["live_pid"] = live.pid
    (out / "c6-expect.json").write_text(json.dumps(exp, indent=1))


def check(rundir: Path, out: Path) -> int:
    exp = json.loads((out / "c6-expect.json").read_text())
    fails = 0

    def say(ok: bool, what: str) -> None:
        nonlocal fails
        print(f"{'ok' if ok else 'FAIL'} {what}")
        fails += not ok

    run = wal.read_run(rundir)
    execs = [x for x in run.ring_records(0) if x.name == "EXEC"]

    def mine(marker: bytes) -> list:
        return [e for e in execs if e.var["argv"].split(b"\0", 1)[0] == marker]

    # 1. exec from memory
    say(exp["memfd_exit"] == 0, f"the memfd program ran (exit {exp['memfd_exit']}, vm.memfd_noexec={exp['memfd_noexec']})")
    m = mine(b"p15-it-memfd")
    say(len(m) == 1, f"exactly one EXEC of p15-it-memfd (found {len(m)})")
    if m:
        e = m[0]
        say(e.var["exe_name"].startswith(b"memfd:p15-it"), f"  ... exe_name is the memfd's name ({e.var['exe_name']!r})")
        say(e.f["exe_nlink"] == 0 and e.f["exe_fs_magic"] == PV.TMPFS,
            f"  ... nlink 0 on tmpfs (nlink {e.f['exe_nlink']}, magic {e.f['exe_fs_magic']:#x})")
        say(PV.backing(e) == "memory" and "runs from memory (no file on disk)" in PV.unusual(e),
            f"  ... the reader classes it 'runs from memory' ({PV.unusual(e)})")

    # 2. the three stream kinds
    say(exp["streams_exit"] == 0, "the streams program ran")
    s = mine(b"p15-it-streams")
    say(len(s) == 1, f"exactly one EXEC of p15-it-streams (found {len(s)})")
    if s:
        e = s[0]
        for fd, kind, ifmt in (("stdin", "pipe", S_IFIFO), ("stdout", "file", S_IFREG), ("stderr", "socket", S_IFSOCK)):
            want = exp["streams"][fd]
            got = {"ino": e.f[f"{fd}_ino"], "dev": e.f[f"{fd}_dev"], "mode": e.f[f"{fd}_mode"]}
            say(got == want and want["mode"] & S_IFMT == ifmt and PV.stream_kind(got["mode"]) == kind,
                f"  ... {fd} is the {kind} the workload opened (record {got}, fstat {want})")

    # 3. the pipe link
    say(exp["pipe_exit"] == [0, 0], "the pipeline ran")
    w, r = mine(b"p15-it-writer"), mine(b"p15-it-reader")
    say(len(w) == 1 and len(r) == 1, f"one EXEC each of p15-it-writer and p15-it-reader (found {len(w)}, {len(r)})")
    if w and r:
        say((w[0], r[0]) in PV.pipe_links(execs), "  ... joined writer -> reader by their shared pipe inode")
        lines = trace.provenance_block(trace.load(rundir))
        say(any(f"(pid {w[0].h['tgid']}) -> " in x and f"(pid {r[0].h['tgid']})" in x for x in lines),
            "  ... p15-trace's provenance block shows that pipe")
        say(any("runs from memory" in x for x in lines), "  ... and the process that ran from memory")

    # 4. PROC v2 against EXEC v2 for a process alive at the closing snapshot
    lv = mine(b"p15-it-live")
    say(len(lv) == 1 and lv[0].h["tgid"] == exp["live_pid"], f"one EXEC of p15-it-live, pid {exp['live_pid']}")
    snaps = SN.collect(run.ring_records(2))
    closing = [x for x in snaps if x.kind == "closing"]
    say(len(closing) == 1, f"one closing snapshot (found {len(closing)})")
    if lv and closing:
        pr = closing[0].procs.get(lv[0].proc)
        say(pr is not None, "  ... it lists p15-it-live under the same process key as its EXEC")
        if pr is not None:
            diff = {k: (lv[0].f[k], pr.f[k]) for k in SHARED if lv[0].f[k] != pr.f[k]}
            say(not diff, f"  ... PROC v2 and EXEC v2 agree on all {len(SHARED)} shared facts{'' if not diff else f' (differ: {diff})'}")
    return fails


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "workload":
        workload(Path(sys.argv[2]))
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "check":
        return 1 if check(Path(sys.argv[2]), Path(sys.argv[3])) else 0
    print(__doc__, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main())
