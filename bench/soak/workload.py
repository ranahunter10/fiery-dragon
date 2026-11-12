#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The soak's workload (gate 4 of STATE decision 28): real programs in a loop, each step logging
what it did, so the soak can check that capture saw every one of those things.

    python3 bench/soak/workload.py --work DIR --duration S --log truth.jsonl [--pause 1.0]

Steps, in turn, each in its own directory DIR/<step>-<i> (so every expected path is unique):
  compile  K generated C files compiled with cc, linked, and the built program executed
  git      a repository: K files written, added, committed, logged (needs git; skipped without)
  archive  K files packed with tar and gzip, unpacked elsewhere, the copies checksummed
  pyfiles  a Python child writes K files, reads them back, deletes them
  http     a local http.server and M clients (curl if present, else Python) fetching from it
  shell    /bin/true copied into the step's directory and executed N times from bash, a pipeline
  memfd    a program copied into a memfd and executed from it (fileless execution)
One JSON line per step: {"step", "i", "t0", "t1" (CLOCK_BOOTTIME ns), "ok", "expect": {...}} where
expect holds what the WAL must show:
  open_w: paths opened for writing; open_r: paths opened for reading;
  exec: {filename: n} EXECs with that bprm filename, at least n; argv0: {marker: n} likewise by argv[0];
  accept: {port: n} accepted connections on that local port; connect: {port: n} connects to it.
A step whose programs failed says ok false and lists nothing to expect.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

K, M, N = 12, 8, 50


def boot_ns() -> int:
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def run(cmd, **kw) -> None:
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300, **kw)


def which(name: str) -> str | None:
    p = shutil.which(name)
    return p and str(Path(p).resolve())


def step_compile(d: Path, i: int) -> dict:
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        raise FileNotFoundError("cc")
    srcs = []
    for k in range(K):
        s = d / f"m{k}.c"
        s.write_text(f"int f{k}(int x) {{ return x * {k + 1} + {i}; }}\n")
        srcs.append(s)
    (d / "main.c").write_text("#include <stdio.h>\n" + "".join(f"int f{k}(int);\n" for k in range(K)) +
                              "int main(void) { int s = 0;" + "".join(f" s += f{k}(1);" for k in range(K)) +
                              ' printf("%d\\n", s); return 0; }\n')
    objs = []
    for s in srcs + [d / "main.c"]:
        o = s.with_suffix(".o")
        run([cc, "-O1", "-c", str(s), "-o", str(o)])
        objs.append(o)
    exe = d / f"prog{i}"
    run([cc, "-o", str(exe)] + [str(o) for o in objs])
    run([str(exe)])
    return {"open_w": [str(o) for o in objs] + [str(exe)], "open_r": [str(s) for s in srcs],
            "exec": {cc: len(objs) + 1, str(exe): 1}}


def step_git(d: Path, i: int) -> dict:
    git = shutil.which("git")
    if not git:
        return {}
    env = dict(os.environ, GIT_AUTHOR_NAME="soak", GIT_AUTHOR_EMAIL="soak@localhost", GIT_COMMITTER_NAME="soak",
               GIT_COMMITTER_EMAIL="soak@localhost", GIT_CONFIG_NOSYSTEM="1", HOME=str(d))
    run([git, "init", "-q", str(d / "r")], env=env)
    files = []
    for k in range(K):
        f = d / "r" / f"file{k}.txt"
        f.write_text(f"soak {i} {k}\n" * 20)
        files.append(str(f))
    run([git, "-C", str(d / "r"), "add", "."], env=env)
    run([git, "-C", str(d / "r"), "commit", "-q", "-m", f"soak {i}"], env=env)
    run([git, "-C", str(d / "r"), "log", "--oneline"], env=env)
    return {"open_r": files, "exec": {git: 4}}


def step_archive(d: Path, i: int) -> dict:
    tar = shutil.which("tar")
    if not tar:
        raise FileNotFoundError("tar")
    (d / "src").mkdir()
    (d / "x").mkdir()
    names = [f"doc{k}.txt" for k in range(K)]
    for n in names:
        (d / "src" / n).write_text(("archive %d %s\n" % (i, n)) * 200)
    tgz = d / f"a{i}.tgz"
    run([tar, "-czf", str(tgz), "-C", str(d / "src")] + names)
    run([tar, "-xzf", str(tgz), "-C", str(d / "x")])
    sha = shutil.which("sha256sum")
    if sha:
        run([sha] + [str(d / "x" / n) for n in names])
    return {"open_w": [str(tgz)] + [str(d / "x" / n) for n in names], "open_r": [str(d / "src" / n) for n in names],
            "exec": {tar: 2}}


CHILD_FILES = """
import sys, os
d = sys.argv[1]
for k in range(int(sys.argv[2])):
    p = os.path.join(d, f"py{k}.dat")
    with open(p, "w") as f:
        f.write("x" * 4096)
    with open(p) as f:
        f.read()
    os.unlink(p)
"""


def step_pyfiles(d: Path, i: int) -> dict:
    run([sys.executable, "-c", CHILD_FILES, str(d), str(K)])
    return {"open_w": [str(d / f"py{k}.dat") for k in range(K)]}


FETCH = """
import sys, urllib.request
for _ in range(int(sys.argv[2])):
    urllib.request.urlopen(sys.argv[1], timeout=10).read()
"""


def step_http(d: Path, i: int) -> dict:
    (d / "www").mkdir()
    (d / "www" / "index.html").write_text(f"<p>soak {i}</p>\n" * 50)
    srv = subprocess.Popen([sys.executable, "-u", "-m", "http.server", "0", "--bind", "127.0.0.1", "--directory",
                            str(d / "www")], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        line = srv.stdout.readline()          # "Serving HTTP on 127.0.0.1 port N (http://...) ..."
        port = int(line.split(" port ")[1].split()[0])
        url = f"http://127.0.0.1:{port}/index.html"
        curl = shutil.which("curl")
        if curl:
            for _ in range(M):
                run([curl, "-s", "-o", "/dev/null", url])
        else:
            run([sys.executable, "-c", FETCH, url, str(M)])
    finally:
        srv.terminate()
        srv.wait(10)
    return {"accept": {str(port): M}, "connect": {str(port): M}, "open_r": [str(d / "www" / "index.html")]}


def step_shell(d: Path, i: int) -> dict:
    t = d / f"true{i}"
    shutil.copy2("/bin/true", t)
    bash = shutil.which("bash") or "/bin/sh"
    run([bash, "-c", f"for k in $(seq {N}); do {t}; done; ls -l /usr/bin | grep -c x | sort | uniq > {d}/count.txt"])
    return {"exec": {str(t): N}, "open_w": [str(d / "count.txt")]}


MEMFD = """
import os, sys
fd = os.memfd_create("p15-soak", 0)
with open("/bin/true", "rb") as f:
    os.write(fd, f.read())
os.execv(f"/proc/self/fd/{fd}", [sys.argv[1]])
"""


def step_memfd(d: Path, i: int) -> dict:
    marker = f"p15-soak-memfd-{i}"
    run([sys.executable, "-c", MEMFD, marker])
    return {"argv0": {marker: 1}}


STEPS = (("compile", step_compile), ("git", step_git), ("archive", step_archive), ("pyfiles", step_pyfiles),
         ("http", step_http), ("shell", step_shell), ("memfd", step_memfd))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--duration", type=float, required=True)
    ap.add_argument("--log", type=Path, required=True)
    ap.add_argument("--pause", type=float, default=1.0)
    a = ap.parse_args(argv)
    work = a.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    end = time.monotonic() + a.duration
    i = 0
    with open(a.log, "w") as log:
        while time.monotonic() < end:
            name, fn = STEPS[i % len(STEPS)]
            d = work / f"{name}-{i}"
            d.mkdir()
            t0 = boot_ns()
            try:
                exp, ok = fn(d, i), True
            except (subprocess.SubprocessError, OSError, ValueError, IndexError) as e:
                exp, ok = {"error": f"{type(e).__name__}: {e}"}, False
            log.write(json.dumps({"step": name, "i": i, "t0": t0, "t1": boot_ns(), "ok": ok and bool(exp),
                                  "expect": exp if ok else {}, **({} if ok else exp)}) + "\n")
            log.flush()
            shutil.rmtree(d, ignore_errors=True)
            i += 1
            time.sleep(a.pause)
    return 0


if __name__ == "__main__":
    sys.exit(main())
