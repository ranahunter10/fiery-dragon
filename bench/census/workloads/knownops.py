#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Perform exact, known numbers of operations and print what the census must see.

Every census class that a hook can silently miss gets K deliberate operations
here. The script counts what actually succeeded in userspace and prints
{"expect": {class: n}} as its last line. run.py checks census_count >= n for
each class. Background activity can only add, so a count below expectation
means the hook missed events: the "silent hook" failure seen on 7.0 with
syscalls:sys_enter_*. This is the prototype of the product's load-time self-test.

x86_64 only (raw syscall numbers for ptrace, process_vm_writev, io_uring_setup).
"""

from __future__ import annotations

import argparse
import ctypes
import json
import mmap
import os
import shutil
import socket
import sys
import time

SYS_PTRACE, SYS_PROCESS_VM_WRITEV, SYS_IO_URING_SETUP = 101, 311, 425
PROT_READ, PROT_WRITE, PROT_EXEC = 1, 2, 4
MAP_PRIVATE, MAP_ANONYMOUS = 0x02, 0x20
PTRACE_TRACEME = 0

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long)
libc.mprotect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
libc.munmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t)


class IoVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


def meta_ops(work: str, k: int, exp: dict) -> None:
    """mkdir/rmdir, chmod, chown, truncate, link, symlink, rename, unlink: k each (unlink 3k)."""
    uid, gid = os.getuid(), os.getgid()
    for i in range(k):
        d = os.path.join(work, f"d{i}")
        a, l, s, r = (os.path.join(work, f"{p}{i}") for p in ("a", "l", "s", "r"))
        os.mkdir(d); exp["mkdir"] += 1
        fd = os.open(a, os.O_CREAT | os.O_WRONLY, 0o600); os.write(fd, b"x"); os.close(fd)
        os.chmod(a, 0o640); exp["chmod"] += 1
        os.chown(a, uid, gid); exp["chown"] += 1
        os.truncate(a, 0); exp["truncate"] += 1
        os.link(a, l); exp["link"] += 1
        os.symlink(a, s); exp["symlink"] += 1
        os.rename(a, r); exp["rename_file"] += 1
        for p in (r, l, s):
            os.unlink(p); exp["unlink"] += 1
        os.rmdir(d); exp["rmdir"] += 1


def net_ops(k: int, exp: dict) -> None:
    """One listener (bind, listen); k accepted connections; k refused connects."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0)); exp["bind"] += 1
    srv.listen(k); exp["listen"] += 1
    port = srv.getsockname()[1]
    for _ in range(k):
        c = socket.create_connection(("127.0.0.1", port)); exp["connect"] += 1
        conn, _ = srv.accept(); exp["accept"] += 1
        c.sendall(b"x"); conn.recv(1)
        c.close(); conn.close()
    srv.close()
    closed = socket.socket(); closed.bind(("127.0.0.1", 0)); dead_port = closed.getsockname()[1]; closed.close()
    for _ in range(k):
        c = socket.socket()
        try:
            c.connect(("127.0.0.1", dead_port))
        except ConnectionRefusedError:
            exp["connect_fail"] += 1
        finally:
            c.close()


def cap_ops(work: str, k: int, exp: dict) -> None:
    """mmap shared+write, mprotect to exec, memfd, ptrace, process_vm_writev, io_uring_setup."""
    path = os.path.join(work, "shared")
    with open(path, "wb") as f:
        f.write(b"\0" * 4096)
    for _ in range(k):
        with open(path, "r+b") as f:
            m = mmap.mmap(f.fileno(), 4096, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            m[0] = 1; m.close()
        exp["mmap_shared_w"] += 1
    os.unlink(path)

    for _ in range(k):
        addr = libc.mmap(None, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        if libc.mprotect(addr, 4096, PROT_READ | PROT_EXEC) == 0:
            exp["mprotect_exec"] += 1
        libc.munmap(addr, 4096)

    for _ in range(k):
        os.close(os.memfd_create("fd-knownops")); exp["memfd"] += 1

    for _ in range(k):                      # each child makes exactly one ptrace call
        pid = os.fork()
        if pid == 0:
            libc.syscall(SYS_PTRACE, PTRACE_TRACEME, 0, 0, 0)
            os._exit(0)
        os.waitpid(pid, 0); exp["ptrace"] += 1

    src, dst = ctypes.create_string_buffer(b"y" * 8), ctypes.create_string_buffer(8)
    liov, riov = IoVec(ctypes.cast(src, ctypes.c_void_p), 8), IoVec(ctypes.cast(dst, ctypes.c_void_p), 8)
    for _ in range(k):                      # hook counts calls, whatever their result
        libc.syscall(SYS_PROCESS_VM_WRITEV, os.getpid(), ctypes.byref(liov), 1, ctypes.byref(riov), 1, 0)
        exp["process_vm_writev"] += 1

    params = ctypes.create_string_buffer(120)  # sizeof(struct io_uring_params)
    for _ in range(k):
        fd = libc.syscall(SYS_IO_URING_SETUP, 4, params)
        if fd >= 0:
            os.close(fd); exp["io_uring_setup"] += 1


def run(work: str, k: int) -> dict:
    os.makedirs(work, exist_ok=True)
    exp = {c: 0 for c in ("mkdir", "rmdir", "chmod", "chown", "truncate", "link", "symlink", "rename_file",
                          "unlink", "bind", "listen", "connect", "accept", "connect_fail", "mmap_shared_w",
                          "mprotect_exec", "memfd", "ptrace", "process_vm_writev", "io_uring_setup")}
    meta_ops(work, k, exp)
    net_ops(k, exp)
    cap_ops(work, k, exp)
    shutil.rmtree(work)
    return exp


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", required=True, help="scratch directory (created, then removed)")
    ap.add_argument("--k", type=int, default=50, help="operations per class (default 50)")
    ap.add_argument("--duration", type=float, default=0, help="seconds to stay alive afterwards, so the census window is even")
    args = ap.parse_args(argv)
    t0 = time.monotonic()
    exp = run(args.dir, args.k)
    elapsed = time.monotonic() - t0
    if args.duration > elapsed:
        time.sleep(args.duration - elapsed)
    print(json.dumps({"expect": exp, "params": {"k": args.k}, "ops_seconds": round(elapsed, 3)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
