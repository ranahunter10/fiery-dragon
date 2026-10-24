#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""PostMark-style small-file churn: create, append, read and delete files for a fixed time.

PostMark (Katcher, 1997) models mail/news servers: a pool of small files hit by
random transactions. The census uses this shape to drive open, read and write
on regular files at a high rate. It is not a PostMark reimplementation; the
parameters are ours and are printed with the results.

Every operation uses unbuffered os.read/os.write in 4 KiB chunks, so each one
is a real syscall the census can see.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import sys
import time

CHUNK = 4096


def write_bytes(path: str, size: int, rnd: random.Random, append: bool = False) -> int:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    fd = os.open(path, flags, 0o644)
    written = 0
    try:
        while written < size:
            n = min(CHUNK, size - written)
            written += os.write(fd, rnd.randbytes(n))
    finally:
        os.close(fd)
    return written


def read_all(path: str) -> int:
    fd = os.open(path, os.O_RDONLY)
    total = 0
    try:
        while chunk := os.read(fd, CHUNK):
            total += len(chunk)
    finally:
        os.close(fd)
    return total


def churn(directory: str, duration: float, files: int, min_size: int, max_size: int, seed: int) -> dict:
    rnd = random.Random(seed)
    os.makedirs(directory, exist_ok=True)
    live: list[str] = []
    stats = {"create": 0, "append": 0, "read": 0, "delete": 0, "bytes_written": 0, "bytes_read": 0}
    next_id = 0

    def create() -> None:
        nonlocal next_id
        path = os.path.join(directory, f"f{next_id:08d}")
        next_id += 1
        stats["bytes_written"] += write_bytes(path, rnd.randint(min_size, max_size), rnd)
        live.append(path)
        stats["create"] += 1

    for _ in range(files):          # initial pool, like PostMark's "set number"
        create()

    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        op = rnd.choice(("read", "append", "delete", "create"))
        if op == "create" or not live:
            create()
        elif op == "read":
            stats["bytes_read"] += read_all(rnd.choice(live))
            stats["read"] += 1
        elif op == "append":
            stats["bytes_written"] += write_bytes(rnd.choice(live), rnd.randint(min_size, max_size) // 4, rnd, append=True)
            stats["append"] += 1
        else:
            os.unlink(live.pop(rnd.randrange(len(live))))
            stats["delete"] += 1
    shutil.rmtree(directory)
    return stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", required=True, help="scratch directory (created, then removed)")
    ap.add_argument("--duration", type=float, required=True, help="seconds")
    ap.add_argument("--files", type=int, default=500, help="initial pool size (default 500)")
    ap.add_argument("--min-size", type=int, default=512, help="bytes (default 512)")
    ap.add_argument("--max-size", type=int, default=16384, help="bytes (default 16 KiB)")
    ap.add_argument("--seed", type=int, default=15, help="random seed, for repeatable runs")
    args = ap.parse_args(argv)
    stats = churn(args.dir, args.duration, args.files, args.min_size, args.max_size, args.seed)
    print(json.dumps({"filechurn": stats, "params": vars(args)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
