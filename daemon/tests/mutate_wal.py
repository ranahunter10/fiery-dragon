#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation sweep for the WAL writer (CONTRIBUTING: every gate is checked by mutation sweeps).

Each mutant plants one deliberate bug in daemon/wal.c or daemon/crc32c.c, rebuilds
daemon/tests/test_wal.c against it and expects the tests to fail. The source files are
restored after every mutant, also on error or Ctrl-C.

    python3 daemon/tests/mutate_wal.py        (or: make mutate-wal)

Exit 0 only if every mutant is killed. Left out as equivalent (no observable difference):
recovering a clean segment by "truncating" it at its own length.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
CC = os.environ.get("CC", "cc")

M = [
 ("wal.c", "w->st.next_seq[ring] += count;\n\tw->seg_bytes += total;", "w->st.next_seq[ring] += count + (ring == 0 && count == 3);\n\tw->seg_bytes += total;"),
 ("wal.c", "put32(h + 24, p15_crc32c(0, payload, len));", "put32(h + 24, p15_crc32c(0, payload, len - 8));"),
 ("wal.c", "put32(h + 32, p15_crc32c(0, h, 32));", "put32(h + 32, p15_crc32c(0, h, 28));"),
 ("wal.c", "w->seg_bytes + total > w->o.max_bytes &&\n", "w->seg_bytes + total > w->o.max_bytes + 136 &&\n"),
 ("wal.c", "if (!w->in_open && w->seg_batches > 0", "if (w->seg_batches > 0"),
 ("wal.c", "if (w->seg_batches > 0 && t - w->opened_ns >= w->o.max_ns)", "if (t - w->opened_ns >= w->o.max_ns)"),
 ("wal.c", "if (w->dirty && t - w->last_sync_ns >= w->o.sync_ns)", "if (t - w->last_sync_ns >= w->o.sync_ns)"),
 ("wal.c", "w->last_sync_ns = t;\n\t\tw->dirty = 0;", "w->dirty = 0;"),
 ("wal.c", "s->torn = (off + P15W_BATCH_HDR_LEN + plen == n);", "s->torn = 1;"),
 ("wal.c", "if (all_zero(h, rem))", "if (0)"),
 ("wal.c", "else if (get64(h + 16) != s->next_seq[ring])", "else if (0)"),
 ("wal.c", "} else if (s.stop && !s.torn) {", "} else if (0) {"),
 ("wal.c", "if (rl < P15W_REC_MIN || rl % 8 || rl > len - off)", "if (rl < P15W_REC_MIN || rl > len - off)"),
 ("wal.c", "return n == count;", "return 1;"),
 ("wal.c", "if (len < P15W_REC_MIN || len % 8 || len > size || len > b->cap)", "if (len < P15W_REC_MIN || len % 8 || len > b->cap)"),
 ("wal.c", "memcpy(b->buf + b->len, rec, len);\n\tb->len += len;", "memcpy(b->buf + b->len, rec, len);\n\tb->len += size < 1000 ? len : size;"),
 ("wal.c", "if (!w->failed)\n\t\tw->failed = -err;", ""),
 ("wal.c", "if (w->failed)\n\t\treturn -EIO;\n\tif (ring", "if (ring"),
 ("wal.c", "w->st.rejected_batches++;", ""),
 ("wal.c", "OWN(\"clock.read_spread_ns\", \"%llu\", (unsigned long long)(bt1 - bt0));", "OWN(\"clock.read_spread_ns\", \"%llu\", (unsigned long long)(bt1));"),
 ("wal.c", "!strncmp(k, \"clock.\", 6) || ", ""),
 ("wal.c", "O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC", "O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC"),
 ("wal.c", "crc = p15_crc32c(crc, zero4, 4);", ""),
 ("wal.c", "w->st.short_writes++;", "w->st.short_writes++; r = 0;"),
 ("crc32c.c", "c = (c >> 1) ^ (0x82F63B78u & (0u - (c & 1)));", "c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1)));"),
 ("wal.c", "w->st.oversize_batches++;", ""),
 ("wal.c", "if (ftruncate(fd, s.good_end) || fdatasync(fd))", "if (ftruncate(fd, s.good_end + 8) || fdatasync(fd))"),
]


def main() -> int:
    originals = {f: (ROOT / "daemon" / f).read_text() for f in ("wal.c", "crc32c.c")}
    killed = 0
    with tempfile.TemporaryDirectory() as tmp:
        exe = pathlib.Path(tmp) / "test_wal"
        try:
            for i, (f, old, new) in enumerate(M):
                if originals[f].count(old) != 1:
                    print(f"mutant {i}: anchor not found exactly once in {f}; update this sweep")
                    return 2
                (ROOT / "daemon" / f).write_text(originals[f].replace(old, new))
                r = subprocess.run(f"{CC} -std=gnu11 -O1 -Idaemon daemon/tests/test_wal.c daemon/wal.c "
                                   f"daemon/crc32c.c -o {exe} && timeout 60 {exe}", shell=True, cwd=ROOT,
                                   capture_output=True, text=True)
                (ROOT / "daemon" / f).write_text(originals[f])
                dead = r.returncode != 0
                killed += dead
                print(("killed   " if dead else "SURVIVED "), i, old.splitlines()[0].strip()[:72])
        finally:
            for f, text in originals.items():
                (ROOT / "daemon" / f).write_text(text)
    print(f"mutation sweep: {killed}/{len(M)} killed")
    return 0 if killed == len(M) else 1


if __name__ == "__main__":
    sys.exit(main())
