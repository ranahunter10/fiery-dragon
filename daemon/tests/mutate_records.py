#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation sweep for the record checks and formatting, daemon/records.c (CONTRIBUTING §6).

Each mutant plants one bug in daemon/records.c, rebuilds daemon/tests/test_records.c and
daemon/tests/test_selftest.c against it, and expects at least one of them to fail. The source
is restored after every mutant, also on error or Ctrl-C.

    python3 daemon/tests/mutate_records.py        (or: make mutate-records)

The tests run under ASan and UBSan, so a mutant that reads past the bytes it was given is
killed too. Exit 0 only if every mutant is killed. A mutant that does not compile is not valid,
and the sweep stops. Left out as equivalent:
  - the header-size check `size < sizeof(*h)` weakened to `size < 8`: with 8 to 31 bytes,
    every type is still refused by `len < fixed` before any byte past the eighth is read.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "daemon" / "records.c"
CC = os.environ.get("CC", "cc")
LIBBPF_INC = ROOT / "build" / "libbpf"

M = [
 # the header and len rules every record must pass
 ("if (h->len > size) {", "if (h->len > size + 8) {"),
 ("if (h->len % 8) {", "if (h->len % 4) {"),
 ("if (h->len < fixed) {", "if (h->len + 8 < fixed) {"),
 ("case P15_T_STATS:  return version == 1 ?", "case P15_T_STATS:  return version >= 1 ?"),
 ("case P15_T_GAP:    return version == 1 ? sizeof(struct p15_gap_v1) : 0;", "case P15_T_GAP:    return 0;"),
 ("\t} else if (h->len != fixed) {", "\t} else if (0) {"),
 # the variable-field tail rules (EXEC and END)
 ("if (fixed + used > h->len) {", "if (fixed + used > h->len + 8) {"),
 ("if (h->len != ((fixed + used + 7) & ~(size_t)7) && !slack_ok) {", "if (h->len != ((fixed + used + 7) & ~(size_t)7)) {"),
 ("if (h->len != ((fixed + used + 7) & ~(size_t)7) && !slack_ok) {", "if (h->len > ((fixed + used + 7) & ~(size_t)7) + 8 && !slack_ok) {"),
 ("for (size_t i = fixed + used; i < h->len; i++)", "for (size_t i = fixed + used + 1; i < h->len; i++)"),
 ("\t\tif (((const __u8 *)data)[i]) {", "\t\tif (0) {"),
 ("h->flags & P15_F_READ_FAILED, why))", "h->flags & P15_F_TRUNCATED, why))"),
 ("if (e->filename_len > P15_EXEC_V1_FILENAME_MAX || e->argv_len > P15_EXEC_V1_ARGV_MAX) {",
  "if (e->filename_len > P15_EXEC_V1_FILENAME_MAX) {"),
 ("if (e->reason_len > P15_END_V1_REASON_MAX) {", "if (0) {"),
 ("if (check_tail(data, fixed, e->reason_len, 0, why))", "if (check_tail(data, fixed, e->reason_len, 1, why))"),
 # names and formatting
 ('case P15_T_END:        return "END";', 'case P15_T_END:        return "?";'),
 ('case P15_T_GAP:        return "GAP";', 'case P15_T_GAP:        return "END";'),
 ("(unsigned long long)r->fork_build_failed, (unsigned long long)r->exec_build_failed,",
  "(unsigned long long)r->exec_build_failed, (unsigned long long)r->fork_build_failed,"),
 ("(unsigned long long)r->spine_written,", "(unsigned long long)r->spine_invalid,"),
 ("printable(b, sizeof(b), (const __u8 *)(r + 1), r->reason_len);", "printable(b, sizeof(b), (const __u8 *)(r + 1), 4);"),
]


def main() -> int:
    orig = SRC.read_text()
    killed = 0
    with tempfile.TemporaryDirectory() as tmp:
        try:
            for i, (old, new) in enumerate(M):
                if orig.count(old) != 1:
                    print(f"mutant {i}: anchor not found exactly once; update this sweep")
                    return 2
                SRC.write_text(orig.replace(old, new))
                inc = (f"-Idaemon -Ischema/generated -Ibpf/include -I{LIBBPF_INC} "
                       "-fsanitize=address,undefined -fno-sanitize-recover=undefined")
                build = subprocess.run(
                    f"{CC} -std=gnu11 -O1 {inc} daemon/tests/test_records.c daemon/records.c -o {tmp}/r && "
                    f"{CC} -std=gnu11 -O1 {inc} daemon/tests/test_selftest.c daemon/records.c daemon/selftest.c "
                    f"build/libbpf/libbpf.a -lelf -lz -o {tmp}/s", shell=True, cwd=ROOT, capture_output=True, text=True)
                if build.returncode != 0:
                    print(f"mutant {i} does not compile: not a valid mutant; fix this sweep\n{build.stderr[-400:]}")
                    return 2
                r = subprocess.run(f"timeout 60 {tmp}/r && timeout 60 {tmp}/s", shell=True, cwd=ROOT,
                                   capture_output=True, text=True)
                SRC.write_text(orig)
                dead = r.returncode != 0
                killed += dead
                print(("killed   " if dead else "SURVIVED "), i, old.strip()[:72])
        finally:
            SRC.write_text(orig)
    print(f"mutation sweep: {killed}/{len(M)} killed")
    return 0 if killed == len(M) else 1


if __name__ == "__main__":
    sys.exit(main())
