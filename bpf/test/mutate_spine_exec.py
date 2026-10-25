#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation sweep for the spine's EXEC program, the way it is built (OUTPUT, ADR-0017 layer 1),
and the counter books (CONTRIBUTING §6). Root: each mutant is loaded into the kernel.

Each mutant plants one bug in bpf/progs/spine.bpf.c, rebuilds build/p15-spine and runs its
load-time self-test, which then also checks the counters after detaching. The run must fail.
The source is restored after every mutant, also on error or Ctrl-C.

    sudo python3 bpf/test/mutate_spine_exec.py        (or: sudo make mutate-spine)

A mutant must be killed by the self-test, not by the compiler: every mutant here builds and
loads, and the sweep says so when one does not.

Exit 0 only if every mutant is killed. Left out, and why:
  - EXEC submitted with BPF_RB_NO_WAKEUP: equivalent for this test. The child's EXIT always
    follows its EXEC and is submitted with a wakeup, which delivers both.
  - the zeroing of EXEC padding: a fresh per-CPU scratch is already zero, so only an earlier,
    longer exec on the same CPU would expose stale bytes. p15_rec_check refuses them in the
    drain at run time (non-zero bytes after the fields) and its unit test plants them.
"""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "bpf" / "progs" / "spine.bpf.c"

M = [
 # the record's ring size: exactly len
 ("if (bpf_ringbuf_output(&spine_rb, r, len, 0)) {",
  "if (bpf_ringbuf_output(&spine_rb, r, len > 0 ? P15_EXEC_MAX_SIZE : len, 0)) {"),
 # len larger than the fields: refused by p15_rec_check
 ("\tlen = exec_len(end);\n", "\tlen = exec_len(end + 8);\n"),
 # variable-field lengths not written into the scratch record
 ("\tr->argv_len = av_len;\n\n\t/* zero the bytes", "\n\t/* zero the bytes"),
 ("\tr->filename_len = fn_len;\n\treturn fn_len;", "\treturn fn_len;"),
 # the books: an emitted record not counted, a seen event not counted
 ("#endif\n\tcount(P15_T_EXEC, P15_CK_EMITTED);", "#endif\n"),
 ("\tcount(P15_T_EXEC, P15_CK_SEEN);\n#if P15_EXEC_WAY == P15_EXEC_WAY_FIXED", "#if P15_EXEC_WAY == P15_EXEC_WAY_FIXED"),
 # the default way: back to the maximum reservation
 ("#define P15_EXEC_WAY P15_EXEC_WAY_OUTPUT\n", "#define P15_EXEC_WAY P15_EXEC_WAY_FIXED\n"),
]


def build_and_test() -> bool:
    """True if the self-test run fails (the mutant is killed)."""
    b = subprocess.run(["make", "-s", "build/p15-spine"], cwd=ROOT, capture_output=True, text=True)
    if b.returncode != 0:
        print("    (the build refused it: not a valid mutant)")
        return False
    r = subprocess.run(["timeout", "60", "build/p15-spine", "selftest"], cwd=ROOT, capture_output=True, text=True)
    if "load failed" in r.stderr or "attach failed" in r.stderr:
        print("    (the verifier refused it: not a valid mutant)")
        return False
    return r.returncode != 0


def main() -> int:
    if os.geteuid() != 0:
        print("mutate_spine_exec: needs root (loads BPF)", file=sys.stderr)
        return 2
    orig = SRC.read_text()
    killed = 0
    try:
        for i, (old, new) in enumerate(M):
            if orig.count(old) != 1:
                print(f"mutant {i}: anchor not found exactly once; update this sweep")
                return 2
            SRC.write_text(orig.replace(old, new))
            dead = build_and_test()
            SRC.write_text(orig)
            killed += dead
            print(("killed   " if dead else "SURVIVED "), i, old.strip().splitlines()[0][:72])
    finally:
        SRC.write_text(orig)
        subprocess.run(["make", "-s", "build/p15-spine"], cwd=ROOT, capture_output=True)
    print(f"mutation sweep: {killed}/{len(M)} killed")
    return 0 if killed == len(M) else 1


if __name__ == "__main__":
    sys.exit(main())
