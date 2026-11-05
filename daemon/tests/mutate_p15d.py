#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation sweep for p15d's modules (CONTRIBUTING §6): queue, config, drain, writer, run.

Each mutant plants one bug, rebuilds, and runs the tests that should catch it: the unit
tests for queue and config (no root), the end-to-end test daemon/tests/it_p15d.sh for the
drain, writer and run (root; about 25 s each). Sources are restored after every mutant.

    sudo python3 daemon/tests/mutate_p15d.py        (or: sudo make mutate-p15d)
Exit 0 only if every mutant is killed.
"""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
UNIT = "make -s build/test_queue build/test_config build/test_run && build/test_queue && build/test_config && build/test_run"
IT = "make -s build/p15d build/p15w-inspect && daemon/tests/it_p15d.sh build"

M = [
    # queue: capacity, ordering, publication
    ("queue.c", "if (h - t >= q->n) {", "if (h - t > q->n) {", UNIT),
    ("queue.c", "\tatomic_store_explicit(&q->head, h, memory_order_release);", "", UNIT),
    ("queue.c", "\ts->count = 0;\n\ts->len = 0;", "", UNIT),
    ("queue.c", "return t == h ? NULL : &q->slots[t % q->n];", "return t == h ? NULL : &q->slots[h % q->n];", UNIT),
    ("queue.c", "while (d > m && !atomic_compare_exchange_weak_explicit", "while (0 && !atomic_compare_exchange_weak_explicit", UNIT),
    # config: strictness
    ("config.c", "\t\t\tsnprintf(err, errlen, \"unknown argument '%s'\", f);\n\t\t\treturn -EINVAL;", "\t\t\tcontinue;", UNIT),
    ("config.c", "if (v < OPTS[i].lo || v > OPTS[i].hi ||", "if (v > OPTS[i].hi ||", UNIT),
    ("config.c", "(OPTS[i].pow2 && (v & (v - 1)))", "0", UNIT),
    ("config.c", "\tif (!c->wal_root) {", "\tif (0) {", UNIT),
    # drain, writer, run: the books, GAP, END
    ("drain.c", "\t\tif (any)\n\t\t\temit_gap(d, from, to, now_ctr);", "\t\tif (any && 0)\n\t\t\temit_gap(d, from, to, now_ctr);", IT),
    ("drain.c", "\tatomic_fetch_add(&d->run->drained[h->type], 1);", "", IT),
    ("writer.c", "\tdrained -= r->spine_selftest_consumed;", "", UNIT),
    ("writer.c", "\tuint64_t emitted = 0, drained = r->spine_selftest_consumed;", "\tuint64_t emitted = 0, drained = 0;", UNIT),
    ("writer.c", "\tif (inv == P15_INV_BROKEN)\n\t\tp15_run_set_state(r, P15_RUN_INVALID, why);", "", UNIT),
    ("writer.c", "\tif (drained != atomic_load(&r->spine_written) + atomic_load(&r->spine_drain_lost)) {", "\tif (0) {", UNIT),
    ("writer.c", "\tif (emitted != drained + atomic_load(&r->spine_invalid)) {", "\tif (0) {", UNIT),
    ("writer.c", "\tbuf.e.signal = (uint32_t)atomic_load(&w->run->stop_signal);", "", IT),
    ("run.c", "\tcase P15_RUN_DEGRADED:\n\t\treturn P15_EXIT_DEGRADED;\n\tdefault:\n\t\treturn P15_EXIT_INVALID;", "\tdefault:\n\t\treturn P15_EXIT_OK;", IT),
]


def main() -> int:
    files = sorted({f for f, *_ in M})
    orig = {f: (ROOT / "daemon" / f).read_text() for f in files}
    killed = 0
    try:
        for i, (f, old, new, test) in enumerate(M):
            if orig[f].count(old) != 1:
                print(f"mutant {i}: anchor not found exactly once in {f}; update this sweep")
                return 2
            (ROOT / "daemon" / f).write_text(orig[f].replace(old, new))
            r = subprocess.run(f"timeout 180 sh -c '{test}'", shell=True, cwd=ROOT, capture_output=True, text=True)
            (ROOT / "daemon" / f).write_text(orig[f])
            built = "error:" not in r.stdout + r.stderr
            dead = r.returncode != 0 and built
            killed += dead
            tag = "killed  " if dead else ("NO BUILD" if not built else "SURVIVED")
            print(tag, i, f, old.strip().splitlines()[0][:70])
    finally:
        for f, text in orig.items():
            (ROOT / "daemon" / f).write_text(text)
        subprocess.run("make -s build/p15d build/test_queue build/test_config", shell=True, cwd=ROOT)
    print(f"mutation sweep: {killed}/{len(M)} killed")
    return 0 if killed == len(M) else 1


if __name__ == "__main__":
    sys.exit(main())
