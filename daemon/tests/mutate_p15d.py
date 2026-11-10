#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation sweep for p15d's modules (CONTRIBUTING §6): queue, config, drain, writer, run, counters, startup.

Each mutant plants one bug, rebuilds, and runs the tests that should catch it: the unit
tests for queue and config (no root), the end-to-end test daemon/tests/it_p15d.sh for the
drain, writer and run (root; about 25 s each). Sources are restored after every mutant.

    sudo python3 daemon/tests/mutate_p15d.py        (or: sudo make mutate-p15d)
Exit 0 only if every mutant is killed.
"""
import pathlib
import signal
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
UNIT = ("make -s build/test_queue build/test_config build/test_run build/test_counters && build/test_queue && "
        "build/test_config && build/test_run && build/test_counters")
IT = "make -s build/p15d build/p15w-inspect && daemon/tests/it_p15d.sh build"

M = [
    # counters (ADR-0026): the row sum, configure and verify; the drain's mapped read; the loader;
    # the startup order (case 7 of it_p15d.sh traces map syscalls). Left out as equivalent: which
    # row a CPU counts into (bpf/progs/*.bpf.c count()): every row is summed, so the choice changes
    # cache-line sharing, never a total.
    ("counters.c", "for (int r = 0; r <= ncpu; r++)", "for (int r = 0; r < ncpu; r++)", UNIT),
    ("counters.c", "\t*ncpu_rodata = (uint32_t)ncpu;", "\t(void)ncpu_rodata;", UNIT),
    ("counters.c", "if (ncpu <= 0 || ncpu > P15_CTR_NCPU_MAX)\n\t\treturn -EINVAL;\n\trc =", "if (ncpu > P15_CTR_NCPU_MAX)\n\t\treturn -EINVAL;\n\trc =", UNIT),
    ("counters.c", "bpf_map__type(map) != BPF_MAP_TYPE_ARRAY ||", "", UNIT),
    ("counters.c", "!(bpf_map__map_flags(map) & BPF_F_MMAPABLE) ||", "", UNIT),
    ("counters.c", "bpf_map__value_size(map) != sizeof(uint64_t) ||", "", UNIT),
    ("counters.c", "bpf_map__max_entries(map) != P15_CTR_ENTRIES((uint32_t)ncpu))", "0)", UNIT),
    ("drain.c", "\tp15_counters_sum(c, sum);\n\treturn 0;", "\t(void)c;\n\tmemset(sum, 0, sizeof(uint64_t) * P15_CTR_MAX);\n\treturn 0;", IT),
    ("loader.c", "if (l->ncpu <= 0 || p15_counters_configure(l->spine->maps.spine_counters, &l->spine->rodata->spine_counters_ncpu,\n\t\t\t\t\t\t   l->ncpu)) {",
     "if (l->ncpu <= 0) {", IT),
    ("p15d.c", '\tcode = p15_snapshot_init(&snap, &run, err, sizeof(err));\n\tif (code) {\n\t\tlogline("error", "load", err);\n\t\tp15_snapshot_free(&snap);\n\t\treturn code;\n\t}\n\t{\n\t\tstruct p15_loader_opts lo = {\n\t\t\t.spine_ring_bytes = run.spine_ring_bytes, .bulk_ring_bytes = run.bulk_ring_bytes, .net = run.net,\n\t\t\t.files = run.files, .test_no_path_fentry = run.cfg.test_no_path_fentry,\n\t\t\t.file_map_entries = run.cfg.file_map_entries, .obj_map_entries = run.cfg.obj_map_entries,\n\t\t};\n\n\t\tcode = p15_loader_start(&ld, &lo, err, sizeof(err));\n\t}\n\tif (code) {\n\t\tlogline("error", "load", err);\n\t\tp15_loader_free(&ld);\n\t\tp15_snapshot_free(&snap);\n\t\treturn code;\n\t}\n\trun.start_ns = ld.daemon_start_ns;\n',
     '\t{\n\t\tstruct p15_loader_opts lo = {\n\t\t\t.spine_ring_bytes = run.spine_ring_bytes, .bulk_ring_bytes = run.bulk_ring_bytes, .net = run.net,\n\t\t\t.files = run.files, .test_no_path_fentry = run.cfg.test_no_path_fentry,\n\t\t\t.file_map_entries = run.cfg.file_map_entries, .obj_map_entries = run.cfg.obj_map_entries,\n\t\t};\n\n\t\tcode = p15_loader_start(&ld, &lo, err, sizeof(err));\n\t}\n\tif (code) {\n\t\tlogline("error", "load", err);\n\t\tp15_loader_free(&ld);\n\t\tp15_snapshot_free(&snap);\n\t\treturn code;\n\t}\n\trun.start_ns = ld.daemon_start_ns;\n\tcode = p15_snapshot_init(&snap, &run, err, sizeof(err));\n\tif (code) {\n\t\tlogline("error", "load", err);\n\t\tp15_snapshot_free(&snap);\n\t\treturn code;\n\t}\n', IT),   # snapshot loaded after attach
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
    ("drain.c", "\t\tif (p15_spine_loss_changed(d->prev_ctr, now_ctr, d->prev_missed, now_missed)) {", "\t\tif (0) {", IT),
    # ADR-0020 rule 3: a kernel skip of any spine type calls for a GAP
    ("drain.c", "now_missed[t] != prev_missed[t];", "(0 && now_missed[t] != prev_missed[t]);", UNIT),
    ("drain.c", "\tfor (int t = 1; t < P15_SPINE_TYPES; t++)\n\t\tany |=", "\tfor (int t = 2; t < P15_SPINE_TYPES; t++)\n\t\tany |=", UNIT),
    ("drain.c", "\tatomic_fetch_add(&d->run->drained[h->type], 1);", "", IT),
    ("writer.c", "\tdrained -= r->spine_selftest_consumed;", "", UNIT),
    ("writer.c", "\tuint64_t emitted = 0, drained = r->spine_selftest_consumed;", "\tuint64_t emitted = 0, drained = 0;", UNIT),
    ("writer.c", "\tif (inv == P15_INV_BROKEN)\n\t\tp15_run_set_state(r, P15_RUN_INVALID, why);", "", UNIT),
    ("writer.c", "\tif (drained != atomic_load(&r->spine_written) + atomic_load(&r->spine_drain_lost)) {", "\tif (0) {", UNIT),
    ("writer.c", "\tif (emitted != drained + atomic_load(&r->spine_invalid)) {", "\tif (0) {", UNIT),
    ("writer.c", "\tbuf.e.signal = (uint32_t)atomic_load(&w->run->stop_signal);", "", IT),
    ("run.c", "\tcase P15_RUN_DEGRADED:\n\t\treturn P15_EXIT_DEGRADED;\n\tdefault:\n\t\treturn P15_EXIT_INVALID;", "\tdefault:\n\t\treturn P15_EXIT_OK;", IT),
    # file identity (ADR-0015, step 2a part 2): the shared bulk ring's books, FILE_STATS, the run state
    ("drain.c", "atomic_fetch_add(is_net ? &d->run->net_drained : &d->run->file_drained, 1);",
     "atomic_fetch_add(&d->run->net_drained, 1);", IT),
    ("writer.c", "\tif (r->files) {\n\t\tif (file_books(r, why, n))", "\tif (0) {\n\t\tif (file_books(r, why, n))", UNIT),
    ("writer.c", "A(BACKING_LOST) + A(FENTRY_NO_INODE)) {", "A(BACKING_LOST)) {", UNIT),
    ("writer.c", "if (A(SESSION_ENTRY) != A(SESSION_RETURN) + A(SESSION_NO_INODE) ||", "if (", UNIT),
    ("writer.c", "A(VERDICT_LOST) + A(SESSION_NO_COOKIE) + A(SESSION_NO_ENTRY)) {", "A(VERDICT_LOST) + A(SESSION_NO_ENTRY)) {", UNIT),
    ("writer.c", "A(MISSING_EMITTED) + A(MISSING_LOST) + A(VERDICT_EMITTED)", "A(MISSING_EMITTED) + A(VERDICT_EMITTED)", UNIT),
    ("writer.c", "if (A(FREE_RUN) != A(CLOSE_EMITTED) + A(CLOSE_LOST) + A(FREE_UNREGISTERED)) {", "if (0) {", UNIT),
    ("writer.c", "uint64_t taken = atomic_load(&r->file_drained) + r->file_selftest_consumed + atomic_load(&r->file_invalid);",
     "uint64_t taken = atomic_load(&r->file_drained) + r->file_selftest_consumed;", UNIT),
    ("writer.c", "if (!r->net && atomic_load(&r->file_drained) != atomic_load(&r->net_written) + atomic_load(&r->net_drain_lost)) {",
     "if (0) {", UNIT),
    # the facts epoch (E-0151): without it an object first opened during the self-tests has no facts in the WAL
    ("loader.c", "\tif (l->file)\n\t\tl->file->data->facts_epoch++;", "", IT),
    ("writer.c", "\tif (w->run->files)\n\t\tfile_stats(w);", "", IT),
    ("loader.c", "\tif (o->files && (code = load_file(l, o, err, errlen)))\n\t\treturn code;", "", IT),
]


def main() -> int:
    files = sorted({f for f, *_ in M})
    # The sweep takes the working tree as the original and restores it afterwards: a tree that already
    # differs from git (a mutant left by a killed sweep) would be "restored" with the mutant in it and
    # every result would be about the wrong program (E-0155). Refuse it.
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "daemon", "bpf", "schema"], cwd=ROOT,
                           capture_output=True, text=True)
    if dirty.returncode or dirty.stdout.strip():
        print("the working tree differs from git; commit or restore it first:\n" + dirty.stdout, flush=True)
        return 2
    orig = {f: (ROOT / "daemon" / f).read_text() for f in files}
    killed = 0
    # SIGTERM and SIGHUP (pkill, a closed terminal) unwind like Ctrl-C, so `finally` restores the sources
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(130))
    try:
        # the unmutated tree must pass both test commands, or "killed" would mean nothing
        for name, test in (("unit tests", UNIT), ("end-to-end test", IT)):
            r = subprocess.run(f"timeout 300 sh -c '{test}'", shell=True, cwd=ROOT, capture_output=True, text=True)
            if r.returncode:
                print(f"baseline: the {name} fail on the unmutated tree (exit {r.returncode}); no mutant was run\n"
                      + (r.stdout + r.stderr)[-3000:], flush=True)
                return 2
            print(f"baseline: the {name} pass", flush=True)
        for i, (f, old, new, test) in enumerate(M):
            if orig[f].count(old) != 1:
                print(f"mutant {i}: anchor not found exactly once in {f}; update this sweep", flush=True)
                return 2
            (ROOT / "daemon" / f).write_text(orig[f].replace(old, new))
            r = subprocess.run(f"timeout 180 sh -c '{test}'", shell=True, cwd=ROOT, capture_output=True, text=True)
            (ROOT / "daemon" / f).write_text(orig[f])
            built = "error:" not in r.stdout + r.stderr
            dead = r.returncode != 0 and built
            killed += dead
            tag = "killed  " if dead else ("NO BUILD" if not built else "SURVIVED")
            print(tag, i, f, old.strip().splitlines()[0][:70], flush=True)
    finally:
        for f, text in orig.items():
            (ROOT / "daemon" / f).write_text(text)
        subprocess.run("make -s build/p15d build/test_queue build/test_config", shell=True, cwd=ROOT)
    print(f"mutation sweep: {killed}/{len(M)} killed")
    return 0 if killed == len(M) else 1


if __name__ == "__main__":
    sys.exit(main())
