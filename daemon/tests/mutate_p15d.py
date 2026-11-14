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
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
UNIT = ("make -s build/test_queue build/test_config build/test_run build/test_counters build/test_canary && build/test_queue && "
        "build/test_config && build/test_run && build/test_counters && build/test_canary 2>/dev/null")
IT = "make -s build/p15d build/p15w-inspect build/test_open_iter && daemon/tests/it_p15d.sh build"
SPACE = "make -s build/test_space && build/test_space"
WAL = "make -s build/test_wal && build/test_wal"

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
    ("writer.c", "\tif (drained != atomic_load(&r->spine_written) + atomic_load(&r->spine_drain_lost) + atomic_load(&r->spine_shed)) {", "\tif (0) {", UNIT),
    ("writer.c", "\tif (emitted != drained + atomic_load(&r->spine_invalid)) {", "\tif (0) {", UNIT),
    ("writer.c", "\tbuf.e.signal = (uint32_t)atomic_load(&w->run->stop_signal);", "", IT),
    ("run.c", "\tcase P15_RUN_DEGRADED:\n\t\treturn P15_EXIT_DEGRADED;\n\tdefault:\n\t\treturn P15_EXIT_INVALID;", "\tdefault:\n\t\treturn P15_EXIT_OK;", IT),
    # file identity (ADR-0015, step 2a part 2): the shared bulk ring's books, FILE_STATS, the run state
    ("drain.c", "atomic_fetch_add(is_net ? &d->run->net_drained : &d->run->file_drained, 1);",
     "atomic_fetch_add(&d->run->net_drained, 1);", IT),
    ("writer.c", "\tif (r->files) {\n\t\tif (file_books(r, why, n))", "\tif (0) {\n\t\tif (file_books(r, why, n))", UNIT),
    ("writer.c", "A(BACKING_LOST) + A(FENTRY_NO_INODE)) {", "A(BACKING_LOST)) {", UNIT),
    ("writer.c", "if (A(SESSION_ENTRY) + A(SESSION_RETURNED_AFTER_COUNT) + A(SESSION_NOSLOT_RETURN) !=\n\t    A(SESSION_RETURN) + A(SESSION_NO_INODE) + A(SESSION_GATED) + A(SESSION_OPEN_AT_END) + A(SESSION_NOSLOT_ENTRY)) {", "if (0) {", UNIT),
    ("writer.c", "A(RET_BACKING) + A(SESSION_NO_COOKIE) + A(SESSION_NO_ENTRY)) {", "A(RET_BACKING) + A(SESSION_NO_ENTRY)) {", UNIT),
    ("writer.c", "A(MISSING_EMITTED) + A(MISSING_LOST) + A(VERDICT_EMITTED)", "A(MISSING_EMITTED) + A(VERDICT_EMITTED)", UNIT),
    # gate 3: the drain's adaptive poll and the writer's wait until its next deadline
    ("drain.c", "\tif (took || queue_full || max_ms <= P15_POLL_MIN_MS)", "\tif (took || (queue_full && 0) || max_ms <= P15_POLL_MIN_MS)", UNIT),
    ("drain.c", "\tif (took || queue_full || max_ms <= P15_POLL_MIN_MS)", "\tif ((took && 0) || queue_full || max_ms <= P15_POLL_MIN_MS)", UNIT),
    ("drain.c", "\tint next = cur_ms * 2;", "\tint next = cur_ms + P15_POLL_MIN_MS;", UNIT),
    ("drain.c", "return next > max_ms ? max_ms : next < P15_POLL_MIN_MS ? P15_POLL_MIN_MS : next;", "return next;", UNIT),
    ("writer.c", "\tif (wal_due_ns < ns)\n\t\tns = wal_due_ns;", "\tif (wal_due_ns < ns && 0)\n\t\tns = wal_due_ns;", UNIT),
    ("writer.c", "\tns = (ns + 999999) / 1000000;", "\tns = ns / 1000000;", UNIT),
    ("writer.c", "return ns < 1 ? 1 : ns > P15_WRITER_WAIT_MAX_MS ? P15_WRITER_WAIT_MAX_MS : (int)ns;", "return (int)ns;", UNIT),
    # ADR-0029: the return's walk and BACKING on the books
    ("writer.c", "A(VERDICT_LOST) + A(RET_BACKING) + A(SESSION_NO_COOKIE)", "A(VERDICT_LOST) + A(SESSION_NO_COOKIE)", UNIT),
    ("writer.c", "if (A(MISSING_EMITTED) != A(WALKED) + A(WALK_UNNAMED) ||", "if (A(MISSING_EMITTED) != A(WALKED) ||", UNIT),
    ("writer.c", "A(RET_BACKING) != A(RET_BACKING_EMITTED) + A(RET_BACKING_LOST)) {", "0) {", UNIT),
    ("writer.c", "\t\t\t   A(RET_BACKING_EMITTED) + A(RET_BACKING_VERDICT_EMITTED);", "\t\t\t   A(RET_BACKING_EMITTED);", UNIT),
    ("writer.c", "if (A(FREE_RUN) != A(CLOSE_EMITTED) + A(CLOSE_LOST) + A(FREE_UNREGISTERED)) {", "if (0) {", UNIT),
    ("writer.c", "uint64_t taken = atomic_load(&r->file_drained) + r->file_selftest_consumed + atomic_load(&r->file_invalid);",
     "uint64_t taken = atomic_load(&r->file_drained) + r->file_selftest_consumed;", UNIT),
    ("writer.c", "if (!r->net && atomic_load(&r->file_drained) != atomic_load(&r->net_written) + atomic_load(&r->net_drain_lost)) {",
     "if (0) {", UNIT),
    # the facts epoch (E-0151): without it an object first opened during the self-tests has no facts in the WAL
    ("loader.c", "\tif (l->file)\n\t\tl->file->data->facts_epoch++;", "", IT),
    ("writer.c", "\tif (w->run->files)\n\t\tfile_stats(w);", "\tif (0)\n\t\tfile_stats(w);", IT),
    ("loader.c", "\tif (o->files && (code = load_file(l, o, err, errlen)))\n\t\treturn code;",
     "\tif (0 && (code = load_file(l, o, err, errlen)))\n\t\treturn code;", IT),
    # the snapshot's FD pass (ADR-0015 rule 7, E-0160): case 9 of it_p15d.sh
    ("snapshot.c", "\tif (s->fd_link && !k.wal_rc)\n\t\tfd_pass(s, &k, kind);", "\tif (0 && s->fd_link && !k.wal_rc)\n\t\tfd_pass(s, &k, kind);", IT),
    ("snapshot.c", "\tif (kind == P15_SNAP_OPENING)\n\t\t__atomic_add_fetch(&s->file->data->facts_epoch, 1, __ATOMIC_SEQ_CST);",
     "\tif (0 && kind == P15_SNAP_OPENING)\n\t\t__atomic_add_fetch(&s->file->data->facts_epoch, 1, __ATOMIC_SEQ_CST);", IT),
    ("p15d.c", "\tp15_snapshot_set_fd(&snap, ld.file, ld.fd_iter_link);", "\tp15_snapshot_set_fd(&snap, NULL, NULL);", IT),
    # the stop's watchdog (E-0162)
    ("run.c", "\treturn ++w->still >= r->cfg.stop_stall_s * 10u;", "\treturn 0;", UNIT),
    ("run.c", "\tif (now_ns - w->at_ns < 100000000ull)\n\t\treturn 0;                    /* not yet an observation */", "", UNIT),
    ("run.c", "\tif (b != w->beats || !w->at_ns) {", "\tif (!w->at_ns) {", UNIT),
    ("p15d.c", "\t\t\tif (p15_writer_stalled(&run, &wd, p15_mono_ns()))\n\t\t\t\treturn stuck(&run, &ld, \"the closing snapshot\");",
     "\t\t\tif (0 && p15_writer_stalled(&run, &wd, p15_mono_ns()))\n\t\t\t\treturn stuck(&run, &ld, \"the closing snapshot\");", IT),    # room before a read (E-0173): the unit test of p15_drain_room, and case 11 of it_p15d.sh
    ("drain.c", "\treturn (d->open->cap - d->open->len) / P15_RECORD_MAX_SIZE;", "\treturn (d->open->cap - d->open->len) / P15_RECORD_MAX_SIZE + 1;", UNIT),
    ("drain.c", "(d->open->ring != ring || d->open->cap - d->open->len < P15_RECORD_MAX_SIZE))", "(d->open->ring != ring))", UNIT),
    ("drain.c", "(d->open->ring != ring || d->open->cap - d->open->len < P15_RECORD_MAX_SIZE))", "(d->open->cap - d->open->len < P15_RECORD_MAX_SIZE))", UNIT),
    ("drain.c", "\t\tgot = ring__consume_n(r, room);", "\t\tgot = ring__consume(r);", IT),
    ("drain.c", "\tn = take_all(d);\n\tnote_poll_gap(d, p15_boot_ns());", "\tn = ring_buffer__consume(d->rb);\n\tnote_poll_gap(d, p15_boot_ns());", IT),
    ("drain.c", "\tint n = d->spine ? take(d, d->spine, P15W_RING_SPINE) : 0, m;", "\tint n = 0, m;", IT),
    # the end of the flow programs' run (bpf/include/p15_flow.h; the design note of 2026-11-13): B1's
    # terms by the unit test, the stop's order and the programs' count word by it_p15d cases 15 to 17
    ("writer.c", "+ L(V_OWNED_BY_SOCK) + L(V_GATED) + L(OPEN_AT_END) +", "+ L(V_OWNED_BY_SOCK) + L(OPEN_AT_END) +", UNIT),
    ("writer.c", "+ L(V_OWNED_BY_SOCK) + L(V_GATED) + L(OPEN_AT_END) +", "+ L(V_OWNED_BY_SOCK) + L(V_GATED) +", UNIT),
    ("writer.c", "if (L(SESS_ENTRY) + L(RETURNED_AFTER_COUNT) + L(V_RELEASE_FAILED) + L(V_NO_SLOT_RETURN) !=",
     "if (L(SESS_ENTRY) + L(V_RELEASE_FAILED) + L(V_NO_SLOT_RETURN) !=", UNIT),
    ("writer.c", "if (L(SESS_ENTRY) + L(RETURNED_AFTER_COUNT) + L(V_RELEASE_FAILED) + L(V_NO_SLOT_RETURN) !=",
     "if (L(SESS_ENTRY) + L(RETURNED_AFTER_COUNT) + L(V_NO_SLOT_RETURN) !=", UNIT),
    ("writer.c", "if (L(SESS_ENTRY) + L(RETURNED_AFTER_COUNT) + L(V_RELEASE_FAILED) + L(V_NO_SLOT_RETURN) !=",
     "if (L(SESS_ENTRY) + L(RETURNED_AFTER_COUNT) + L(V_RELEASE_FAILED) !=", UNIT),
    ("writer.c", "	    L(V_NO_SLOT_ENTRY)) {", "	    0) {", UNIT),
    ("barrier.c", "	if (test_fail)\n		return -ENOSYS;", "	(void)test_fail;", IT),
    ("p15d.c", "	p15_run_set_state(r, P15_RUN_DEGRADED, msg);\n}\n\n/*\n * The end of the sessions", "}\n\n/*\n * The end of the sessions", IT),
    ("p15d.c", "	rc = p15_loader_flow_count(l);\n", "	rc = 0;\n", IT),
    ("p15d.c", "	p15_loader_flow_gate(l);\n", "", IT),
    ("../bpf/progs/file.bpf.c", "	if (__sync_fetch_and_add(&st->open, 1) & P15_FLOW_OPEN_MASK)", "	if (0)", IT),
    ("../bpf/progs/file.bpf.c", "		if (st)\n			rw_release(st);\n		else", "		if (st)\n			(void)rw_release;\n		else", IT),
    ("../bpf/progs/file.bpf.c", "		if (claimed)\n			nw = w - P15_FLOW_CLAIM_ONE;\n		else if", "		if (0)\n			nw = w - P15_FLOW_CLAIM_ONE;\n		else if", IT),
    ("../bpf/progs/file.bpf.c", "	if (flow_gate) {", "	if (0) {", IT),
    # a return that never finds its call in the count: V_RELEASE_NONE moves (case 13's check)
    ("../bpf/progs/file.bpf.c", "		else if (w & P15_FLOW_OPEN_MASK)\n			nw = w - 1;", "		else if (0)\n			nw = w - 1;", IT),
    # the open path's session at the end (bpf/include/p15_file.h; it_p15d cases 18 and 19): the book's
    # terms, then the gate, the count, the return's claimed branch and the iterator's claim
    ("writer.c", "if (A(SESSION_ENTRY) + A(SESSION_RETURNED_AFTER_COUNT) + A(SESSION_NOSLOT_RETURN) !=", "if (A(SESSION_ENTRY) + A(SESSION_NOSLOT_RETURN) !=", UNIT),
    ("writer.c", "if (A(SESSION_ENTRY) + A(SESSION_RETURNED_AFTER_COUNT) + A(SESSION_NOSLOT_RETURN) !=", "if (A(SESSION_ENTRY) + A(SESSION_RETURNED_AFTER_COUNT) !=", UNIT),
    ("writer.c", "A(SESSION_NO_INODE) + A(SESSION_GATED) + A(SESSION_OPEN_AT_END) + A(SESSION_NOSLOT_ENTRY)) {", "A(SESSION_NO_INODE) + A(SESSION_OPEN_AT_END) + A(SESSION_NOSLOT_ENTRY)) {", UNIT),
    ("writer.c", "A(SESSION_NO_INODE) + A(SESSION_GATED) + A(SESSION_OPEN_AT_END) + A(SESSION_NOSLOT_ENTRY)) {", "A(SESSION_NO_INODE) + A(SESSION_GATED) + A(SESSION_NOSLOT_ENTRY)) {", UNIT),
    ("writer.c", "A(SESSION_NO_INODE) + A(SESSION_GATED) + A(SESSION_OPEN_AT_END) + A(SESSION_NOSLOT_ENTRY)) {", "A(SESSION_NO_INODE) + A(SESSION_GATED) + A(SESSION_OPEN_AT_END)) {", UNIT),
    ("p15d.c", "	p15_loader_file_gate(l);\n", "", IT),
    ("p15d.c", "	rc = p15_loader_file_count(l);\n", "	rc = 0;\n", IT),
    ("../bpf/progs/file.bpf.c", "		if (file_gate) {", "		if (0) {", IT),
    ("../bpf/progs/file.bpf.c", "	    (__sync_fetch_and_or(&fe->state, ST_SESSION_RETURNED) & ST_SESSION_CLAIMED))", "	    (__sync_fetch_and_or(&fe->state, ST_SESSION_RETURNED) & 0))", IT),
    ("../bpf/progs/file.bpf.c", "		if (__sync_val_compare_and_swap(&fe->state, s, s | ST_SESSION_CLAIMED) == s) {\n			count(P15_FC_SESSION_OPEN_AT_END);", "		if (__sync_val_compare_and_swap(&fe->state, s, s | ST_SESSION_CLAIMED) == s) {", IT),
    ("../bpf/progs/file.bpf.c", "		if ((s & (ST_SESSION_ENTRY | ST_SESSION_RETURNED | ST_SESSION_CLAIMED)) != ST_SESSION_ENTRY)", "		if ((s & (ST_SESSION_ENTRY | ST_SESSION_CLAIMED)) != ST_SESSION_ENTRY)", IT),
    # the self-check (ADR-0019 G4.4; canary.c, selfcheck.c; test_canary and it_p15d cases 21 to 25)
    ("canary.c", "		if (now - c->last_poll_ns > P15_CANARY_STALL_NS) {", "		if (0) {", UNIT),
    ("canary.c", "now >= c->deadline_ns && c->polls >= P15_CANARY_POLLS && !took &&", "now >= c->deadline_ns && !took &&", UNIT),
    ("canary.c", "now >= c->deadline_ns && c->polls >= P15_CANARY_POLLS && !took &&", "now >= c->deadline_ns && c->polls >= P15_CANARY_POLLS && !(took && 0) &&", UNIT),
    ("canary.c", "			finish(c, c->all_seen_ns > c->deadline_ns ? P15_CANARY_MISS_KIND_LATE : 0,", "			finish(c, 0,", UNIT),
    ("canary.c", "				c->cur_want &= ~P15_CANARY_EXEC;\n", "", UNIT),
    ("canary.c", "		p15_run_set_state(c->run, P15_RUN_DEGRADED, msg);\n		publish_bad(c, kind, late_ns);", "		publish_bad(c, kind, late_ns);", IT),
    ("canary.c", "		p15_run_set_state(c->run, P15_RUN_DEGRADED, msg);\n		publish_bad(c, kind, late_ns);", "		p15_run_set_state(c->run, P15_RUN_DEGRADED, msg);\n		(void)publish_bad;\n		(void)late_ns;", IT),
    ("selfcheck.c", "		if (!err && info.id == r->links[i].id && info.prog_id == r->links[i].prog_id)", "		if (1)", IT),
    ("writer.c", "		p15_run_set_state(r, P15_RUN_DEGRADED, msg);\n		memset(&m, 0, sizeof(m));\n		m.kind = P15_CANARY_MISS_KIND_LINK;", "		memset(&m, 0, sizeof(m));\n		m.kind = P15_CANARY_MISS_KIND_LINK;", IT),
    ("p15d.c", "	rc = p15_loader_each_link(&ld, link_add, &run);\n", "	rc = 0;\n	(void)link_add;\n", IT),
    ("drain.c", "	atomic_fetch_add(&d->run->spine_seq_next, 1);\n	p15_canary_see(&d->canary, h);", "	atomic_fetch_add(&d->run->spine_seq_next, 1);", IT),
    # the open-file map's size from the host and its full state (decision 103; test_config, cases 26 and 27)
    ("config.c", "	if (want < P15_FILE_MAP_DEFAULT)\n", "	if (0)\n", UNIT),
    ("config.c", "	if (want > cap)\n", "	if (0)\n", UNIT),
    ("config.c", "	if (cap > P15_FILE_MAP_MAX)\n", "	if (0)\n", UNIT),
    ("config.c", "	uint64_t want = files_now * P15_FILE_MAP_HEADROOM;", "	uint64_t want = files_now;", UNIT),
    ("p15d.c", "		run.cfg.file_map_entries = p15_file_map_auto(files, mem);\n", "", IT),
    ("drain.c", "	if (f[P15_FC_FILE_MAP_FULL] != d->prev_file[P15_FC_FILE_MAP_FULL])\n		p15_run_set_state(d->run, P15_RUN_DEGRADED,", "	if (0)\n		p15_run_set_state(d->run, P15_RUN_DEGRADED,", IT),
    # the WAL's free-space guard (F-02; space.c, wal.c, writer.c; test_space, test_wal, test_run, it_p15d 28 and 29)
    ("space.c", "	if (avail < s->reserve)\n		return P15_SPACE_SHED_ALL;", "	if (0)\n		return P15_SPACE_SHED_ALL;", SPACE),
    ("space.c", "	if (lv == P15_SPACE_SHED_ALL && avail < up_res)", "	if (lv == P15_SPACE_SHED_ALL && avail < up_res - s->reserve / 8)", SPACE),
    ("space.c", "	if (lv >= P15_SPACE_SHED_BULK && avail < up_low)", "	if (lv >= P15_SPACE_SHED_BULK && avail < up_low - s->low / 8)", SPACE),
    ("space.c", "	s->avail = s->avail > bytes ? s->avail - bytes : 0;", "	(void)bytes;", SPACE),
    ("space.c", "		return s->level < P15_SPACE_SHED_ALL;", "		return 1;", SPACE),
    ("space.c", "	if (l < 2 * r)\n		l = 2 * r;", "	if (0)\n		l = 2 * r;", SPACE),
    ("wal.c", "		if (ftruncate(w->fd, (off_t)w->seg_bytes) || lseek(w->fd, (off_t)w->seg_bytes, SEEK_SET) < 0)", "		if (lseek(w->fd, (off_t)w->seg_bytes, SEEK_SET) < 0)", WAL),
    ("wal.c", "	if (rc == -ENOSPC || rc == -EDQUOT) {\n		/* the disk is full (F-02)", "	if (0) {\n		/* the disk is full (F-02)", WAL),
    ("wal.c", "	if (!w->in_open && !w->hold_rotation && w->seg_batches > 0", "	if (!w->in_open && w->seg_batches > 0", WAL),
    ("writer.c", "	if (drained != atomic_load(&r->spine_written) + atomic_load(&r->spine_drain_lost) + atomic_load(&r->spine_shed)) {", "	if (drained != atomic_load(&r->spine_written) + atomic_load(&r->spine_drain_lost)) {", UNIT),
    ("writer.c", "	if (!p15_space_allows(&w->space, ring)) {\n		shed(w, ring, count, buf, len, 0);\n		return;\n	}", "", IT),
    ("writer.c", "	p15_run_set_state(r, P15_RUN_DEGRADED, msg);\n}\n\nstatic void append", "}\n\nstatic void append", IT),
    ("writer.c", "		if (p15_space_refresh(&w->space, p15w_fd(w->wal)) > 0)\n			space_changed(w);\n", "", IT),
    ("writer.c", "			forks += h->type == P15_T_FORK;", "			forks += 0;", IT),   # 122: shed FORKs uncounted: the tree check goes INVALID
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
    # `mutate_p15d.py 40 41` runs only those mutants (after a sweep in which they did not build)
    only = {int(a) for a in sys.argv[1:]}
    # SIGTERM and SIGHUP (pkill, a closed terminal) unwind like Ctrl-C, so `finally` restores the sources
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(130))
    try:
        # The unmutated tree must pass both test commands, or "killed" would mean nothing. Their time
        # sets each mutant's limit: a mutant is killed only by a failed check, never by the clock (a
        # VirtualBox guest can stall for minutes, E-0088); a mutant that runs out of time is TIMEOUT and
        # is not counted as killed (E-0157).
        limit = {}
        names = {UNIT: "unit tests", IT: "end-to-end test", SPACE: "space-guard tests", WAL: "WAL tests"}
        needed = [t for t in names if any(m[3] == t for i, m in enumerate(M) if not only or i in only)]
        for name, test in ((names[t], t) for t in needed):
            t0 = time.monotonic()
            r = subprocess.run(f"timeout 900 sh -c '{test}'", shell=True, cwd=ROOT, capture_output=True, text=True)
            dt = time.monotonic() - t0
            if r.returncode:
                print(f"baseline: the {name} fail on the unmutated tree (exit {r.returncode} after {dt:.0f} s); "
                      "no mutant was run\n" +
                      "".join(ln + "\n" for ln in (r.stdout + r.stderr).splitlines() if "FAIL" in ln) +   # wherever it failed
                      (r.stdout + r.stderr)[-3000:], flush=True)
                return 2
            limit[test] = max(120, int(4 * dt))
            print(f"baseline: the {name} pass in {dt:.0f} s; a mutant gets {limit[test]} s", flush=True)
        for i, (f, old, new, test) in enumerate(M):
            if only and i not in only:
                continue
            if orig[f].count(old) != 1:
                print(f"mutant {i}: anchor not found exactly once in {f}; update this sweep", flush=True)
                return 2
            (ROOT / "daemon" / f).write_text(orig[f].replace(old, new))
            t0 = time.monotonic()
            r = subprocess.run(f"timeout {limit[test]} sh -c '{test}'", shell=True, cwd=ROOT, capture_output=True,
                               text=True)
            dt = time.monotonic() - t0
            (ROOT / "daemon" / f).write_text(orig[f])
            built = "error:" not in r.stdout + r.stderr
            timed_out = r.returncode == 124
            dead = r.returncode != 0 and built and not timed_out
            killed += dead
            tag = ("killed  " if dead else "NO BUILD" if not built else "TIMEOUT " if timed_out else "SURVIVED")
            print(f"{tag} {i} {f} {old.strip().splitlines()[0][:70]} ({dt:.0f} s)", flush=True)
    finally:
        for f, text in orig.items():
            (ROOT / "daemon" / f).write_text(text)
        subprocess.run("make -s build/p15d build/test_queue build/test_config", shell=True, cwd=ROOT)
    total = len(only) if only else len(M)
    print(f"mutation sweep: {killed}/{total} killed" + (f" (mutants {sorted(only)} only)" if only else ""), flush=True)
    return 0 if killed == total else 1


if __name__ == "__main__":
    sys.exit(main())
