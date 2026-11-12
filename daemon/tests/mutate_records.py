#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation sweep for the record checks and formatting, daemon/records.c (CONTRIBUTING §6).

Each mutant plants one bug in daemon/records.c (or, with a leading "snapshot_frame.c" entry,
in daemon/snapshot_frame.c), rebuilds daemon/tests/test_records.c,
daemon/tests/test_selftest.c and daemon/tests/test_snapshot.c against it, and expects at least
one of them to fail. The source
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
import signal
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "daemon" / "records.c"
FRAME = ROOT / "daemon" / "snapshot_frame.c"
CC = os.environ.get("CC", "cc")
LIBBPF_INC = ROOT / "build" / "libbpf"

M = [
 # the header and len rules every record must pass
 ("if (h->len > size) {", "if (h->len > size + 8) {"),
 ("if (h->len % 8) {", "if (h->len % 4) {"),
 ("if (h->len < fixed) {", "if (h->len + 8 < fixed) {"),
 ("case P15_T_STATS:  return version == 1 ?", "case P15_T_STATS:  return version >= 1 ?"),
 ("case P15_T_GAP:    return version == 1 ? sizeof(struct p15_gap_v1) : version == 2 ? sizeof(struct p15_gap_v2) : 0;", "case P15_T_GAP:    return 0;"),
 ("version == 2 ? sizeof(struct p15_stats_v2) : 0;", "version == 2 ? sizeof(struct p15_stats_v1) : 0;"),
 ("version == 2 ? sizeof(struct p15_net_stats_v2) : 0;", "0;"),
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
 # EXEC v2 (ADR-0025): the new size, the exe_name clause, the three-field tail and the v2 formatter
 ("case P15_T_EXEC:   return version == 1 ? sizeof(struct p15_exec_v1) : version == 2 ? sizeof(struct p15_exec_v2) : 0;",
  "case P15_T_EXEC:   return version == 1 ? sizeof(struct p15_exec_v1) : 0;"),
 ("e->exe_name_len > P15_EXEC_V2_EXE_NAME_MAX) {", "0) {"),
 ("tail = (size_t)e->filename_len + e->argv_len + e->exe_name_len;",
  "tail = (size_t)e->filename_len + e->argv_len;"),
 ("printable(nm, sizeof(nm), tail + r->filename_len + r->argv_len, r->exe_name_len);",
  "printable(nm, sizeof(nm), tail, r->exe_name_len);"),
 ("if (rl > P15_END_V1_REASON_MAX) {", "if (0) {"),
 ("if (check_tail(data, fixed, rl, 0, why))", "if (check_tail(data, fixed, rl, 1, why))"),
 # END v2 (ADR-0023 rule 1)
 ("case P15_T_END:    return version == 1 ? sizeof(struct p15_end_v1) : version == 2 ? sizeof(struct p15_end_v2) : 0;",
  "case P15_T_END:    return version >= 1 ? sizeof(struct p15_end_v1) : 0;"),
 ("__u16 rl = h->version == 1 ? ((const struct p15_end_v1 *)data)->reason_len",
  "__u16 rl = h->version >= 1 ? ((const struct p15_end_v1 *)data)->reason_len"),
 ("if (h->version >= 2 && ((const struct p15_end_v2 *)data)->reserved) {", "if (0) {"),
 ('m += snprintf(buf + m, n - (size_t)m, " closing_snapshot=%d", r2->closing_snapshot);', "m += 0;"),
 # PROC and SNAP_DONE (ADR-0007 rule 3): checked by test_snapshot.c
 ("case P15_T_PROC:   return version == 1 ? sizeof(struct p15_proc_v1) : version == 2 ? sizeof(struct p15_proc_v2) : 0;",
  "case P15_T_PROC:   return version == 1 ? sizeof(struct p15_proc_v1) : 0;"),
 ("if (ep_len > P15_PROC_V1_EXE_PATH_MAX || av_len > P15_PROC_V1_ARGV_MAX) {", "if (ep_len > P15_PROC_V1_EXE_PATH_MAX) {"),
 ("if (ep_len > P15_PROC_V2_EXE_PATH_MAX || av_len > P15_PROC_V2_ARGV_MAX) {", "if (ep_len > P15_PROC_V2_EXE_PATH_MAX) {"),
 ("if (reserved || (kind != 1 && kind != 2) || (pflags & ~3u)) {", "if (reserved || (pflags & ~3u)) {"),
 ("if (reserved || (kind != 1 && kind != 2) || (pflags & ~3u)) {", "if (reserved || (kind != 1 && kind != 2)) {"),
 ("if (check_tail(data, fixed, (size_t)ep_len + av_len, 0, why))",
  "if (check_tail(data, fixed, (size_t)ep_len + av_len, 1, why))"),
 ("((const struct p15_snap_done_v2 *)data)->kind) != 2) {", "((const struct p15_snap_done_v2 *)data)->kind) != 0) {"),
 ("(h->version == 1 ? ((const struct p15_snap_done_v1 *)data)->kind : ((const struct p15_snap_done_v2 *)data)->kind) != 1 &&",
  "((const struct p15_snap_done_v1 *)data)->kind != 1 &&"),
 ("nlink=%u fsmagic=0x%x mode=0%o uid=%u self_exec_id=%llu ", "nlink=%u fsmagic=0x%x mode=0%o uid=%u "),
 # names and formatting
 ('case P15_T_END:        return "END";', 'case P15_T_END:        return "?";'),
 ('case P15_T_GAP:        return "GAP";', 'case P15_T_GAP:        return "END";'),
 ("(unsigned long long)r->fork_build_failed, (unsigned long long)r->exec_build_failed,",
  "(unsigned long long)r->exec_build_failed, (unsigned long long)r->fork_build_failed,"),
 ("(unsigned long long)r->spine_written,", "(unsigned long long)r->spine_invalid,"),
 ("printable(b, sizeof(b), (const __u8 *)(r1 + 1), r1->reason_len);", "printable(b, sizeof(b), (const __u8 *)(r1 + 1), 4);"),
 # ADR-0022: NET v2, its ISN flag and the bytes around it
 ("case P15_T_NET:    return version == 1 ? sizeof(struct p15_net_v1) : version == 2 ? sizeof(struct p15_net_v2) : 0;",
  "case P15_T_NET:    return version == 1 ? sizeof(struct p15_net_v1) : 0;"),
 ("if (h->flags & ~(__u16)(P15_F_TRUNCATED | P15_F_READ_FAILED | P15_F_ISN)) {", "if (0) {"),
 ("if ((h->flags & P15_F_ISN) && !(h->type == P15_T_NET && h->version >= 2)) {", "if (0) {"),
 ("if (r->reserved || (!(h->flags & P15_F_ISN) && r->tcp_isn)) {", "if (r->reserved) {"),
 ("if (r->reserved || (!(h->flags & P15_F_ISN) && r->tcp_isn)) {", "if (!(h->flags & P15_F_ISN) && r->tcp_isn) {"),
 ('m += snprintf(buf + m, n - (size_t)m, " isn=%u", r->tcp_isn);', "m += 0;"),
 # file identity (ADR-0015, STATE decision 19): OPEN, OPEN_VERDICT, BACKING, CLOSE, FD
 ("case P15_T_OPEN:   return version == 1 ? sizeof(struct p15_open_v1) : 0;", "case P15_T_OPEN:   return 0;"),
 ("\tif (p15_is_file_type(h->type) || h->type == P15_T_FD || h->type == P15_T_FILE) {", "\tif (0) {"),
 ("if ((len != 0 && len != sizeof(*f)) || full != len) {", "if (len != 0 && len != sizeof(*f)) {"),
 ("if ((len != 0 && len != sizeof(*f)) || full != len) {", "if (full != len) {"),
 ("\tif (!!len != !!want) {", "\tif (0) {"),
 ("if (len && ((f->oflags & ~1u) || f->seen < 1 || f->seen > 5)) {", "if (len && (f->seen < 1 || f->seen > 5)) {"),
 ("if (len && ((f->oflags & ~1u) || f->seen < 1 || f->seen > 5)) {", "if (len && (f->oflags & ~1u)) {"),
 ("\t	if (r->fflags & ~ok) {", "\t	if (0) {"),
 ("\t	if (!!(r->fflags & P15_FF_PATH_ERROR) != !!r->path_err) {\n\t\t\t*why = \"OPEN:", "\t\tif (0) {\n\t\t\t*why = \"OPEN:"),
 ("\t	if (!(r->fflags & ret) && r->verdict) {", "\t\tif (0) {"),
 ("\t	if (!(r->fflags & ret) && r->verdict) {", "\t\tif (!(r->fflags & P15_FF_PATH_MISSING) && r->verdict) {"),
 ("if ((r->fflags & ret) == ret || ((r->fflags & P15_FF_PATH_RACED) && !(r->fflags & P15_FF_PATH_WALKED))) {", "if ((r->fflags & ret) == ret) {"),
 ("if ((r->fflags & ret) == ret || ((r->fflags & P15_FF_PATH_RACED) && !(r->fflags & P15_FF_PATH_WALKED))) {", "if ((r->fflags & P15_FF_PATH_RACED) && !(r->fflags & P15_FF_PATH_WALKED)) {"),
 ("if ((r->fflags & P15_FF_PATH_WALKED) && (r->fflags & (P15_FF_PATH_ERROR | P15_FF_FULL_SIZE))) {", "if (0) {"),
 ("(r->fflags & P15_FF_FULL_SIZE) && h->len == P15_OPEN_V1_MAX_SIZE, why);", "(r->fflags & P15_FF_FULL_SIZE), why);"),
 ("(r->fflags & P15_FF_FULL_SIZE) && h->len == P15_OPEN_V1_MAX_SIZE, why);", "h->len == P15_OPEN_V1_MAX_SIZE, why);"),
 ("\t	if (r->verdict >= 0) {", "\t\tif (r->verdict > 0) {"),
 ("r->fflags & P15_FF_USER_OBJ_NEW, \"BACKING: user_facts", "r->fflags & P15_FF_OBJ_NEW, \"BACKING: user_facts"),
 ("if (((const struct p15_close_v1 *)data)->fflags & ~(P15_FF_NEVER_OPENED | P15_FF_KTHREAD)) {", "if (0) {"),
 ("if (check_part(data, fixed, r->facts_len, r->facts_full, 1, \"FD:", "if (check_part(data, fixed, r->facts_len, r->facts_full, r->facts_len, \"FD:"),
 ("fixed + r->facts_len + r->path_len > h->len) {\n\t\t\t*why = \"variable field beyond len\";\n\t\t\treturn -EINVAL;\n\t\t}\n\t\tif (check_part(data, fixed, r->facts_len, r->facts_full, r->fflags & P15_FF_OBJ_NEW,",
  "fixed + r->facts_len + r->path_len > h->len + 8) {\n\t\t\t*why = \"variable field beyond len\";\n\t\t\treturn -EINVAL;\n\t\t}\n\t\tif (check_part(data, fixed, r->facts_len, r->facts_full, r->fflags & P15_FF_OBJ_NEW,"),
 ("return type == P15_T_OPEN || type == P15_T_OPEN_VERDICT || type == P15_T_BACKING || type == P15_T_CLOSE;", "return type == P15_T_OPEN || type == P15_T_OPEN_VERDICT || type == P15_T_BACKING;"),
 # SNAP_DONE v2 (ADR-0015 rule 7)
 ("case P15_T_SNAP_DONE: return version == 1 ? sizeof(struct p15_snap_done_v1) : version == 2 ? sizeof(struct p15_snap_done_v2) : 0;",
  "case P15_T_SNAP_DONE: return version == 1 ? sizeof(struct p15_snap_done_v1) : 0;"),
 ("((const struct p15_snap_done_v2 *)data)->fd_pass > 1) {", "((const struct p15_snap_done_v2 *)data)->fd_pass > 2) {"),
 # data flow (ADR-0005 rules 2, 7, 8; ADR-0015 rules 2, 5, 9): FLOW and FILE
 ("case P15_T_FLOW:   return version == 1 ? sizeof(struct p15_flow_v1) : 0;", "case P15_T_FLOW:   return 0;"),
 ("case P15_T_FLOW_STATS: return version == 1 ? sizeof(struct p15_flow_stats_v1) : 0;", "case P15_T_FLOW_STATS: return 0;"),
 ("case P15_T_FLOW_STATS: return \"FLOW_STATS\";", "case P15_T_FLOW_STATS: return \"?\";"),
 ("case P15_T_FILE:   return version == 1 ? sizeof(struct p15_file_v1) : 0;", "case P15_T_FILE:   return 0;"),
 ("\t} else if (h->type == P15_T_FLOW) {", "\t} else if (0) {"),
 (" || h->type == P15_T_FD || h->type == P15_T_FILE) {", " || h->type == P15_T_FD) {"),
 ("P15_FF_VECTORED | P15_FF_START_UNKNOWN;\n", "P15_FF_VECTORED | P15_FF_START_UNKNOWN | P15_FF_KTHREAD;\n"),
 ("if (r->kind < 1 || r->kind > P15_FLOW_KIND_MAX ||", "if (r->kind > P15_FLOW_KIND_MAX ||"),
 ("r->reason < 1 || r->reason > P15_FLOW_REASON_MAX) {", "r->reason < 1 || r->reason > P15_FLOW_REASON_MAX + 1) {"),
 ("r->reason < 1 || r->reason > P15_FLOW_REASON_MAX) {", "r->reason > P15_FLOW_REASON_MAX) {"),
 ("if (r->count < 1 || r->bytes < r->count ||", "if (r->bytes < r->count ||"),
 ("if (r->count < 1 || r->bytes < r->count ||", "if (r->count < 1 ||"),
 ("(r->reason == P15_FLOW_REASON_SINGLE && r->count != 1)) {", "0) {"),
 ("if (((r->fflags & P15_FF_PEEK) && r->kind != P15_FLOW_KIND_RECV) ||", "if (0 ||"),
 ("((r->fflags & (P15_FF_VECTORED | P15_FF_START_UNKNOWN)) && !vfs)) {", "((r->fflags & P15_FF_VECTORED) && !vfs)) {"),
 ("((r->fflags & (P15_FF_VECTORED | P15_FF_START_UNKNOWN)) && !vfs)) {", "((r->fflags & P15_FF_START_UNKNOWN) && !vfs)) {"),
 ("if ((r->fflags & P15_FF_OBJ_NEW) && !(r->fflags & P15_FF_UNREGISTERED)) {", "if (0) {"),
 ("if (r->reason != P15_FLOW_REASON_SINGLE &&", "if (1 &&"),
 ("!!(r->fflags & P15_FF_UNREGISTERED) != (r->reason == P15_FLOW_REASON_MAP_FULL)) {",
  "!(r->fflags & P15_FF_UNREGISTERED) && (r->reason == P15_FLOW_REASON_MAP_FULL)) {"),
 ("if (r->facts_len > P15_PART_OBJFACTS_SIZE || fixed + r->facts_len > h->len) {", "if (0) {"),
 ("r->fflags & P15_FF_OBJ_NEW,\n\t\t       \"FLOW: facts", "r->facts_len,\n\t\t       \"FLOW: facts"),
 ("if (check_tail(data, fixed, r->facts_len, 0, why))", "if (0)"),
 ("if (memcmp(r->_pad, zero, sizeof(zero))) {\n\t\t*why = \"FLOW: non-zero padding\";", "if (0) {\n\t\t*why = \"FLOW: non-zero padding\";"),
 ("if (r->fflags & ~P15_FF_OBJ_NEW) {\n\t\t\t*why = \"FILE:", "if (0) {\n\t\t\t*why = \"FILE:"),
 ("if (r->seen < 3 || r->seen > 5) {", "if (r->seen > 5) {"),
 ("if (!!(h->flags & P15_F_TRUNCATED) != (r->name_full != r->name_len) || r->name_full < r->name_len) {",
  "if (r->name_full < r->name_len) {"),
 ("r->name_len > P15_FILE_V1_NAME_MAX ||", ""),
 ("r->fflags & P15_FF_OBJ_NEW,\n\t\t\t       \"FILE: facts", "1,\n\t\t\t       \"FILE: facts"),
 ("if (check_tail(data, fixed, (size_t)r->facts_len + r->name_len, 0, why))", "if (0)"),
 ("if (memcmp(r->_pad, zero, sizeof(zero))) {\n\t\t\t*why = \"FILE: non-zero padding\";", "if (0) {\n\t\t\t*why = \"FILE: non-zero padding\";"),
 ("case P15_T_FLOW:       return \"FLOW\";", "case P15_T_FLOW:       return \"?\";"),
 ("kinds[r->kind <= P15_FLOW_KIND_MAX ? r->kind : 0]", "kinds[0]"),
 # the snapshot's framing and FD books (snapshot_frame.c)
 ("snapshot_frame.c", "\tif (h->type != f->type)\n\t\treturn 0;", ""),
 ("snapshot_frame.c", "return h->version == P15_FD_VERSION && ((const struct p15_fd *)rec)->snap_id == f->snap_id;", "return h->version == P15_FD_VERSION;"),
 ("snapshot_frame.c", "return len >= sizeof(struct p15_fd) && len <= P15_FD_MAX_SIZE && len % 8 == 0;", "return len >= sizeof(struct p15_hdr) && len <= P15_FD_MAX_SIZE && len % 8 == 0;"),
 ("snapshot_frame.c", "\tf->entries = &done->fd_entries;", "\tf->entries = &done->entries;"),
 ("snapshot_frame.c", "\tf->invalid = &done->fd_invalid;", "\tf->invalid = &done->invalid;"),
 ("snapshot_frame.c", "\tf->error = &done->fd_error;", "\tf->error = &done->error;"),
 ("snapshot_frame.c", "\tif (!d->fd_pass)\n\t\treturn 0;", ""),
 ("snapshot_frame.c", "\tif (d->fd_error) {\n\t\tsnprintf(why, n, \"snapshot %u: reading the FD", "\tif (0) {\n\t\tsnprintf(why, n, \"snapshot %u: reading the FD"),
 ("snapshot_frame.c", "if (d->fd_files != d->fd_no_inode + d->fd_emitted + d->fd_write_failed) {", "if (d->fd_files != d->fd_emitted + d->fd_write_failed) {"),
 ("snapshot_frame.c", "if (d->fd_files != d->fd_no_inode + d->fd_emitted + d->fd_write_failed) {", "if (d->fd_files < d->fd_emitted) {"),
 ("snapshot_frame.c", "if (d->fd_emitted != d->fd_entries + d->fd_invalid + d->fd_unwritten) {", "if (0) {"),
 ("snapshot_frame.c", "if (d->fd_emitted != d->fd_known + d->fd_registered + d->fd_map_full) {", "if (d->fd_emitted != d->fd_known + d->fd_registered) {"),
 ("snapshot_frame.c", "if (d->fd_write_failed || d->fd_invalid || d->fd_unwritten) {", "if (d->fd_write_failed || d->fd_invalid) {"),
 ("snapshot_frame.c", "\treturn fd_books_close(d, why, n);", "\treturn 0;"),
 ("snapshot_frame.c", "\td->fd_pass = 1;", ""),
]


def main() -> int:
    origs = {SRC: SRC.read_text(), FRAME: FRAME.read_text()}
    killed = 0
    # SIGTERM and SIGHUP unwind like Ctrl-C, so `finally` restores the sources (E-0155's lesson; a
    # pkill during this sweep left mutant 17 in records.c, E-0160)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(130))
    with tempfile.TemporaryDirectory() as tmp:
        try:
            for i, m in enumerate(M):
                path, (old, new) = (FRAME, m[1:]) if len(m) == 3 else (SRC, m)
                orig = origs[path]
                if orig.count(old) != 1:
                    print(f"mutant {i}: anchor not found exactly once in {path.name}; update this sweep")
                    return 2
                path.write_text(orig.replace(old, new))
                inc = (f"-Idaemon -Ischema/generated -Ibpf/include -I{LIBBPF_INC} "
                       "-fsanitize=address,undefined -fno-sanitize-recover=undefined")
                build = subprocess.run(
                    f"{CC} -std=gnu11 -O1 {inc} daemon/tests/test_records.c daemon/records.c -o {tmp}/r && "
                    f"{CC} -std=gnu11 -O1 {inc} daemon/tests/test_selftest.c daemon/records.c daemon/selftest.c "
                    f"build/libbpf/libbpf.a -lelf -lz -o {tmp}/s && "
                    f"{CC} -std=gnu11 -O1 {inc} daemon/tests/test_snapshot.c daemon/snapshot_frame.c daemon/records.c "
                    f"-o {tmp}/n", shell=True, cwd=ROOT, capture_output=True, text=True)
                if build.returncode != 0:
                    path.write_text(orig)
                    print(f"mutant {i} does not compile: not a valid mutant; fix this sweep\n{build.stderr[-400:]}")
                    return 2
                r = subprocess.run(f"timeout 60 {tmp}/r && timeout 60 {tmp}/s && timeout 60 {tmp}/n", shell=True, cwd=ROOT,
                                   capture_output=True, text=True)
                path.write_text(orig)
                dead = r.returncode != 0
                killed += dead
                print(("killed   " if dead else "SURVIVED "), i, path.name, old.strip().splitlines()[0][:72], flush=True)
        finally:
            for path, text in origs.items():
                path.write_text(text)
    print(f"mutation sweep: {killed}/{len(M)} killed")
    return 0 if killed == len(M) else 1


if __name__ == "__main__":
    sys.exit(main())
