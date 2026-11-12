# SPDX-License-Identifier: MIT
"""Graph v0 (ADR-0028): the raw tables, the node rules (ADR-0009, ADR-0015 rule 3, ADR-0027), the
edges, the books and the PIDSMaker export, on synthetic runs whose every value is chosen here."""

import contextlib
import csv
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import duckdb
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scenario as SC  # noqa: E402
from p15w_build import R, batch, header, meta_for, rec, write_run  # noqa: E402

from p15.graph import __main__ as CLI  # noqa: E402
from p15.graph import build as B  # noqa: E402
from p15.graph import pidsmaker as PM  # noqa: E402
from p15.graph import raw as RAW  # noqa: E402

S = SC.S
T0 = SC.START
EXT4, TMPFS, BTRFS, PIPEFS, ANON, OVL = 0xEF53, 0x01021994, 0x9123683E, 0x50495045, 0x09041934, 0x794C7630
DEV = (8 << 20) | 1
REG, FIFO = 0o100644, 0o010600
A, B2 = (700, T0 + 10), (710, T0 + 20)          # two processes
FF = R.gen


def facts(**kw) -> bytes:
    a = np.zeros(1, R.gen.PARTS["OBJFACTS"])
    a["seen"] = 1
    for k, v in kw.items():
        a[k] = v
    return a.tobytes()


def hdr(t, p):
    return {"h_ts_ns": t, "h_tgid": p[0], "h_tid": p[0], "h_start_ns": p[1]}


def opn(t, p, fid, obj, path=b"", f=None, mode=1, fflags=0, **kw):
    var = {"path": path}
    if f is not None:
        var["facts"] = f
        fflags |= FF.FF_OBJ_NEW
    return rec("OPEN", var=var, **hdr(t, p), fid=fid, obj=obj, f_mode=mode, fflags=fflags, **kw)


def fd(t, p, fid, obj, n, f, path=b"", mode=3):
    return rec("FD", var={"facts": f, "path": path}, **hdr(t, p), fid=fid, obj=obj, fd=n, f_mode=mode, snap_id=0)


def close(t, p, fid, obj, fflags=0):
    return rec("CLOSE", **hdr(t, p), fid=fid, obj=obj, fflags=fflags)


def run_of(d: Path, spine=(), bulk=(), daemon=()) -> Path:
    daemon = [rec("CLOCK_SYNC", h_ts_ns=T0, boottime_ns=T0, monotonic_ns=T0, realtime_ns=SC.WALL)] + list(daemon)
    m = meta_for(**{"clock.boottime_ns": str(T0), "clock.realtime_ns": str(SC.WALL), "run.id": "g1"})
    seg = header(0, m) + (batch(0, 0, list(spine)) if spine else b"") + (batch(1, 0, list(bulk)) if bulk else b"") + \
        batch(2, 0, daemon)
    return write_run(d, [seg])


class Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.cons = []

    def tearDown(self):
        for c in self.cons:
            c.close()
        shutil.rmtree(self.d)

    def graph(self, **rings):
        run_of(self.d / "run", **rings)
        self.res = B.build(self.d / "run", self.d / "g.duckdb")
        return self.open()

    def open(self):
        c = duckdb.connect(str(self.d / "g.duckdb"), read_only=True)
        self.cons.append(c)
        return c

    def q(self, c, sql, *a):
        return c.execute(sql, a).fetchall()

    def node_of_fid(self, c, fid):
        return self.q(c, "SELECT file_node, rule FROM openfile WHERE fid = ?", fid)[0]


class Profile(Base):
    def test_statement_by_statement_is_the_same_graph(self):
        st = B.statements(B.SQL.read_text())
        self.assertEqual("\n".join(st).split(), B.SQL.read_text().split())   # nothing dropped or added
        self.assertGreater(len(st), 20)
        with self.assertRaisesRegex(ValueError, "ends inside a statement"):
            B.statements("SELECT 1;\nSELECT 2 -- no end;")
        bulk = [opn(T0 + 1, A, 1, 10, b"/a", facts(ino=1, dev=DEV, gen=1, mode=REG, fs_magic=EXT4)),
                opn(T0 + 2, A, 2, 11, b"/b", facts(ino=2, dev=DEV, gen=1, mode=REG, fs_magic=EXT4))]
        run_of(self.d / "one", bulk=bulk)
        whole = B.build(self.d / "one", self.d / "whole.duckdb")
        prof: list = []
        parts = B.build(self.d / "one", self.d / "parts.duckdb", prof)
        self.assertEqual(parts.counts, whole.counts)
        names = [w for w, _ in prof]
        self.assertEqual(names[:3], ["read the WAL, the process tree", "raw tables", "proc_src"])
        self.assertEqual(len(names), 3 + len(st))
        self.assertTrue(all(sec >= 0 for _, sec in prof))


class InsertRows(unittest.TestCase):
    def test_columns_with_nulls_booleans_and_text(self):
        from p15.graph import raw
        c = duckdb.connect()
        c.execute("CREATE TABLE t (a UINTEGER, b UBIGINT, c INTEGER, d VARCHAR, e BOOLEAN)")
        cols = [("a", "UINTEGER"), ("b", "UBIGINT"), ("c", "INTEGER"), ("d", "VARCHAR"), ("e", "BOOLEAN")]
        raw.insert_rows(c, "t", cols, [(1, 2**63, -1, "x y", True), (None, None, None, None, None), (3, 0, 7, "", False)])
        raw.insert_rows(c, "t", cols, [])
        self.assertEqual(c.execute("SELECT * FROM t ORDER BY a NULLS LAST").fetchall(),
                         [(1, 2**63, -1, "x y", True), (3, 0, 7, "", False), (None, None, None, None, None)])
        c.close()


class RawTables(Base):
    def test_every_layout_fits_its_table(self):
        """A row built from a record of each (type, version) has only columns of its raw table, and
        the generated DDL has exactly the generated column list."""
        con = duckdb.connect()
        RAW.create(con)
        for (t, v), lay in R.gen.RECORDS.items():
            var = {vn: (facts() if vn in dict(lay.parts) else b"x") for vn, _ in lay.var}
            extra = {"kind": 1} if lay.name in ("PROC", "SNAP_DONE") else {}
            if lay.name == "OPEN":
                extra["fflags"] = FF.FF_OBJ_NEW
            if lay.name == "BACKING":
                extra["fflags"] = FF.FF_OBJ_NEW | FF.FF_USER_OBJ_NEW
            if lay.name == "OPEN_VERDICT":
                extra["verdict"] = -13
            r = R.decode(memoryview(rec(lay.name, var=var, version=v, **extra)), 0, 0, 0)
            cols = [c for c, _ in R.gen.SQL_COLUMNS[lay.name]]
            self.assertLessEqual(set(RAW.row(r)), set(cols), (lay.name, v))
            ddl = [x[0] for x in con.execute(f"DESCRIBE raw_{lay.name.lower()}").fetchall()]
            self.assertEqual(ddl, cols, lay.name)
        con.close()

    def test_rows_values_and_nulls(self):
        c = self.graph(bulk=[opn(T0 + 5, A, 7, 8, b"/etc/passwd", facts(ino=42, dev=DEV, gen=9, mode=REG, fs_magic=EXT4)),
                             opn(T0 + 6, A, 9, 8, b"/etc/passwd"),
                             SC.net(T0 + 7, A, "CONNECT", 2 ** 63 + 5, "10.0.0.0:1", "10.0.0.9:80")])
        self.assertEqual(self.q(c, "SELECT fid, facts_ino, facts_fs_magic, path, tgid, start_ns, ts_ns, ring, seq "
                                   "FROM raw_open ORDER BY seq"),
                         [(7, 42, EXT4, b"/etc/passwd", 700, T0 + 10, T0 + 5, 1, 0),
                          (9, None, None, b"/etc/passwd", 700, T0 + 10, T0 + 6, 1, 1)])
        # u64 above 2^63 and a char[16] with trailing NULs survive
        self.assertEqual(self.q(c, "SELECT sock_cookie, octet_length(laddr), laddr[1:4] FROM raw_net"),
                         [(2 ** 63 + 5, 16, b"\x0a\x00\x00\x00")])
        self.assertEqual(self.res.raw_rows["OPEN"], 2)
        self.assertEqual(self.q(c, "SELECT value FROM run_meta WHERE key = 'run.id'"), [("g1",)])

    def test_a_record_that_fails_its_check_is_listed_not_loaded(self):
        bad = bytearray(opn(T0 + 5, A, 7, 8, b"/x"))
        bad[6] = 0x80                                    # an unknown header flag
        c = self.graph(bulk=[bytes(bad), opn(T0 + 6, A, 9, 8, b"/y")])
        self.assertEqual(self.q(c, "SELECT ring, seq, why FROM record_error"), [(1, 0, "unknown flag bits")])
        self.assertEqual(self.q(c, "SELECT fid FROM raw_open"), [(9,)])
        self.assertEqual(self.res.raw_rows["record_error"], 1)

    def test_a_row_with_an_unknown_column_is_refused(self):
        con = duckdb.connect()
        RAW.create(con)
        ld = RAW.Loader(con)
        ld.buf["CLOSE"].append({"ring": 1, "seq": 0, "nonsense": 1})
        with self.assertRaisesRegex(KeyError, "CLOSE: no raw column for"):
            ld.flush("CLOSE")
        con.close()

    def test_flushes_in_chunks(self):
        old, RAW.FLUSH_ROWS = RAW.FLUSH_ROWS, 2
        try:
            c = self.graph(bulk=[close(T0 + i, A, 100 + i, 5) for i in range(5)])
        finally:
            RAW.FLUSH_ROWS = old
        self.assertEqual(self.q(c, "SELECT count(*), count(DISTINCT fid) FROM raw_close"), [(5, 5)])


class FileNodes(Base):
    def test_trusted_filesystem_joins_by_tuple(self):
        """ext4: one file evicted from the inode cache and read back has two object ids and is one
        node (ADR-0015 rule 3); a reused inode number with another generation is another node."""
        f = dict(ino=42, dev=DEV, mode=REG, fs_magic=EXT4)
        c = self.graph(bulk=[opn(T0 + 1, A, 1, 10, b"/a", facts(gen=9, **f)), opn(T0 + 2, A, 2, 11, b"/a", facts(gen=9, **f)),
                             opn(T0 + 3, A, 3, 12, b"/b", facts(gen=77, **f))])
        n1, n2, n3 = (self.node_of_fid(c, i) for i in (1, 2, 3))
        self.assertEqual(n1, n2)
        self.assertEqual(n1[1], "tuple")
        self.assertNotEqual(n1[0], n3[0])
        self.assertEqual(self.q(c, "SELECT key, n_objs, path, path_from, kind FROM file ORDER BY node_id"),
                         [(f"t:{DEV}:0:42:9", 2, "/a", "kernel", "file"), (f"t:{DEV}:0:42:77", 1, "/b", "kernel", "file")])

    def test_untrusted_filesystem_never_merges(self):
        """Two pipes with one inode number (pipefs: generation 0, a wrapping counter) are two nodes."""
        f = facts(ino=5, dev=13, mode=FIFO, fs_magic=PIPEFS)
        c = self.graph(daemon=[fd(T0 + 1, A, 1, 10, 0, f, b"pipe:[5]"), fd(T0 + 2, A, 2, 11, 1, f, b"pipe:[5]")])
        n1, n2 = self.node_of_fid(c, 1), self.node_of_fid(c, 2)
        self.assertNotEqual(n1[0], n2[0])
        self.assertEqual((n1[1], n2[1]), ("obj", "obj"))
        self.assertEqual(self.q(c, "SELECT kind FROM file"), [("pipe",), ("pipe",)])

    def test_one_pipe_two_ends_is_one_node(self):
        f = facts(ino=5, dev=13, mode=FIFO, fs_magic=PIPEFS)
        c = self.graph(daemon=[fd(T0 + 1, A, 1, 10, 0, f), fd(T0 + 2, B2, 2, 10, 1, f)])
        self.assertEqual(self.node_of_fid(c, 1), self.node_of_fid(c, 2))

    def test_anonymous_inode_node_is_the_open_file(self):
        """ADR-0027's confirmation: one object id and two fids are two nodes; one fid in two
        processes is one node."""
        f = facts(ino=1, dev=14, mode=0o600, fs_magic=ANON)
        c = self.graph(daemon=[fd(T0 + 1, A, 1, 10, 3, f, b"anon_inode:[eventfd]"),
                               fd(T0 + 2, A, 2, 10, 4, f, b"anon_inode:[eventfd]"),
                               fd(T0 + 3, B2, 2, 10, 4, f, b"anon_inode:[eventfd]")])
        self.assertEqual(self.q(c, "SELECT fid, rule, file_key FROM openfile ORDER BY fid"),
                         [(1, "fid", "f:1"), (2, "fid", "f:2")])
        self.assertEqual(self.q(c, "SELECT count(*) FROM file"), [(2,)])
        held = self.q(c, "SELECT p.tgid, e.fid FROM edge e JOIN proc p ON p.node_id = e.dst WHERE op = 'HELD' ORDER BY 1, 2")
        self.assertEqual(held, [(700, 1), (700, 2), (710, 2)])
        self.assertEqual(len(set(self.q(c, "SELECT src FROM edge WHERE fid = 2"))), 1)

    def test_btrfs_by_subvolume_or_per_lifetime(self):
        f = dict(ino=300, dev=40, gen=7, mode=REG, fs_magic=BTRFS)
        c = self.graph(bulk=[opn(T0 + 1, A, 1, 10, b"/s1/f", facts(subvol=256, **f)),
                             opn(T0 + 2, A, 2, 11, b"/s2/f", facts(subvol=257, **f)),
                             opn(T0 + 3, A, 3, 12, b"/s1/f", facts(subvol=256, **f)),
                             opn(T0 + 4, A, 4, 13, b"/u", facts(oflags=1, **f)),
                             opn(T0 + 5, A, 5, 14, b"/u", facts(oflags=1, **f))])
        n = [self.node_of_fid(c, i) for i in (1, 2, 3, 4, 5)]
        self.assertEqual(n[0], n[2])                       # one subvolume: the tuple
        self.assertNotEqual(n[0][0], n[1][0])              # two subvolumes share (dev, ino): two nodes
        self.assertEqual((n[3][1], n[4][1]), ("obj", "obj"))   # SUBVOL_UNKNOWN: a node per lifetime
        self.assertNotEqual(n[3][0], n[4][0])

    def test_facts_from_any_record_and_missing_facts_counted(self):
        """The facts may come with an earlier record of another type; an object whose facts the run
        does not hold gets a node per object id, and is counted."""
        f = facts(ino=42, dev=DEV, gen=9, mode=REG, fs_magic=EXT4, seen=2)
        c = self.graph(bulk=[opn(T0 + 5, A, 2, 10, b"/a"), opn(T0 + 6, A, 3, 99, b"/lost")],
                       daemon=[fd(T0 + 1, A, 1, 10, 3, f, b"/a")])
        self.assertEqual(self.node_of_fid(c, 1), self.node_of_fid(c, 2))
        self.assertEqual(self.node_of_fid(c, 3)[1], "obj-no-facts")
        self.assertEqual(self.res.counts["file_rule_obj-no-facts"], 1)
        self.assertEqual(self.res.counts["file_rule_tuple"], 1)

    def test_falsifier_counts(self):
        """Repeated facts that disagree, and one fid with two objects, are counted (they must not happen)."""
        c = self.graph(bulk=[opn(T0 + 1, A, 1, 10, b"/a", facts(ino=1, dev=DEV, gen=1, mode=REG, fs_magic=EXT4)),
                             opn(T0 + 2, A, 2, 10, b"/a", facts(ino=2, dev=DEV, gen=1, mode=REG, fs_magic=EXT4)),
                             close(T0 + 3, A, 1, 11)])
        self.assertEqual((self.res.counts["obj_facts_conflict"], self.res.counts["fid_two_objs"]), (1, 1))
        self.assertEqual(self.q(c, "SELECT ino FROM obj_facts"), [(1,)])     # the first facts stand
        run_of(self.d / "ok", bulk=[opn(T0 + 1, A, 1, 10, b"/a", facts(ino=1, dev=DEV, gen=1, mode=REG, fs_magic=EXT4)),
                                    opn(T0 + 2, A, 2, 10, b"/a", facts(ino=1, dev=DEV, gen=1, mode=REG, fs_magic=EXT4,
                                                                         nlink=3))])
        r = B.build(self.d / "ok", self.d / "ok.duckdb")
        self.assertEqual((r.counts["obj_facts_conflict"], r.counts["fid_two_objs"]), (0, 0))   # nlink may change

    def test_backing_joins_overlay_and_real_file(self):
        real = facts(ino=77, dev=DEV, gen=3, mode=REG, fs_magic=EXT4)
        ovl = facts(ino=900, dev=50, mode=REG, fs_magic=OVL)
        c = self.graph(bulk=[opn(T0 + 1, A, 1, 20, b"/merged/f", ovl),
                             rec("BACKING", var={"facts": real, "user_facts": b""}, **hdr(T0 + 2, A), fid=2, obj=21,
                                 user_obj=20, fflags=FF.FF_OBJ_NEW, f_mode=1 << 24)])
        self.assertEqual(self.q(c, "SELECT real_node, user_node FROM file_backing"),
                         [(self.node_of_fid(c, 2)[0], self.node_of_fid(c, 1)[0])])
        self.assertEqual(self.q(c, "SELECT how FROM openfile WHERE fid = 2"), [("backing",)])
        self.assertEqual(self.q(c, "SELECT count(*) FROM edge WHERE fid = 2"), [(0,)])   # a relation, not a flow

    def test_overlay_object_known_only_from_backing(self):
        real = facts(ino=77, dev=DEV, gen=3, mode=REG, fs_magic=EXT4)
        ovl = facts(ino=900, dev=50, mode=REG, fs_magic=OVL)
        c = self.graph(bulk=[rec("BACKING", var={"facts": real, "user_facts": ovl}, **hdr(T0 + 2, A), fid=2, obj=21,
                                 user_obj=20, fflags=FF.FF_OBJ_NEW | FF.FF_USER_OBJ_NEW, f_mode=1 << 24)])
        self.assertEqual(self.q(c, "SELECT f.key FROM file_backing b JOIN file f ON f.node_id = b.user_node"), [("o:20",)])


class OpenEdges(Base):
    F = dict(dev=DEV, gen=9, mode=REG, fs_magic=EXT4)

    def test_open_edge_direction_access_and_openfile(self):
        c = self.graph(bulk=[opn(T0 + 1, A, 1, 10, b"/r", facts(ino=1, **self.F), mode=1),
                             opn(T0 + 2, A, 2, 11, b"/w", facts(ino=2, **self.F), mode=2),
                             opn(T0 + 3, B2, 3, 12, b"/rw", facts(ino=3, **self.F), mode=3 | (1 << 5)),
                             close(T0 + 9, B2, 3, 12)])
        e = self.q(c, "SELECT f.path, p.tgid, e.access, e.ok, e.fid, e.ts_ns FROM edge e JOIN file f ON f.node_id = e.src "
                      "JOIN proc p ON p.node_id = e.dst WHERE e.op = 'OPEN' ORDER BY e.edge_id")
        self.assertEqual(e, [("/r", 700, "r", True, 1, T0 + 1), ("/w", 700, "w", True, 2, T0 + 2),
                             ("/rw", 710, "rw", True, 3, T0 + 3)])
        self.assertEqual(self.q(c, "SELECT fid, how, opener_tgid, closed_ns, path FROM openfile ORDER BY fid"),
                         [(1, "open", 700, None, "/r"), (2, "open", 700, None, "/w"), (3, "open", 710, T0 + 9, "/rw")])
        # a process only an OPEN names is a node, as a counted placeholder
        self.assertEqual(self.res.tree_counts["placeholder"], 2)
        self.assertEqual(self.q(c, "SELECT origin FROM proc WHERE tgid = 700"), [("no spine record in the run",)])

    def test_denied_and_failed_opens_are_edges_that_did_not_happen(self):
        c = self.graph(bulk=[
            opn(T0 + 1, A, 1, 10, b"/denied", facts(ino=1, **self.F)),
            rec("OPEN_VERDICT", **hdr(T0 + 2, A), fid=1, verdict=-13),
            opn(T0 + 3, A, 2, 11, b"", facts(ino=2, **self.F), fflags=FF.FF_PATH_MISSING, verdict=-1),
            opn(T0 + 4, A, 3, 12, b"/fifo", facts(ino=3, **self.F)), close(T0 + 5, A, 3, 12, FF.FF_NEVER_OPENED),
            opn(T0 + 6, A, 4, 13, b"", facts(ino=4, **self.F), fflags=FF.FF_PATH_MISSING),
            opn(T0 + 7, A, 5, 14, b"/fine", facts(ino=5, **self.F))])
        self.assertEqual(self.q(c, "SELECT fid, ok, ret FROM edge WHERE op = 'OPEN' ORDER BY fid"),
                         [(1, False, -13), (2, False, -1), (3, False, 0), (4, True, 0), (5, True, 0)])
        cn = self.res.counts
        self.assertEqual((cn["open_denied"], cn["open_never_opened"], cn["open_no_path"]), (2, 1, 2))
        self.assertEqual((cn["edge_OPEN"], cn["edge_OPEN_failed"]), (2, 3))

    def test_a_close_without_an_object_id_is_a_node_of_its_own(self):
        """CLOSE obj 0 (no program of the open computed the object, E-0190): never an object id, so
        two such fids are two nodes, and an OPEN's object with a later CLOSE obj 0 is no conflict."""
        F = dict(dev=DEV, gen=9, mode=REG, fs_magic=EXT4)
        c = self.graph(bulk=[close(T0 + 1, A, 1, 0), close(T0 + 2, A, 2, 0),
                             opn(T0 + 3, A, 3, 10, b"/a", facts(ino=1, **F)), close(T0 + 4, A, 3, 0)])
        self.assertEqual(self.q(c, "SELECT fid, rule, file_key FROM openfile ORDER BY fid"),
                         [(1, "obj-unknown", "u:1"), (2, "obj-unknown", "u:2"), (3, "tuple", f"t:{DEV}:0:1:9")])
        self.assertEqual(self.res.counts["fid_two_objs"], 0)
        self.assertEqual(self.res.counts["file_rule_obj-unknown"], 2)

    def test_close_only_fid_is_counted_and_has_no_edge(self):
        c = self.graph(bulk=[close(T0 + 5, A, 9, 10)])
        self.assertEqual(self.q(c, "SELECT how, rule FROM openfile"), [("close-only", "obj-no-facts")])
        self.assertEqual(self.res.counts["openfile_close-only"], 1)
        self.assertEqual(self.q(c, "SELECT count(*) FROM edge"), [(0,)])

    def test_held_is_the_first_sighting_and_an_open_wins_over_a_later_snapshot_row(self):
        f = facts(ino=1, seen=2, **self.F)
        c = self.graph(bulk=[opn(T0 + 1, A, 1, 10, b"/a", facts(ino=1, **self.F))],
                       daemon=[fd(T0 + 5, A, 1, 10, 3, f, b"/a"), fd(T0 + 8, A, 1, 10, 3, f, b"/a")])
        self.assertEqual(self.q(c, "SELECT how, opener_tgid, first_ns FROM openfile"), [("open", 700, T0 + 1)])
        self.assertEqual(self.q(c, "SELECT op, ts_ns FROM edge ORDER BY edge_id"), [("OPEN", T0 + 1), ("HELD", T0 + 5)])


class ExecEdges(Base):
    def exe(self, t, p, path, **kw):
        return rec("EXEC", var={"filename": path, "argv": path + b"\0"}, **hdr(t, p), old_tid=p[0], **kw)

    def test_exec_joins_the_file_its_open_named(self):
        """Trusted filesystem: the exec's own (dev, ino, gen) is the tuple, with or without an OPEN.
        Elsewhere: the object capture saw with those numbers most recently before the exec; else a
        node of its own, counted."""
        ovl = dict(ino=900, dev=50, mode=0o100755, fs_magic=OVL)
        c = self.graph(
            spine=[self.exe(T0 + 10, A, b"a", exe_ino=42, exe_dev=DEV, exe_gen=9, exe_fs_magic=EXT4),
                   self.exe(T0 + 20, A, b"./b", exe_ino=43, exe_dev=DEV, exe_gen=1, exe_fs_magic=EXT4),
                   self.exe(T0 + 30, B2, b"/merged/c", exe_ino=900, exe_dev=50, exe_fs_magic=OVL),
                   self.exe(T0 + 40, B2, b"/merged/d", exe_ino=901, exe_dev=50, exe_fs_magic=OVL)],
            bulk=[opn(T0 + 9, A, 1, 10, b"/usr/bin/a", facts(ino=42, dev=DEV, gen=9, mode=0o100755, fs_magic=EXT4)),
                  opn(T0 + 25, B2, 2, 20, b"/merged/c", facts(**ovl)),
                  opn(T0 + 28, B2, 3, 21, b"/merged/c", facts(**ovl)),      # evicted, read back: the later object
                  opn(T0 + 29, B2, 5, 23, b"/other/c", facts(**{**ovl, "dev": 51})),   # the numbers on another device
                  opn(T0 + 35, B2, 4, 22, b"/merged/c", facts(**ovl))])     # after the exec: not it
        e = self.q(c, "SELECT f.key, f.path, f.path_from, p.tgid FROM edge e JOIN file f ON f.node_id = e.src "
                      "JOIN proc p ON p.node_id = e.dst WHERE e.op = 'EXECUTE' ORDER BY e.ts_ns")
        self.assertEqual(e, [(f"t:{DEV}:0:42:9", "/usr/bin/a", "kernel", 700), (f"t:{DEV}:0:43:1", "./b", "exec-argument", 700),
                             ("o:21", "/merged/c", "kernel", 710), ("x:50:901:0", "/merged/d", "exec-argument", 710)])
        self.assertEqual(self.node_of_fid(c, 1)[0], self.q(c, "SELECT src FROM edge WHERE op = 'EXECUTE' ORDER BY ts_ns")[0][0])
        cn = self.res.counts
        self.assertEqual((cn["exec_file_tuple"], cn["exec_file_object-match"], cn["exec_file_unjoined"]), (2, 1, 1))
        self.assertEqual(cn["file_rule_exec-unjoined"], 1)

    def test_scenario_processes_edges_and_sockets(self):
        SC.build(self.d / "run", snap=True)
        self.res = B.build(self.d / "run", self.d / "g.duckdb")
        c = self.open()
        self.assertEqual(self.q(c, "SELECT p.tgid, pp.tgid, p.cmd, p.exit_code FROM proc p LEFT JOIN proc pp "
                                   "ON pp.node_id = p.parent_node ORDER BY p.tgid"),
                         [(1, None, "/sbin/init", None), (500, 1, "-bash", None),
                          (600, 500, "python3 -m http.server 18077", None), (610, 500, "curl http://127.0.0.1:18077/", 0),
                          (620, 500, "curl http://127.0.0.1:18077/x", 0), (630, 600, "sh -c nc 127.0.0.1 4444", 256),
                          (640, 630, "nc 127.0.0.1 4444", 256)])
        self.assertEqual(self.q(c, "SELECT origin, count(*) FROM proc GROUP BY origin ORDER BY 2"),
                         [("started before the capture (parent and program from the opening snapshot)", 2),
                          ("forked in the run", 5)])
        clone = self.q(c, "SELECT s.tgid, d.tgid FROM edge e JOIN proc s ON s.node_id = e.src JOIN proc d "
                          "ON d.node_id = e.dst WHERE op = 'CLONE' ORDER BY e.edge_id")
        self.assertEqual(clone, [(500, 600), (500, 610), (500, 620), (600, 630), (630, 640)])
        net = self.q(c, "SELECT e.op, e.ok, e.ret, coalesce(ps.tgid, pd.tgid), coalesce(sd.cookie, ss.cookie), "
                        "ps.tgid IS NOT NULL FROM edge e LEFT JOIN proc ps ON ps.node_id = e.src LEFT JOIN proc pd "
                        "ON pd.node_id = e.dst LEFT JOIN sock ss ON ss.node_id = e.src LEFT JOIN sock sd ON sd.node_id = e.dst "
                        "WHERE e.op IN ('CONNECT', 'ACCEPT', 'LISTEN', 'BIND') ORDER BY e.edge_id")
        self.assertEqual(net, [("BIND", True, 0, 600, 9001, True), ("LISTEN", True, 0, 600, 9001, True),
                               ("CONNECT", True, 0, 610, 9002, True), ("ACCEPT", True, 0, 600, 9003, False),
                               ("CONNECT", True, 0, 620, 9004, True), ("ACCEPT", True, 0, 600, 9005, False),
                               ("ACCEPT", True, 0, 600, 9006, False), ("CONNECT", False, -111, 640, 9007, True)])
        self.assertEqual(self.q(c, "SELECT s.cookie, laddr, lport, raddr, rport, listening, l.cookie FROM sock s "
                                   "LEFT JOIN (SELECT node_id, cookie FROM sock) l ON l.node_id = s.listener_node "
                                   "WHERE s.cookie IN (9001, 9003, 9007) ORDER BY 1"),
                         [(9001, "127.0.0.1", 18077, "0.0.0.0", 0, True, None),
                          (9003, "127.0.0.1", 18077, "127.0.0.1", 41000, False, 9001),
                          (9007, "127.0.0.1", 0, "127.0.0.1", 4444, False, None)])
        # exact ISN joins only: the two local clients; the remote client's accept is counted
        self.assertEqual(self.q(c, "SELECT a.cookie, b.cookie FROM sock_pair p JOIN sock a ON a.node_id = p.client_node "
                                   "JOIN sock b ON b.node_id = p.server_node ORDER BY 1"), [(9002, 9003), (9004, 9005)])
        self.assertEqual(self.res.counts["accept_not_paired"], 1)
        self.assertEqual(self.res.counts["edge_without_node"], 0)
        ids = self.q(c, "SELECT node_id, kind FROM node ORDER BY node_id")
        self.assertEqual([i for i, _ in ids], list(range(1, len(ids) + 1)))
        self.assertEqual([k for _, k in ids], ["proc"] * 7 + ["file"] * 5 + ["sock"] * 7)

    def test_a_thread_is_not_a_clone_edge_and_a_socket_shows_its_connection(self):
        c = self.graph(spine=[SC.fork(T0 + 1, A, B2), SC.fork(T0 + 2, A, (A[0], A[1]), kind=2)],
                       bulk=[SC.net(T0 + 3, A, "BIND", 1, "0.0.0.0:5000"),
                             SC.net(T0 + 4, A, "CONNECT", 1, "10.0.0.1:5000", "10.0.0.2:80")],
                       daemon=[fd(T0 + 5, A, 7, 10, 0, facts(ino=1, dev=DEV, gen=1, mode=REG, fs_magic=EXT4, seen=2))])
        self.assertEqual(self.q(c, "SELECT s.tgid, d.tgid FROM edge e JOIN proc s ON s.node_id = e.src JOIN proc d "
                                   "ON d.node_id = e.dst WHERE op = 'CLONE'"), [(700, 710)])
        self.assertEqual(self.q(c, "SELECT laddr, lport, raddr, rport FROM sock"), [("10.0.0.1", 5000, "10.0.0.2", 80)])
        self.assertEqual(self.res.counts["open_no_path"], 0)      # a snapshot row without a path is not an open

    def test_a_pair_needs_the_isn_and_mirrored_endpoints(self):
        n = SC.net
        c = self.graph(bulk=[
            n(T0 + 1, A, "CONNECT", 1, "127.0.0.1:5000", "127.0.0.1:80", isn=7),
            n(T0 + 2, B2, "ACCEPT", 2, "127.0.0.1:80", "127.0.0.1:5000", isn=8),      # another ISN
            n(T0 + 3, A, "CONNECT", 3, "127.0.0.1:5001", "127.0.0.1:80", isn=9),
            n(T0 + 4, B2, "ACCEPT", 4, "127.0.0.1:80", "127.0.0.1:5999", isn=9),      # the ISN, another endpoint
            n(T0 + 5, A, "CONNECT", 5, "127.0.0.1:5002", "127.0.0.1:80"),
            n(T0 + 6, B2, "ACCEPT", 6, "127.0.0.1:80", "127.0.0.1:5002"),             # no ISN: not written
            n(T0 + 7, A, "CONNECT", 7, "127.0.0.1:5003", "127.0.0.1:80", isn=11, ret=-115),
            n(T0 + 8, B2, "ACCEPT", 8, "127.0.0.1:80", "127.0.0.1:5003", isn=11)])
        self.assertEqual(self.q(c, "SELECT a.cookie, b.cookie FROM sock_pair p JOIN sock a ON a.node_id = p.client_node "
                                   "JOIN sock b ON b.node_id = p.server_node"), [(7, 8)])
        self.assertEqual(self.res.counts["accept_not_paired"], 3)


class Images(Base):
    """ADR-0031: a process's programs over time, each edge's program at its time, and names from the
    leader only."""
    C, D, E = (720, T0 + 30), (725, T0 + 35), (730, T0 + 60)

    def exe(self, t, p, path):
        return rec("EXEC", var={"filename": path, "argv": path + b"\0x\0"}, **hdr(t, p), old_tid=p[0],
                   exe_ino=40 + t % 7, exe_dev=DEV, exe_gen=1, exe_fs_magic=EXT4)

    def ren(self, t, p, tid, new):
        return rec("RENAME", h_ts_ns=t, h_tgid=p[0], h_tid=tid, h_start_ns=p[1], old_comm=b"x", new_comm=new)

    def run_story(self):
        f = facts(ino=5, dev=DEV, gen=1, mode=REG, fs_magic=EXT4)
        return self.graph(
            spine=[self.exe(T0 + 20, A, b"/bin/a"), self.ren(T0 + 20, A, A[0], b"a"),
                   SC.fork(T0 + 30, A, self.C), SC.fork(T0 + 35, self.C, self.D),
                   self.exe(T0 + 40, self.C, b"/bin/c"), self.ren(T0 + 40, self.C, self.C[0], b"c"),
                   self.ren(T0 + 50, A, A[0] + 1, b"worker"),
                   self.exe(T0 + 60, A, b"/bin/a2"), SC.fork(T0 + 60, A, self.E)],
            bulk=[opn(T0 + 15, A, 1, 10, b"/f", f),          # before A's first exec, A not in a snapshot
                  opn(T0 + 25, A, 2, 10, b"/f"),             # A runs /bin/a
                  opn(T0 + 35, self.C, 3, 10, b"/f"),        # C before its exec: its parent's program
                  opn(T0 + 36, self.D, 5, 10, b"/f"),        # D, forked by C before C's exec: A's program
                  opn(T0 + 37, B2, 6, 10, b"/f"),            # a process with no program in the run
                  opn(T0 + 45, self.C, 4, 10, b"/f"),        # C runs /bin/c
                  SC.net(T0 + 46, self.C, "CONNECT", 1, "10.0.0.1:5000", "10.0.0.2:80"),
                  opn(T0 + 65, A, 7, 10, b"/f")])            # A runs /bin/a2

    def test_each_edge_names_the_program_running_at_its_time(self):
        c = self.run_story()
        rows = self.q(c, "SELECT e.fid, i.seen_in, i.filename, i.cmd FROM edge e JOIN proc p ON p.node_id = e.dst "
                         "LEFT JOIN proc_image i ON i.node_id = e.dst AND i.image_no = e.dst_image "
                         "WHERE e.op = 'OPEN' ORDER BY e.ts_ns")
        self.assertEqual(rows, [(1, None, None, None), (2, "exec", "/bin/a", "/bin/a x"),
                                (3, "fork", "/bin/a", "/bin/a x"), (5, "fork", "/bin/a", "/bin/a x"),
                                (6, None, None, None), (4, "exec", "/bin/c", "/bin/c x"),
                                (7, "exec", "/bin/a2", "/bin/a2 x")])
        self.assertEqual(self.q(c, "SELECT p.tgid, i.image_no, i.valid_from - ?, i.seen_in, i.filename FROM proc_image i "
                                   "JOIN proc p USING (node_id) ORDER BY p.tgid, i.image_no", T0),
                         [(700, 0, 20, "exec", "/bin/a"), (700, 1, 60, "exec", "/bin/a2"),
                          (720, 0, 30, "fork", "/bin/a"), (720, 1, 40, "exec", "/bin/c"),
                          (725, 0, 35, "fork", "/bin/a"), (730, 0, 60, "fork", "/bin/a2")])
        # CLONE: the parent's program at the fork (an image is in effect from its own time on), the child's first
        self.assertEqual(self.q(c, "SELECT s.tgid, d.tgid, e.src_image, e.dst_image FROM edge e JOIN proc s ON s.node_id = e.src "
                                   "JOIN proc d ON d.node_id = e.dst WHERE op = 'CLONE' ORDER BY e.ts_ns"),
                         [(700, 720, 0, 0), (720, 725, 0, 0), (700, 730, 1, 0)])
        self.assertEqual(self.q(c, "SELECT src_image, dst_image FROM edge WHERE op = 'CONNECT'"), [(1, None)])
        # an exec image names the file of its own EXECUTE edge
        self.assertEqual(self.q(c, "SELECT count(DISTINCT i.exe_node) FROM proc_image i JOIN edge e ON e.op = 'EXECUTE' "
                                   "AND e.dst = i.node_id AND e.ts_ns = i.ts_ns AND e.src = i.exe_node "
                                   "AND e.dst_image = i.image_no WHERE i.seen_in = 'exec'"), [(3,)])
        cn = self.res.counts
        self.assertEqual((cn["image_exec"], cn["image_fork"], cn["image_exec_without_edge"]), (3, 3, 0))
        self.assertEqual(cn["edge_proc_end_without_image"], 2)     # fid 1 (A before its exec) and fid 6 (B2)
        self.assertEqual((self.res.tree_counts["image_none"], self.res.tree_counts["image_fork"]), (1, 3))
        # the last image is still proc.cmd
        self.assertEqual(self.q(c, "SELECT tgid, cmd FROM proc WHERE tgid IN (700, 720) ORDER BY tgid"),
                         [(700, "/bin/a2 x"), (720, "/bin/c x")])

    def test_a_child_forked_before_the_opening_snapshot_ran_has_the_snapshot_program(self):
        k = (800, T0 + 50)
        c = self.graph(spine=[SC.fork(T0 + 50, SC.BASH, k)], bulk=[opn(T0 + 60, k, 1, 10, b"/f")],
                       daemon=SC.snapshot(T0 + 100, 0, 1, SC.OPENING))
        self.assertEqual(self.q(c, "SELECT i.seen_in, i.filename FROM edge e JOIN proc_image i ON i.node_id = e.dst "
                                   "AND i.image_no = e.dst_image WHERE e.op = 'OPEN'"), [("fork", "/usr/bin/bash")])

    def test_a_threads_rename_names_the_thread_not_the_process(self):
        c = self.run_story()
        self.assertEqual(self.q(c, "SELECT tgid, comm FROM proc WHERE tgid IN (700, 720) ORDER BY tgid"), [(700, "a"), (720, "c")])
        self.assertEqual(self.q(c, "SELECT p.tgid, t.tid, t.new_comm, t.ts_ns - ? FROM thread_name t JOIN proc p USING (node_id)",
                                T0), [(700, 701, "worker", 50)])
        self.assertEqual(self.res.counts["thread_rename"], 1)
        self.assertEqual((self.res.tree_counts["rename"], self.res.tree_counts["rename_thread"]), (2, 1))

    def test_an_exec_image_without_its_edge_makes_the_run_invalid(self):
        from unittest import mock
        fake = B.Result({"record_error": 0}, {"image_exec_without_edge": 1}, {}, [])
        err = io.StringIO()
        with mock.patch.object(B, "build", return_value=fake), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(err):
            self.assertEqual(CLI.main([str(self.d / "run"), str(self.d / "g.duckdb")]), 1)
        self.assertIn("image_exec_without_edge must be 0", err.getvalue())

    def test_a_snapshot_program_holds_from_the_process_start(self):
        SC.build(self.d / "run", snap=True)
        self.res = B.build(self.d / "run", self.d / "g.duckdb")
        c = self.open()
        self.assertEqual(self.q(c, "SELECT i.image_no, i.valid_from, i.seen_in, i.filename FROM proc_image i "
                                   "JOIN proc p USING (node_id) WHERE p.tgid = 500"), [(0, SC.BASH[1], "snapshot", "/usr/bin/bash")])
        # bash's forks are made by bash's program; each child starts with it, then runs its own
        self.assertEqual(self.q(c, "SELECT DISTINCT si.filename FROM edge e JOIN proc_image si ON si.node_id = e.src "
                                   "AND si.image_no = e.src_image WHERE e.op = 'CLONE' AND e.src = "
                                   "(SELECT node_id FROM proc WHERE tgid = 500)"), [("/usr/bin/bash",)])
        self.assertEqual(self.q(c, "SELECT i.seen_in, i.cmd FROM proc_image i JOIN proc p USING (node_id) "
                                   "WHERE p.tgid = 600 ORDER BY i.image_no"),
                         [("fork", "-bash"), ("exec", "python3 -m http.server 18077")])


class BuildFile(Base):
    def test_refuses_to_overwrite_and_leaves_nothing_half_built(self):
        SC.build(self.d / "run")
        B.build(self.d / "run", self.d / "g.duckdb")
        with self.assertRaises(FileExistsError):
            B.build(self.d / "run", self.d / "g.duckdb")
        old, B.SQL = B.SQL, self.d / "broken.sql"
        B.SQL.write_text("CREATE TABLE node AS SELECT 1; SELECT * FROM no_such_table;")
        try:
            with self.assertRaises(duckdb.Error):
                B.build(self.d / "run", self.d / "h.duckdb")
        finally:
            B.SQL = old
        self.assertFalse((self.d / "h.duckdb").exists())

    def test_cli(self):
        SC.build(self.d / "run", snap=True)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self._cli()
        self.assertIn("exported: EVENT_ACCEPT 3, EVENT_CLONE 5, EVENT_CONNECT 2, EVENT_EXECUTE 5", out.getvalue())
        self.assertIn("INVALID: fid_two_objs must be 0", err.getvalue())
        self.assertIn("g.duckdb exists", err.getvalue())

    def _cli(self):
        self.assertEqual(CLI.main([str(self.d / "run"), str(self.d / "g.duckdb"), "--pidsmaker", str(self.d / "pm")]), 0)
        self.assertEqual(CLI.main([str(self.d / "run"), str(self.d / "g.duckdb")]), 2)           # exists
        (self.d / "nothing").mkdir()
        self.assertEqual(CLI.main([str(self.d / "nothing"), str(self.d / "x.duckdb")]), 2)       # not a run
        self.assertEqual(CLI.main([str(self.d / "no-such-dir"), str(self.d / "x.duckdb")]), 2)   # an OSError, one line
        self.assertFalse((self.d / "x.duckdb").exists())
        run_of(self.d / "bad", bulk=[close(T0 + 3, A, 1, 11), close(T0 + 4, A, 1, 12)])           # one fid, two objects
        self.assertEqual(CLI.main([str(self.d / "bad"), str(self.d / "bad.duckdb")]), 1)
        broken = bytearray(close(T0 + 3, A, 1, 11))
        broken[6] = 0x80                                                                          # an unknown header flag
        run_of(self.d / "err", bulk=[bytes(broken)])
        self.assertEqual(CLI.main([str(self.d / "err"), str(self.d / "err.duckdb")]), 1)

    def test_text_and_addr(self):
        self.assertEqual(B.text(b"/a\xff"), "/a\\xff")
        self.assertEqual(B.addr(b"\x0a\0\0\0" + bytes(12), 2), "10.0.0.0")
        self.assertEqual(B.addr(bytes(15) + b"\x01", 10), "::1")
        with self.assertRaises(R.RecordError):
            B.addr(bytes(16), 1)


class PidsmakerExport(Base):
    def rows(self, name):
        with open(self.d / "pm" / f"{name}.csv", newline="") as f:
            return list(csv.reader(f))

    def test_tables(self):
        SC.build(self.d / "run", snap=True)
        B.build(self.d / "run", self.d / "g.duckdb")
        m = PM.export(self.d / "g.duckdb", self.d / "pm")
        subj, files, flows, ev = (self.rows(t) for t in ("subject_node_table", "file_node_table", "netflow_node_table",
                                                         "event_table"))
        self.assertEqual((len(subj), len(files), len(flows), len(ev)), (7, 5, 7, 15))
        uuid = "b1/20261102T100000Z-scenario/p:500:100"
        h = hashlib.sha256(uuid.encode()).hexdigest()
        self.assertEqual(subj[1], [uuid, h, "/usr/bin/bash", "-bash", "2"])
        self.assertEqual(files[0][2:], ["/usr/bin/python3", "8"])
        self.assertEqual(flows[1][2:], ["127.0.0.1", "41000", "127.0.0.1", "18077", "14"])
        self.assertEqual(flows[5][2:], ["127.0.0.1", "18077", "10.0.0.7", "52000", "18"])     # local, then remote
        # the first event: bash clones the server, at the capture's wall time + 500 ns
        self.assertEqual(ev[0], [h, "2", "EVENT_CLONE", subj[2][1], "3", "20261102T100000Z-scenario:0:0:CLONE",
                                 str(SC.WALL + 500)])
        # object -> subject for EXECUTE and ACCEPT; subject -> object for CONNECT
        by_op = {}
        for r in ev:
            by_op.setdefault(r[2], []).append(r)
        self.assertEqual({k: len(v) for k, v in by_op.items()},
                         {"EVENT_CLONE": 5, "EVENT_EXECUTE": 5, "EVENT_CONNECT": 2, "EVENT_ACCEPT": 3})
        self.assertEqual(by_op["EVENT_EXECUTE"][0][:5], [files[0][1], "8", "EVENT_EXECUTE", subj[2][1], "3"])
        self.assertEqual(by_op["EVENT_CONNECT"][0][:5], [subj[3][1], "4", "EVENT_CONNECT", flows[1][1], "14"])
        self.assertEqual(by_op["EVENT_ACCEPT"][0][:5], [flows[2][1], "15", "EVENT_ACCEPT", subj[2][1], "3"])
        self.assertEqual(len({r[5] for r in ev}), len(ev))                     # event ids are unique
        self.assertEqual(m["events_exported"], {"EVENT_CLONE": 5, "EVENT_EXECUTE": 5, "EVENT_CONNECT": 2, "EVENT_ACCEPT": 3})
        self.assertEqual(m["edges_not_exported"]["CONNECT (not allowed by the kernel)"], 1)
        self.assertEqual(m["wall_ns"], {"first": SC.WALL + 500, "last": SC.WALL + 4 * S + 20})
        self.assertEqual(json.loads((self.d / "pm" / "manifest.json").read_text()), m)
        load = (self.d / "pm" / "load.sql").read_text()
        self.assertIn("\\copy event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, "
                      "timestamp_rec) FROM 'event_table.csv'", load)
        with self.assertRaises(FileExistsError):
            PM.export(self.d / "g.duckdb", self.d / "pm")

    def test_opens_are_events_only_when_they_happened_and_never_reads_or_writes(self):
        F = dict(dev=DEV, gen=9, mode=REG, fs_magic=EXT4)
        self.graph(bulk=[opn(T0 + 1, A, 1, 10, b"/w", facts(ino=1, **F), mode=2),
                         opn(T0 + 2, A, 2, 11, b"/denied", facts(ino=2, **F)),
                         rec("OPEN_VERDICT", **hdr(T0 + 3, A), fid=2, verdict=-13),
                         opn(T0 - 5, A, 3, 12, b"/early", facts(ino=3, **F)),
                         SC.net(T0 + 5, A, "BIND", 1, "0.0.0.0:80", ret=-98),
                         SC.net(T0 + 6, A, "CONNECT", 2, "0.0.0.0:0", "10.0.0.1:80", ret=-111)],
                   daemon=[fd(T0 + 4, A, 1, 10, 3, facts(ino=1, seen=2, **F), b"/w")])
        m = PM.export(self.d / "g.duckdb", self.d / "pm")
        ev = self.rows("event_table")
        # the open stamped 5 ns before the first clock anchor is exported, timed by that anchor
        self.assertEqual([(r[2], r[6]) for r in ev], [("EVENT_OPEN", str(SC.WALL - 5)), ("EVENT_OPEN", str(SC.WALL + 1))])
        self.assertEqual(m["events_timed_by_the_first_anchor"], 1)
        self.assertEqual(m["wall_ns"], {"first": SC.WALL - 5, "last": SC.WALL + 1})
        self.assertEqual(ev[1][1], self.rows("file_node_table")[1][3])          # file -> process
        self.assertEqual(m["events_exported"], {"EVENT_OPEN": 2})
        self.assertEqual(m["edges_not_exported"], {
            "BIND (not allowed by the kernel)": 1, "CONNECT (not allowed by the kernel)": 1,
            "OPEN (not allowed by the kernel)": 1,
            "HELD (a descriptor already open at a snapshot: a state, not an event)": 1})
        self.assertEqual(self.rows("subject_node_table")[0][2:4], ["null", "null"])

    def test_wall_time_follows_the_nearest_earlier_anchor(self):
        """The wall clock was stepped by 7 us between two anchors: an event after the second uses it."""
        F = dict(dev=DEV, gen=9, mode=REG, fs_magic=EXT4)
        self.graph(bulk=[opn(T0 + 50, A, 1, 10, b"/a", facts(ino=1, **F)), opn(T0 + 150, A, 2, 11, b"/b", facts(ino=2, **F))],
                   daemon=[rec("CLOCK_SYNC", h_ts_ns=T0 + 100, boottime_ns=T0 + 100, monotonic_ns=T0 + 100,
                               realtime_ns=SC.WALL + 100 + 7000)])
        m = PM.export(self.d / "g.duckdb", self.d / "pm")
        self.assertEqual([r[6] for r in self.rows("event_table")], [str(SC.WALL + 50), str(SC.WALL + 150 + 7000)])
        self.assertEqual(m["events_timed_by_the_first_anchor"], 0)

    def test_an_operation_with_no_rule_is_refused(self):
        self.graph(bulk=[SC.net(T0 + 1, A, "CONNECT", 1, "127.0.0.1:1", "127.0.0.1:2")])
        for c in self.cons:
            c.close()
        self.cons = []
        c = duckdb.connect(str(self.d / "g.duckdb"))
        c.execute("UPDATE edge SET op = 'TELEPORT'")
        c.close()
        with self.assertRaisesRegex(ValueError, "TELEPORT"):
            PM.export(self.d / "g.duckdb", self.d / "pm")
        c = duckdb.connect(str(self.d / "g.duckdb"))
        c.execute("UPDATE edge SET op = 'CONNECT'")
        c.execute("DELETE FROM clock")                      # no anchor: no event can be written
        c.close()
        with self.assertRaisesRegex(ValueError, "books do not close"):
            PM.export(self.d / "g.duckdb", self.d / "pm2")


if __name__ == "__main__":
    unittest.main()
