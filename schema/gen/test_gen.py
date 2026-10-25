# SPDX-License-Identifier: MIT
"""Tests for the schema generator and the layout check. Run: python3 -m unittest -v schema/gen/test_gen.py"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen  # noqa: E402
import layout_check as LC  # noqa: E402

HEADER = """
[header]
fields = [
  { name = "type", c = "u16" }, { name = "version", c = "u16" }, { name = "len", c = "u16" },
  { name = "flags", c = "u16" }, { name = "ts_ns", c = "u64" }, { name = "tgid", c = "u32" },
  { name = "tid", c = "u32" }, { name = "start_ns", c = "u64" },
]
"""


def schema(body: str, header: str = HEADER) -> Path:
    d = Path(tempfile.mkdtemp())
    p = d / "records.toml"
    p.write_text(header + body)
    return p


def rec(name="A", type_=1, version=1, cls="SPINE", fields='{ name = "x", c = "u64" }', var=""):
    v = f"\nvar = [{var}]" if var else ""
    return f'\n[[record]]\nname = "{name}"\ntype = {type_}\nversion = {version}\nclass = "{cls}"\nfields = [{fields}]{v}\n'


class RealSchemaTest(unittest.TestCase):
    def setUp(self):
        self.s = gen.load()

    def test_header_is_32_bytes_and_starts_type_version_len(self):
        self.assertEqual([(f.name, f.offset) for f in self.s.header][:4],
                         [("type", 0), ("version", 2), ("len", 4), ("flags", 6)])
        self.assertEqual(self.s.header[-1].offset + self.s.header[-1].size, 32)

    def test_spine_records_present(self):
        self.assertEqual([(r.name, r.type, r.version) for r in self.s.records],
                         [("FORK", 1, 1), ("EXEC", 2, 1), ("EXIT", 3, 1), ("RENAME", 4, 1)])

    def test_exec_var_metadata_and_sizes(self):
        ex = next(r for r in self.s.records if r.name == "EXEC")
        gen_fields = [(f.name, f.offset) for f in ex.fields if f.generated]
        self.assertEqual(gen_fields, [("filename_full", 52), ("argv_full", 56), ("filename_len", 60),
                                      ("argv_len", 62)])
        self.assertEqual(ex.fixed_size, 64)
        self.assertEqual(ex.max_size, 64 + 256 + 1024)

    def test_every_fixed_part_is_a_multiple_of_8(self):
        for r in self.s.records:
            self.assertEqual(r.fixed_size % 8, 0, r.name)

    def test_lock_matches_the_committed_lock(self):
        self.assertEqual(gen.check_lock(self.s, json.loads(gen.LOCK.read_text())), [])

    def test_committed_generated_files_are_current(self):
        for name, text in gen.render(self.s).items():
            self.assertEqual((gen.OUT / name).read_text(), text, name)


class ErrorTest(unittest.TestCase):
    def err(self, path, needle):
        with self.assertRaises(gen.SchemaError) as cm:
            gen.load(path)
        self.assertIn(needle, str(cm.exception))

    def test_misaligned_field_is_an_error_not_padding(self):
        self.err(schema(rec(fields='{ name = "a", c = "u32" }, { name = "b", c = "u64" }')), "not 8-aligned")

    def test_duplicate_field(self):
        self.err(schema(rec(fields='{ name = "a", c = "u64" }, { name = "a", c = "u64" }')), "duplicate field")

    def test_unknown_type(self):
        self.err(schema(rec(fields='{ name = "a", c = "float" }')), "unknown C type")

    def test_duplicate_type_version(self):
        self.err(schema(rec() + rec()), "defined twice")

    def test_type_number_shared_by_two_names(self):
        self.err(schema(rec("A", 1) + rec("B", 1)), "exactly one record name")

    def test_same_name_two_type_numbers(self):
        self.err(schema(rec("A", 1) + rec("A", 2, 2)), "exactly one record name")

    def test_bad_class(self):
        self.err(schema(rec(cls="NOPE")), "class")

    def test_type_zero_is_invalid(self):
        self.err(schema(rec(type_=0)), "0 is invalid")

    def test_var_metadata_name_collision(self):
        self.err(schema(rec(fields='{ name = "p_len", c = "u64" }', var='{ name = "p", max = 8 }')), "collides")

    def test_header_size_enforced(self):
        self.err(schema(rec(), header='[header]\nfields = [{ name = "type", c = "u16" }]\n'), "32 bytes")

    def test_record_larger_than_u16_len(self):
        self.err(schema(rec(var='{ name = "big", max = 70000 }')), "exceeds the u16 len")

    def test_bad_var_max(self):
        self.err(schema(rec(var='{ name = "v", max = 0 }')), "bad var field")


class LockTest(unittest.TestCase):
    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = gen.main(list(args))
        return code, out.getvalue() + err.getvalue()

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.toml, self.lock, self.out = self.d / "r.toml", self.d / "lock.json", self.d / "gen"
        self.toml.write_text(HEADER + rec(fields='{ name = "x", c = "u64" }'))
        self.args = ["--schema", str(self.toml), "--lock", str(self.lock), "--out", str(self.out)]
        self.assertEqual(self.run_main(*self.args, "--update-lock")[0], 0)
        self.assertEqual(self.run_main(*self.args)[0], 0)

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_clean_check_passes(self):
        self.assertEqual(self.run_main(*self.args, "--check")[0], 0)

    def test_layout_change_without_bump_fails_check_and_update(self):
        self.toml.write_text(HEADER + rec(fields='{ name = "x", c = "u64" }, { name = "y", c = "u64" }'))
        code, msg = self.run_main(*self.args, "--check")
        self.assertEqual(code, 1)
        self.assertIn("without a version bump", msg)
        code, msg = self.run_main(*self.args, "--update-lock")
        self.assertEqual(code, 1)
        self.assertIn("refusing", msg)

    def test_new_version_needs_lock_update_then_passes(self):
        self.toml.write_text(HEADER + rec(fields='{ name = "x", c = "u64" }')
                             + rec(version=2, fields='{ name = "x", c = "u64" }, { name = "y", c = "u64" }'))
        self.run_main(*self.args)
        code, msg = self.run_main(*self.args, "--check")
        self.assertEqual(code, 1)
        self.assertIn("A/1/v2: new layout", msg)
        self.assertEqual(self.run_main(*self.args, "--update-lock")[0], 0)
        self.assertEqual(self.run_main(*self.args, "--check")[0], 0)
        self.assertEqual(sorted(json.loads(self.lock.read_text())), ["A/1/v1", "A/1/v2", "HEADER"])

    def test_stale_generated_file_fails_check(self):
        (self.out / "p15_records.h").write_text("/* edited by hand */\n")
        code, msg = self.run_main(*self.args, "--check")
        self.assertEqual(code, 1)
        self.assertIn("p15_records.h: stale", msg)

    def test_rename_of_a_field_is_a_layout_change(self):
        self.toml.write_text(HEADER + rec(fields='{ name = "z", c = "u64" }'))
        self.assertIn("without a version bump", self.run_main(*self.args, "--check")[1])


class GeneratedCodeTest(unittest.TestCase):
    def test_numpy_dtypes_match_the_generator(self):
        s = gen.load()
        mod = LC.load_generated_module(gen.OUT / "p15_records.py")
        self.assertEqual(mod.HEADER_DTYPE.itemsize, 32)
        for r in s.records:
            lay = mod.RECORDS[(r.type, r.version)]
            self.assertEqual(lay.dtype.itemsize, r.fixed_size, r.name)
            self.assertEqual(lay.max_size, r.max_size, r.name)
            self.assertEqual(mod.TYPES[r.name], r.type)
            for f in r.fields:
                self.assertEqual(lay.dtype.fields[f.name][1], f.offset, f"{r.name}.{f.name}")
                self.assertEqual(lay.dtype.fields[f.name][0].itemsize, f.size, f"{r.name}.{f.name}")

    def test_c_header_has_an_assert_per_field(self):
        s = gen.load()
        c = gen.emit_c(s)
        for r in s.records:
            for f in r.fields:
                self.assertIn(f"P15_OFFSETOF(struct {r.c_struct}, {f.name}) == {f.offset}", c)
            self.assertIn(f"sizeof(struct {r.c_struct}) == {r.fixed_size}", c)

    @unittest.skipUnless(shutil.which("gcc"), "needs gcc")
    def test_c_header_compiles_and_a_wrong_assert_fails(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "t.c"
            src.write_text('#include "p15_records.h"\nint main(void) { return 0; }\n')
            ok = subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Werror", f"-I{gen.OUT}", str(src), "-o",
                                 str(Path(d) / "t")], capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            bad = Path(d) / "p15_records.h"
            bad.write_text(gen.emit_c(gen.load()).replace("== 32, \"p15_fork_v1.child_start_ns", "== 40, \"x"))
            fail = subprocess.run(["gcc", "-std=gnu11", f"-I{d}", str(src), "-o", str(Path(d) / "t")],
                                  capture_output=True, text=True)
            self.assertNotEqual(fail.returncode, 0)


class LayoutCheckTest(unittest.TestCase):
    def fake_btf(self, s, tweak=None):
        types = []
        for name, (size, mem) in LC.from_generator(s).items():
            members = [{"name": n, "bits_offset": o * 8} for n, o in mem]
            t = {"kind": "STRUCT", "name": name, "size": size, "members": members}
            if tweak:
                tweak(t)
            types.append(t)
        return {"types": types}

    def views(self, btf):
        s = gen.load()
        return {"generator": LC.from_generator(s), "btf": LC.from_btf(btf, set(LC.from_generator(s))),
                "numpy": LC.from_numpy(LC.load_generated_module(gen.OUT / "p15_records.py"), s)}

    def test_agreement(self):
        self.assertEqual(LC.compare(self.views(self.fake_btf(gen.load()))), [])

    def test_offset_size_and_missing_struct_are_caught(self):
        s = gen.load()

        def shift(t):
            if t["name"] == "p15_exit_v1":
                t["members"][-1]["bits_offset"] += 32
                t["size"] = 48
        probs = LC.compare(self.views(self.fake_btf(s, shift)))
        self.assertTrue(any("p15_exit_v1: size" in p for p in probs))
        self.assertTrue(any("p15_exit_v1: members differ" in p for p in probs))
        btf = self.fake_btf(s)
        btf["types"] = [t for t in btf["types"] if t["name"] != "p15_fork_v1"]
        self.assertIn("p15_fork_v1: missing from btf", LC.compare(self.views(btf)))

    def test_bitfield_offsets_are_refused(self):
        with self.assertRaises(ValueError):
            LC.from_btf({"types": [{"kind": "STRUCT", "name": "p15_hdr", "size": 32,
                                    "members": [{"name": "type", "bits_offset": 3}]}]}, {"p15_hdr"})


if __name__ == "__main__":
    unittest.main()
