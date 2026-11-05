#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate every record layout from schema/records.toml (ADR-0008).

    python3 schema/gen/gen.py                 write schema/generated/*
    python3 schema/gen/gen.py --check         exit 1 if the generated files or the lock are stale
    python3 schema/gen/gen.py --update-lock   record new (type, version) layouts in schema/lock.json

Standard library only. The layout rules are in the header of records.toml; every
violation is an error with the record and field named, never a silent fix.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schema" / "records.toml"
OUT = ROOT / "schema" / "generated"
LOCK = ROOT / "schema" / "lock.json"

# C type -> (size, alignment, numpy format). char[N] is handled separately.
SCALARS = {"u8": (1, 1, "u1"), "u16": (2, 2, "<u2"), "u32": (4, 4, "<u4"), "u64": (8, 8, "<u8"),
           "i32": (4, 4, "<i4"), "i64": (8, 8, "<i8")}
C_NAMES = {"u8": "__u8", "u16": "__u16", "u32": "__u32", "u64": "__u64", "i32": "__s32", "i64": "__s64"}
HEADER_SIZE = 32
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
RECORD_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
CLASSES = {"SPINE", "FLOW", "OPEN", "CAP", "MARKER", "STATS"}
LEN_UNKNOWN = 0xFFFFFFFF
MAX_RECORD = 0xFFFF          # header.len is u16


class SchemaError(Exception):
    pass


@dataclass(frozen=True)
class Field:
    name: str
    ctype: str          # u8..i64 or char[N]
    offset: int
    size: int
    doc: str
    generated: bool = False

    @property
    def np_format(self) -> str:
        m = re.fullmatch(r"char\[(\d+)\]", self.ctype)
        return f"S{m.group(1)}" if m else SCALARS[self.ctype][2]

    def c_decl(self) -> str:
        m = re.fullmatch(r"char\[(\d+)\]", self.ctype)
        return f"char {self.name}[{m.group(1)}]" if m else f"{C_NAMES[self.ctype]} {self.name}"


@dataclass(frozen=True)
class VarField:
    name: str
    max: int
    doc: str


@dataclass
class Record:
    name: str
    type: int
    version: int
    cls: str
    doc: str
    fields: list[Field]                      # after the header, in order
    var: list[VarField] = field(default_factory=list)
    fixed_size: int = 0                      # header + fields, padded to 8

    @property
    def c_struct(self) -> str:
        return f"p15_{self.name.lower()}_v{self.version}"

    @property
    def max_size(self) -> int:
        return _pad8(self.fixed_size + sum(v.max for v in self.var))


@dataclass
class Schema:
    header: list[Field]
    header_doc: str
    flags: list[tuple[str, int, str]]
    records: list[Record]


def _pad8(n: int) -> int:
    return (n + 7) & ~7


def _size_align(ctype: str, where: str) -> tuple[int, int]:
    if ctype in SCALARS:
        return SCALARS[ctype][0], SCALARS[ctype][1]
    m = re.fullmatch(r"char\[(\d+)\]", ctype)
    if m and int(m.group(1)) > 0:
        return int(m.group(1)), 1
    raise SchemaError(f"{where}: unknown C type {ctype!r} (allowed: {', '.join(SCALARS)}, char[N])")


def _lay_out(raw: list[dict], start: int, where: str) -> tuple[list[Field], int]:
    """Place fields in order from `start`; refuse implicit padding and duplicate names."""
    out, off, seen = [], start, set()
    for f in raw:
        name, ctype = f.get("name"), f.get("c")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise SchemaError(f"{where}: bad field name {name!r}")
        if name in seen:
            raise SchemaError(f"{where}: duplicate field {name!r}")
        seen.add(name)
        size, align = _size_align(ctype, f"{where}.{name}")
        if off % align:
            raise SchemaError(f"{where}.{name}: offset {off} is not {align}-aligned; reorder fields or add an "
                              f"explicit pad field (no implicit padding)")
        out.append(Field(name, ctype, off, size, f.get("doc", "")))
        off += size
    return out, off


def load(path: Path = SCHEMA) -> Schema:
    data = tomllib.loads(path.read_text())
    header, hsize = _lay_out(data["header"]["fields"], 0, "header")
    if hsize != HEADER_SIZE or [f.name for f in header][:3] != ["type", "version", "len"]:
        raise SchemaError(f"header: must be {HEADER_SIZE} bytes starting type, version, len (ADR-0008); got {hsize}")
    flags = []
    for fl in data.get("flag", []):
        if not 0 <= fl["bit"] < 16:
            raise SchemaError(f"flag {fl['name']}: bit {fl['bit']} outside u16")
        flags.append((fl["name"], fl["bit"], fl.get("doc", "")))
    if len({b for _, b, _ in flags}) != len(flags):
        raise SchemaError("flags: two flags share a bit")

    records, keys, types_by_name = [], set(), {}
    for r in data.get("record", []):
        name, rtype, ver, cls = r.get("name"), r.get("type"), r.get("version"), r.get("class")
        where = f"record {name}"
        if not isinstance(name, str) or not RECORD_NAME_RE.match(name):
            raise SchemaError(f"{where}: bad record name")
        if not isinstance(rtype, int) or not 0 < rtype < 0xFFFF:
            raise SchemaError(f"{where}: type must be an integer in 1..65534 (0 is invalid)")
        if not isinstance(ver, int) or not 0 < ver < 0xFFFF:
            raise SchemaError(f"{where}: version must be an integer in 1..65534")
        if cls not in CLASSES:
            raise SchemaError(f"{where}: class {cls!r} not in {sorted(CLASSES)}")
        if types_by_name.setdefault(name, rtype) != rtype or any(n != name and t == rtype for n, t in types_by_name.items()):
            raise SchemaError(f"{where}: a type number belongs to exactly one record name")
        if (rtype, ver) in keys:
            raise SchemaError(f"{where}: (type {rtype}, version {ver}) defined twice")
        keys.add((rtype, ver))
        fields, off = _lay_out(r.get("fields", []), HEADER_SIZE, where)
        var = []
        for v in r.get("var", []):
            if not NAME_RE.match(v.get("name", "")) or not isinstance(v.get("max"), int) or v["max"] <= 0:
                raise SchemaError(f"{where}: bad var field {v!r}")
            var.append(VarField(v["name"], v["max"], v.get("doc", "")))
        # generated metadata for the variable fields: all _full (u32), then all _len (u16)
        meta = [{"name": f"{v.name}_full", "c": "u32", "doc": f"full length of {v.name} in bytes; "
                 f"P15_LEN_UNKNOWN if cut and not known"} for v in var]
        meta += [{"name": f"{v.name}_len", "c": "u16", "doc": f"bytes of {v.name} present in this record"} for v in var]
        names = {f.name for f in fields}
        if names & {m["name"] for m in meta}:
            raise SchemaError(f"{where}: a field name collides with generated variable-field metadata")
        gen, off = _lay_out(meta, off, f"{where} (generated var metadata)")
        fields += [Field(g.name, g.ctype, g.offset, g.size, g.doc, generated=True) for g in gen]
        if off % 8:
            fields.append(Field("_pad", f"char[{8 - off % 8}]", off, 8 - off % 8, "zero; pads the fixed part to 8",
                                generated=True))
            off = _pad8(off)
        rec = Record(name, rtype, ver, cls, r.get("doc", ""), fields, var, off)
        if rec.max_size > MAX_RECORD:
            raise SchemaError(f"{where}: maximum size {rec.max_size} exceeds the u16 len field")
        records.append(rec)
    return Schema(header, data["header"].get("doc", ""), flags, records)


# ---------------------------------------------------------------- layout identity (the lock)

def layout_key(r: Record) -> str:
    return f"{r.name}/{r.type}/v{r.version}"


def layout_hash(fields: list[Field], var: list[VarField], size: int) -> str:
    canon = {"size": size, "fields": [[f.name, f.ctype, f.offset] for f in fields],
             "var": [[v.name, v.max] for v in var]}
    return hashlib.sha256(json.dumps(canon, sort_keys=True).encode()).hexdigest()


def lock_entries(s: Schema) -> dict[str, str]:
    out = {"HEADER": layout_hash(s.header, [], HEADER_SIZE)}
    for r in s.records:
        out[layout_key(r)] = layout_hash(r.fields, r.var, r.fixed_size)
    return out


def schema_hash(s: Schema) -> str:
    """One hash for the whole schema: of every layout's hash. It names the schema in each WAL
    segment header (ADR-0007), and changes whenever any record layout does."""
    return hashlib.sha256(json.dumps(lock_entries(s), sort_keys=True).encode()).hexdigest()


def check_lock(s: Schema, lock: dict[str, str]) -> list[str]:
    """Problems with the lock: a locked layout changed, or a layout is not locked yet."""
    probs = []
    for key, h in lock_entries(s).items():
        if key not in lock:
            probs.append(f"{key}: new layout, not in schema/lock.json (run gen.py --update-lock)")
        elif lock[key] != h:
            probs.append(f"{key}: layout changed without a version bump (locked {lock[key][:12]}, now {h[:12]})")
    return probs


# ---------------------------------------------------------------- emitters

BANNER = "Generated by schema/gen/gen.py from schema/records.toml. Do not edit."


def emit_c(s: Schema) -> str:
    L = ["/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */", f"/* {BANNER} */",
         "#ifndef P15_RECORDS_H", "#define P15_RECORDS_H", "",
         "#ifndef __VMLINUX_H__", "#include <linux/types.h>", "#endif", "",
         "#define P15_ASSERT(c, m) _Static_assert(c, m)",
         "#define P15_OFFSETOF(t, f) __builtin_offsetof(t, f)", "",
         f"#define P15_HEADER_SIZE {HEADER_SIZE}", f"#define P15_LEN_UNKNOWN 0x{LEN_UNKNOWN:X}u", "",
         "/* sha256 of every layout's hash (schema/gen/gen.py schema_hash): the WAL header's schema.hash */",
         f'#define P15_SCHEMA_HASH "{schema_hash(s)}"', ""]
    for name, bit, doc in s.flags:
        L.append(f"#define P15_F_{name} (1u << {bit})   /* {doc} */")
    L.append("")
    L.append("enum p15_type {")
    for r in sorted({(r.type, r.name) for r in s.records}):
        L.append(f"\tP15_T_{r[1]} = {r[0]},")
    L += ["};", ""]

    def struct(name: str, fields: list[Field], size: int, doc: str, with_header: bool) -> None:
        L.append(f"/* {doc} */")
        L.append(f"struct {name} {{")
        if with_header:
            L.append("\tstruct p15_hdr h;")
        for f in fields:
            L.append(f"\t{f.c_decl()};{'   /* generated */' if f.generated else ''}")
        L.append("} __attribute__((aligned(8)));")
        L.append(f"P15_ASSERT(sizeof(struct {name}) == {size}, \"{name} size\");")
        if with_header:
            L.append(f"P15_ASSERT(P15_OFFSETOF(struct {name}, h) == 0, \"{name}.h offset\");")
        for f in fields:
            L.append(f"P15_ASSERT(P15_OFFSETOF(struct {name}, {f.name}) == {f.offset}, \"{name}.{f.name} offset\");")
        L.append("")

    struct("p15_hdr", s.header, HEADER_SIZE, s.header_doc, False)
    latest: dict[str, Record] = {}
    for r in s.records:
        struct(r.c_struct, r.fields, r.fixed_size, f"{r.name} v{r.version} ({r.cls}): {r.doc}", True)
        L.append(f"#define P15_{r.name}_V{r.version}_MAX_SIZE {r.max_size}")
        for v in r.var:
            L.append(f"#define P15_{r.name}_V{r.version}_{v.name.upper()}_MAX {v.max}")
        L.append("")
        if r.version > latest.get(r.name, r).version or r.name not in latest:
            latest[r.name] = r
    L.append("/* The current version of each record type: what the BPF programs emit. */")
    for name, r in latest.items():
        L.append(f"#define P15_{name}_VERSION {r.version}")
        L.append(f"#define p15_{name.lower()} {r.c_struct}")
        L.append(f"#define P15_{name}_MAX_SIZE P15_{name}_V{r.version}_MAX_SIZE")
        for v in r.var:
            L.append(f"#define P15_{name}_{v.name.upper()}_MAX P15_{name}_V{r.version}_{v.name.upper()}_MAX")
    L += ["", "#endif /* P15_RECORDS_H */", ""]
    return "\n".join(L)


def _np_dtype_expr(fields: list[Field], size: int, header: bool) -> str:
    names = (["h"] if header else []) + [f.name for f in fields]
    formats = (["HEADER_DTYPE"] if header else []) + [repr(f.np_format) for f in fields]
    offsets = ([0] if header else []) + [f.offset for f in fields]
    return (f"np.dtype({{'names': {names!r}, 'formats': [{', '.join(formats)}], "
            f"'offsets': {offsets!r}, 'itemsize': {size}}})")


def emit_py(s: Schema) -> str:
    L = ["# SPDX-License-Identifier: MIT", f"# {BANNER}", '"""Record layouts as numpy dtypes (ADR-0008).', "",
         "RECORDS maps (type, version) to its layout. The dtype covers the fixed part; the variable-length",
         "fields follow it in the order of `var`, each `<name>_len` bytes long. Decoders must never read",
         'past the header\'s len (ADR-0008 rule 5)."""', "",
         "from typing import NamedTuple", "", "import numpy as np", "",
         f"HEADER_SIZE = {HEADER_SIZE}", f"LEN_UNKNOWN = 0x{LEN_UNKNOWN:X}",
         f'SCHEMA_HASH = "{schema_hash(s)}"   # the WAL header\'s schema.hash (ADR-0007)', ""]
    for name, bit, _ in s.flags:
        L.append(f"F_{name} = 1 << {bit}")
    L += ["", f"HEADER_DTYPE = {_np_dtype_expr(s.header, HEADER_SIZE, False)}", "", "",
          "class Layout(NamedTuple):", "    name: str", "    type: int", "    version: int", "    cls: str",
          "    dtype: np.dtype", "    fixed_size: int", "    max_size: int",
          "    var: tuple[tuple[str, int], ...]   # (name, max bytes), in tail order", "", ""]
    L.append("TYPES = {")
    for t, n in sorted({(r.type, r.name) for r in s.records}):
        L.append(f"    {n!r}: {t},")
    L += ["}", "", "RECORDS = {"]
    for r in s.records:
        var = tuple((v.name, v.max) for v in r.var)
        L.append(f"    ({r.type}, {r.version}): Layout({r.name!r}, {r.type}, {r.version}, {r.cls!r},")
        L.append(f"        {_np_dtype_expr(r.fields, r.fixed_size, True)},")
        L.append(f"        {r.fixed_size}, {r.max_size}, {var!r}),")
    L += ["}", ""]
    return "\n".join(L)


def emit_md(s: Schema) -> str:
    L = ["# Records", "", f"> {BANNER}", "", "Little-endian, natural alignment, padded to 8 bytes (ADR-0008).", "",
         f"## Common header ({HEADER_SIZE} bytes)", "", s.header_doc, "",
         "| Offset | Field | Type | Meaning |", "|---:|---|---|---|"]
    L += [f"| {f.offset} | `{f.name}` | {f.ctype} | {f.doc} |" for f in s.header]
    if s.flags:
        L += ["", "**Flags** (`flags`):", ""] + [f"- bit {b} `{n}`: {d}" for n, b, d in s.flags]
    for r in s.records:
        L += ["", f"## {r.name} (type {r.type}, version {r.version}, class {r.cls})", "", r.doc, "",
              f"Fixed part {r.fixed_size} bytes; at most {r.max_size} bytes with its variable fields.", "",
              "| Offset | Field | Type | Meaning |", "|---:|---|---|---|", "| 0 | `h` | header | common header |"]
        L += [f"| {f.offset} | `{f.name}` | {f.ctype} | {f.doc}{' *(generated)*' if f.generated else ''} |"
              for f in r.fields]
        if r.var:
            L += ["", "Variable-length fields, after the fixed part in this order:", ""]
            L += [f"- `{v.name}` (at most {v.max} bytes): {v.doc}" for v in r.var]
    return "\n".join(L) + "\n"


def emit_probe(s: Schema) -> str:
    L = ["// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause", f"// {BANNER}",
         "// Puts every record struct into the object's BTF for the three-way layout check (ADR-0008).",
         "// No programs; never loaded.", '#include "vmlinux.h"', '#include "p15_records.h"', "",
         "struct p15_hdr p15_probe_hdr __attribute__((used));"]
    L += [f"struct {r.c_struct} p15_probe_{r.c_struct} __attribute__((used));" for r in s.records]
    L += ['', 'char LICENSE[] __attribute__((section("license"), used)) = "Dual BSD/GPL";', ""]
    return "\n".join(L)


def render(s: Schema) -> dict[str, str]:
    return {"p15_records.h": emit_c(s), "p15_records.py": emit_py(s), "RECORDS.md": emit_md(s),
            "p15_layout_probe.bpf.c": emit_probe(s)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--schema", type=Path, default=SCHEMA)
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--lock", type=Path, default=LOCK)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="fail if generated files or the lock are stale")
    mode.add_argument("--update-lock", action="store_true", help="add new layouts to the lock (never rewrites old ones)")
    args = ap.parse_args(argv)
    try:
        s = load(args.schema)
    except (SchemaError, KeyError, tomllib.TOMLDecodeError) as e:
        print(f"schema error: {e}", file=sys.stderr)
        return 1
    lock = json.loads(args.lock.read_text()) if args.lock.exists() else {}
    files = render(s)
    if args.update_lock:
        changed = [p for p in check_lock(s, lock) if "without a version bump" in p]
        if changed:
            print("refusing to update the lock:\n  " + "\n  ".join(changed), file=sys.stderr)
            return 1
        lock.update({k: h for k, h in lock_entries(s).items() if k not in lock})
        args.lock.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
        print(f"lock: {len(lock)} layouts")
        return 0
    probs = check_lock(s, lock)
    if args.check:
        for name, text in files.items():
            p = args.out / name
            if not p.exists() or p.read_text() != text:
                probs.append(f"{p.relative_to(ROOT) if p.is_relative_to(ROOT) else p}: stale (run gen.py)")
        for p in probs:
            print(p, file=sys.stderr)
        print(f"schema check: {len(s.records)} records, {len(files)} generated files, {len(probs)} problems")
        return 1 if probs else 0
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text)
    for p in probs:
        print(f"warning: {p}", file=sys.stderr)
    print(f"generated {len(files)} files for {len(s.records)} records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
