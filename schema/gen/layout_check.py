#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Three-way layout check (ADR-0008 rule 3.2): the generator, the BTF that clang put in the
compiled probe object, and the generated numpy dtypes must agree on every struct's size and
every member's name, order and offset.

    bpftool -j btf dump file build/p15_layout_probe.bpf.o > build/layout_btf.json
    python3 schema/gen/layout_check.py build/layout_btf.json

Exit 0 if all three agree; 1 with every disagreement listed.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gen  # noqa: E402

Members = list[tuple[str, int]]       # (name, byte offset), in declaration order


def from_generator(s: gen.Schema) -> dict[str, tuple[int, Members]]:
    out = {"p15_hdr": (gen.HEADER_SIZE, [(f.name, f.offset) for f in s.header])}
    for r in s.records:
        out[r.c_struct] = (r.fixed_size, [("h", 0)] + [(f.name, f.offset) for f in r.fields])
    return out


def from_btf(btf: dict, wanted: set[str]) -> dict[str, tuple[int, Members]]:
    out = {}
    for t in btf.get("types", []):
        if t.get("kind") == "STRUCT" and t.get("name") in wanted:
            mem = []
            for m in t["members"]:
                if m["bits_offset"] % 8:
                    raise ValueError(f"{t['name']}.{m['name']}: bit offset {m['bits_offset']} is not byte-aligned")
                mem.append((m["name"], m["bits_offset"] // 8))
            out[t["name"]] = (t["size"], mem)
    return out


def from_numpy(mod, s: gen.Schema) -> dict[str, tuple[int, Members]]:
    def members(dt) -> Members:
        return [(n, dt.fields[n][1]) for n in dt.names]
    out = {"p15_hdr": (mod.HEADER_DTYPE.itemsize, members(mod.HEADER_DTYPE))}
    for r in s.records:
        lay = mod.RECORDS[(r.type, r.version)]
        out[r.c_struct] = (lay.dtype.itemsize, members(lay.dtype))
    return out


def compare(views: dict[str, dict[str, tuple[int, Members]]]) -> list[str]:
    """Every struct named by the first view must be identical in all views."""
    names = list(views)
    ref_name, ref = names[0], views[names[0]]
    probs = []
    for struct, (size, mem) in ref.items():
        for other in names[1:]:
            got = views[other].get(struct)
            if got is None:
                probs.append(f"{struct}: missing from {other}")
                continue
            if got[0] != size:
                probs.append(f"{struct}: size {ref_name} {size} != {other} {got[0]}")
            if got[1] != mem:
                diff = [f"{a} vs {b}" for a, b in zip(mem, got[1]) if a != b]
                if len(mem) != len(got[1]):
                    diff.append(f"{len(mem)} members vs {len(got[1])}")
                probs.append(f"{struct}: members differ between {ref_name} and {other}: {'; '.join(diff)}")
    return probs


def load_generated_module(path: Path):
    spec = importlib.util.spec_from_file_location("p15_records", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    s = gen.load()
    g = from_generator(s)
    views = {"generator": g,
             "btf": from_btf(json.loads(Path(argv[0]).read_text()), set(g)),
             "numpy": from_numpy(load_generated_module(gen.OUT / "p15_records.py"), s)}
    probs = compare(views)
    for p in probs:
        print(p, file=sys.stderr)
    print(f"layout check: {len(g)} structs x 3 views, {len(probs)} disagreements")
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
