# Record schema (ADR-0008)

[`records.toml`](records.toml) is the **only** place a record layout is written. Everything else is generated from it and checked in:

| Generated file | Used by |
|---|---|
| [`generated/p15_records.h`](generated/p15_records.h) | BPF programs and the C daemon. `_Static_assert` on every size and offset |
| [`generated/p15_records.py`](generated/p15_records.py) | the Python tier. numpy dtypes keyed by `(type, version)` |
| [`generated/RECORDS.md`](generated/RECORDS.md) | people: the reference for every field |
| [`generated/p15_layout_probe.bpf.c`](generated/p15_layout_probe.bpf.c) | the three-way layout check (puts every struct into BTF) |

```bash
python3 schema/gen/gen.py                # regenerate after editing records.toml
python3 schema/gen/gen.py --update-lock  # record a NEW (type, version) layout in lock.json
python3 schema/gen/gen.py --check        # CI: generated files current, no locked layout changed
make layout-check                        # CI: generator == BTF of the compiled probe == numpy
```

## Changing a record

- **Adding or changing a field changes the layout.** Bump that record's `version`: add a new `[[record]]` block with the same name and type and the next version, and keep the old block, since old WAL segments still need it.
- Then run `--update-lock`. The lock never rewrites an existing entry: changing a locked layout without a bump fails both `--check` and `--update-lock`.
- **No implicit padding:** a misaligned field is an error, so reorder the fields. The generator pads only the end of the fixed part, and says so (`_pad`, marked *generated*).

## Tests

```bash
python3 -m unittest -v schema/gen/test_gen.py
```

- 29 tests: layouts, every schema error, the lock, stale-file detection, the generated C (compiled with gcc, including a deliberately wrong assert that must fail) and numpy, and the layout comparison.
- Mutation check: 14 of 14 deliberate bugs caught.
