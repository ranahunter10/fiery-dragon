---
status: proposed
date: 2026-10-25          # proposed; set to the merge date on acceptance
owner: Ashish Rana
consulted: [capture blueprint v1 §0.6, §1 (L1, L6, L7), §4.3, §5.5 (2026-10-21), ADR-0009 (proposed)]
supersedes: none
---

# 0008: One schema file generates every record layout; per-type versions; a 32-byte common header on the boot clock

## Context and problem statement

In v3.7 the record layout was written by hand twice, once in C and once in Python (blueprint L6). A Python default (`getattr(ev, "ts", 0)`) hid a renamed field (L7). A decoder read 110 bytes where the kernel wrote 2, and fabricated a peer (L1).

The new capture will write records for years, through format changes, and every old WAL must stay readable.

**Question:** where is the record layout defined, how do the C, BPF and Python sides stay identical, what does every record start with, and how does the format evolve?

## Decision drivers

1. **One definition.** No layout is ever typed twice.
2. **Mechanical proof that all sides agree**, in CI, on every change.
3. **Old data stays readable forever**, and a layout change without a version bump is impossible to merge.
4. **Bounded decoding.** Nothing reads past a record's stated length; no field has a silent default.
5. No new runtime dependencies for the generator.

## Considered options

1. **One schema file in TOML, a Python generator, generated C header + numpy dtypes + docs, checked in and CI-verified**
2. The same with YAML (the blueprint's proposal; needs PyYAML)
3. Hand-written C structs, with Python decoding via `ctypes`/`struct` (v3.7)
4. An IDL such as protobuf or FlatBuffers

## Decision outcome

**Chosen option:** option 1, because it satisfies drivers 1–4 like option 2 and needs nothing outside Python's standard library: `tomllib` is built in since 3.11 (driver 5). Options 3 and 4 fail driver 1 or don't fit BPF, which can't call a serializer.

### The rules

1. **Source:** `schema/records.toml`. Each record type has a name, numeric `type`, `version`, class (`SPINE`/`FLOW`/`OPEN`/…), and fields with C type, meaning and unit.
2. **Generator:** `schema/gen/` (Python 3.14, standard library only). It produces, into `schema/generated/`, checked in:
   - `p15_records.h`: C structs plus `_Static_assert` on every size and offset;
   - `p15_records.py`: numpy structured dtypes and enums;
   - `RECORDS.md`: the human reference.
   - DDL for the store comes in Phase 5.
3. **CI checks** (Phase 1, part of the L0 level):
   1. Re-generate and `git diff --exit-code`: the generated files match the source.
   2. **Three-way layout check:** sizes and offsets from (a) the generator, (b) the BTF in the compiled `.bpf.o`, and (c) the numpy dtype must be identical.
   3. **Version guard:** `schema/lock.json` records a hash of each `(type, version)` layout. A changed hash without a version bump fails.
4. **Versioning:**
   - every record carries `type`, `version` and `len`;
   - a change to a type's layout bumps that type's version, and decoders for every old version are kept;
   - an unknown type or version is **skipped by `len` and counted**, never guessed;
   - the WAL format has its own major.minor (ADR-0007).
5. **Decoding:**
   - generated decoders have **no defaults**;
   - a missing or out-of-range field is an error that is counted;
   - variable-length fields carry their own copied length and full length, and **no decoder reads past `len`** (L1);
   - the decoder is fuzzed in CI (blueprint L1).
6. **Byte order and alignment:** little-endian (x86-64 only), natural alignment, records padded to 8 bytes. The WAL header records the byte order.

### The common header (32 bytes, every record)

| Offset | Field | Type | Meaning |
|---:|---|---|---|
| 0 | `type` | u16 | record type |
| 2 | `version` | u16 | layout version of that type |
| 4 | `len` | u16 | total record length in bytes, header included |
| 6 | `flags` | u16 | per-record flags, e.g. "truncated" |
| 8 | `ts_ns` | u64 | event time, **`CLOCK_BOOTTIME`** ns (`bpf_ktime_get_boot_ns()`) |
| 16 | `tgid` | u32 | process id, init namespace (ADR-0009) |
| 20 | `tid` | u32 | thread id |
| 24 | `start_ns` | u64 | thread-group leader's `start_boottime` (ADR-0009) |

**Why the boot clock:**
- `start_ns` is on the boot clock (ADR-0009), and one clock for both avoids a conversion.
- Unlike `CLOCK_MONOTONIC`, it keeps counting across suspend.
- The WAL header anchors it to wall time (ADR-0007).

**This is a choice for the maintainer:** the blueprint's header used `ts_mono`.

### Consequences

- Good: v3.7's three layout bugs (L1, L6, L7) each have a mechanical guard.
- Good: no third-party dependency in the generator; the schema is readable in a PR diff.
- Bad: 32 bytes of header leave 32 bytes for a FLOW record's payload under the ≤ 64 B target (blueprint §4.3). Whether that is enough is measured in Phase 2.
- Bad: the generator is new code with its own tests (L2), and a reviewer reviews it through those tests (CONTRIBUTING: generated code is reviewed through its generator).

### Confirmation

- The three CI checks above, introduced with the first spine record in Phase 1.
- An L1 test (`BPF_PROG_RUN`) encodes a record in BPF and decodes it with the generated numpy dtype, field by field.

### Falsifier

Reopen if:
- the three-way check can't be made to agree for some field type (BPF and C disagree on layout), which would need a different schema mechanism;
- the 32-byte header makes the measured FLOW records exceed the WAL bandwidth budget (ADR-0007, census sizing).

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | v3.7's hand-mirrored layout, silent default, and over-read bugs | DOC | blueprint v1 §1, L1/L6/L7 (v3.7 engineering journal) |
| 2 | `tomllib` is in Python's standard library since 3.11 | DOC/MEAS | Python docs; `import tomllib` works on 3.13 (dev container) and 3.14 is the target |
| 3 | `bpf_ktime_get_boot_ns()` exists for tracing programs | DOC | `include/uapi/linux/bpf.h`; to be shown by the first spine load (Phase 1) |
| 4 | `start_boottime` is on the boot clock | SRC | `kernel/fork.c` line 2363 at v7.0 (ADR-0009) |
| 5 | A layout-change-without-bump guard is established practice (Falco `driver-schema-version.yml`) | SRC | blueprint v1 §1 L6 |

## Pros and cons of the options

### 1. TOML + generator
- Good: standard library only; diff-friendly.
- Bad: TOML is less familiar than YAML for nested tables. The schema is shallow, so this matters little.

### 2. YAML + generator
- Good: what the blueprint proposed.
- Bad: needs PyYAML, a dependency for one file.

### 3. Hand-written structs
- Bad: exactly v3.7's failure (L6).

### 4. Protobuf / FlatBuffers
- Bad: BPF can't run a serializer; it would still need a fixed C layout underneath.
