---
status: proposed
date: 2026-10-25
owner: Ashish Rana
consulted: [maintainer's requirements of 2026-10-26 (typed schemas, one error path, memory safety, observability, structure), ADR-0002, ADR-0008, PR #27/#28 practice, capture blueprint v1 §7 (L-levels), THC rootkit write-up (via quantification.md)]
supersedes: none
---

# 0019: Engineering gates for the C daemon: typed boundaries, one error path, memory-safety checks, self-observability, and a fixed module layout

## Context and problem statement

The daemon is in C (ADR-0002), so the language gives no memory safety, no exceptions and no schema types. The maintainer asked for the standards a good full-stack codebase takes for granted:
- schemas that are typed and validated at every boundary (as zod does in TypeScript);
- one place where errors are handled;
- memory safety;
- proper observability;
- a clear code structure.

PRs #26–#28 already do parts of this: generated layouts with static asserts, length checks, ASan/UBSan, mutation sweeps. None of it is yet a **rule** with a CI check.

**Question:** which engineering gates must every daemon change pass, and how is each one checked automatically?

## Decision drivers

1. A bug class that can be made impossible, or caught by a machine, must be. Review is the last line, not the first.
2. Every gate is a CI check or a test, not a convention.
3. The capture must report its own health. A silent blind spot is the worst failure a HIDS can have.
4. Gates must not slow the drain's hot path.

## Considered options

1. **Seven gates, each with a CI check** (below)
2. Rewrite the daemon in Rust for memory safety
3. Keep the current practice as conventions

## Decision outcome

**Chosen option:** option 1. It turns today's practice into checked rules (drivers 1, 2) and adds what is missing: self-observability (driver 3) and one error path.
- **Option 2** reopens ADR-0002 for a component that is about 1–2 k lines of bounded, single-purpose C, where these gates catch the classes Rust would prevent. The trade is recorded under Falsifier.

### G1. Typed boundaries: every byte that crosses a boundary is parsed by code that refuses what it doesn't know

This is the zod rule, applied at each of five boundaries:

| Boundary | Single source | Generated or specified code | Refuses |
|---|---|---|---|
| kernel → daemon | `schema/records.toml` (ADR-0008) | C structs with static asserts; `p15_rec_check` | unknown type or version; `len` outside bounds; variable fields past `len` |
| daemon → disk | `docs/formats/p15w-v1.md` (ADR-0007) | `daemon/wal.c` writer and scanner | any batch failing the §4 checks |
| disk → Python | the same TOML | a **generated** decoder (step 5): no default values, numpy dtypes from the generator | the same as `p15_rec_check`, plus unknown header keys of a newer major version |
| Python → DuckDB / Parquet | the same TOML | **generated** DDL / Arrow schema (Phase 5); never hand-written | — |
| operator → daemon | one config struct | a strict parser | unknown keys and out-of-range values; the effective config is echoed into the WAL header |

### G2. One error path

1. **Errors are returned, and must be checked.**
   - Every fallible function returns `0` or `-errno` and is declared `P15_MUST_CHECK` (`__attribute__((warn_unused_result))`).
   - With `-Werror`, an ignored error is a **build failure**. This is C's equivalent of an unhandled promise lint.
2. **One fatal path.**
   - `p15_fail(run, code, reason)` is the only way out on error. It stops the drain, flushes what is queued, and writes a final END record with the code and reason.
   - It exits with a code from one table, `daemon/exitcodes.h`. Every code is documented, and a test covers each one.
   - CI fails on any `exit(`, `abort(` or `_exit(` in `daemon/` outside that function and the test child.
3. **Run state is a machine, not a log line:**
   - `RUNNING`;
   - `DEGRADED`: counted bulk loss;
   - `INVALID`: spine loss, invariant broken or an I/O error.

   It is written in every STATS record and in the END record, and decides the exit code.
4. **Signals.**
   - `SIGTERM`/`SIGINT` give an orderly stop: drain to empty, final STATS, END, close.
   - Crash signals are **not** caught. The core dump is the evidence; systemd restarts the daemon and the next segment's header counts the restart.

### G3. Memory safety

1. **Kernel side:** the BPF verifier proves memory safety of every program. Loads happen in CI (`make smoke`).
2. **Hot path:**
   - no `malloc` after start-up in the drain, queue or writer: batches and the queue are preallocated;
   - only bounded copies;
   - no VLAs (`-Wvla`).
3. **Compiler hardening for every daemon binary:**
   - `-D_FORTIFY_SOURCE=3 -fstack-protector-strong -fstack-clash-protection -fcf-protection -fPIE -pie -Wl,-z,relro,-z,now`;
   - warnings: `-Wall -Wextra -Wshadow -Wformat=2 -Wvla -Wstrict-prototypes -Wmissing-prototypes`, with `-Werror`.
4. **Dynamic checks in CI:**
   - every C test under ASan + UBSan (exists);
   - the drain/writer queue under ThreadSanitizer (ADR-0017).
5. **Fuzzing in CI on every PR:**
   - libFuzzer harnesses for `p15_rec_check`, `p15w_scan_buf` and the config parser, 60 s each, with a committed seed corpus;
   - the Python decoder under Atheris (blueprint L1) once it exists;
   - a crash fails the PR, and its input is added to the corpus.
6. **Static analysis in CI:**
   - `gcc -fanalyzer` and clang `scan-build` on `daemon/`, zero findings; every suppression carries a reason;
   - CodeQL on `main` (free for public repositories).

### G4. The capture observes itself

1. **STATS record** into the WAL every second, from the daemon ring:
   - per type: seen, emitted, reserve_failed, read_failed, truncated;
   - per ring: fill high-water;
   - the drain's poll-to-poll gap as a fixed histogram;
   - queue depth high-water;
   - WAL: bytes, batches, fsyncs, worst fsync latency;
   - the daemon's CPU time and RSS (`getrusage`);
   - the run state (G2).
2. **A live view without a network port.** Every second, a Prometheus text-format file is written atomically (write, then `rename`). The node_exporter textfile collector convention lets any monitoring stack read it. No listener in v1, so no added attack surface.
3. **Structured logs:** one line per event on stderr (journald). Each line has a level, a code from a table, a message and `key=value` fields. Nothing is logged per record.
4. **A canary, a continuous self-test.**
   - Every 10 s (configurable) the daemon starts `fd-canary`: fork, exec of `/bin/true` with a nonce in argv, exit.
   - It checks that the canary's FORK, EXEC and EXIT arrive within 1 s.
   - A miss writes a CANARY_MISS record, raises a counter, logs an error and moves the run to `DEGRADED`.
   - This catches silent blindness, a stuck pipeline or detached programs, between the load-time self-test (ADR-0003) and the end of the run. Published rootkits hide events by hooking the ring-buffer functions (THC write-up). A canary at least raises the cost: they must recognise and pass it.
   - Cost: one short process every 10 s (INF: negligible).

### G5. Module layout: one job per file, one contract per header

The daemon's files:

| File | Job |
|---|---|
| `loader.c` | open, load, attach, self-test |
| `drain.c` | poll, batch, sequence, GAP detection (ADR-0017) |
| `queue.c` | bounded SPSC queue |
| `wal.c` | writer, scanner (exists) |
| `stats.c` | counters, STATS records, textfile |
| `canary.c` | |
| `config.c` | |
| `p15d.c` | `main`: wiring only |

Rules:
- Each header states the contract: inputs, outputs, errors, thread ownership.
- **No global mutable state** outside one `struct p15_run`, passed explicitly.
- Style: a committed `.clang-format`, checked in CI.

### G6. Test levels (made concrete here; ADR-0011 will add the coverage matrix)

| Level | What | Rule |
|---|---|---|
| L0 | build with `-Werror`, analyzers, format check | zero findings |
| L1 | unit tests in C and Python; a mutation sweep per module | ≥ 90 % of planted bugs caught; every survivor shown to be equivalent, or fixed |
| L2 | fuzzing (G3.5) | no crash in the CI budget |
| L3 | sanitizer and ThreadSanitizer runs | clean |
| L4 | VM integration | self-test, canary, the functional workloads of ADR-0018 rule 4, invariant closes |

### G7. Review (unchanged)

The maintainer reviews every PR and re-runs the test command in a fresh clone (CLAUDE.md).

### Consequences

- Good: whole bug classes become build or CI failures: ignored errors, unchecked lengths, memory errors on tested paths, data races in the queue, malformed input.
- Good: the capture reports its own health every second, continuously proves it can still see (canary), and ends every run with a machine-readable verdict.
- Good: every boundary is typed from one source, as the maintainer asked; DuckDB tables come from the same TOML.
- Bad: CI time grows by fuzzing (3 × 60 s) and analyzers (about a minute). Accepted.
- Bad: hardening flags and `-fanalyzer` may flag existing code; fixing that is part of the PR that turns them on.

### Confirmation

Each gate is a CI step:

| Gate | Check |
|---|---|
| G1 | schema check, layout check (exist); decoder and DDL generation checks (steps 5 and 5b) |
| G2 | the build (`warn_unused_result` + `-Werror`); a grep check; exit-code tests |
| G3 | hardened build flags; `test-c-asan` (exists); a TSan job; fuzz jobs; analyzer jobs |
| G4 | the STATS record and canary in the L4 VM run; a test that a stuck drain raises CANARY_MISS |
| G5 | format check; one header per module |
| G6 | `make mutate-*` sweeps per module (`mutate-wal` exists) |

The gates are turned on in order, each in its own PR:
1. G2 and G3 flags, with the existing code fixed to pass;
2. fuzzing;
3. G4 with `p15d` (step 4b).

### Falsifier

Reopen (and reconsider option 2, Rust) if:
- a memory-safety bug reaches `main` that these gates should have caught;
- the daemon grows past about 5 k lines, where C's costs outweigh one language for kernel and daemon.

## Evidence

| # | Claim | Grade | Source |
|---|---|---|---|
| 1 | Current practice: generated layouts with static asserts and a three-way check; length checks; ASan/UBSan; mutation sweeps 14/14, 12/12, 27/27 | MEAS | E-0063, E-0064, E-0068; `make check`, `make test-c-asan`, `make mutate-wal` |
| 2 | Published rootkits blind eBPF tools by hooking `bpf_ringbuf_*`, `perf_event_output` and the iterator functions | DOC (blog) | THC, "Breaking eBPF Security" (via `quantification.md`) |
| 3 | The node_exporter textfile collector reads `*.prom` files written atomically | INF (well-known convention; to cite the node_exporter README in the G4 PR) | — |
| 4 | `warn_unused_result` makes an ignored return value a warning, and `-Werror` makes it an error | INF (GCC/Clang documentation; to cite in the G2 PR) | — |
| 5 | Falco runs a short fuzzing smoke in CI | DOC | via blueprint v1 L1 |

## Pros and cons of the options

### 1. Seven checked gates
- Good: machine-checked; covers the maintainer's list; keeps one language.
- Bad: more CI time; some up-front fixing.

### 2. Rust daemon
- Good: memory and thread safety by construction.
- Bad: reopens ADR-0002; libbpf-rs adds a binding layer; two languages for one data path. Not justified at the current size.

### 3. Conventions only
- Bad: not checked, so not guaranteed.
