# Fiery Dragon

A lossless, versioned eBPF capture layer for host provenance on Linux.

Fiery Dragon records what happens on a host:
- **who** ran what (process lifecycle);
- **what** they read and wrote (files, pipes, sockets, io_uring), with byte counts and kernel-resolved identities;
- **where** they connected.

Every event is written as a compact, versioned binary record to a write-ahead log. A provenance graph and detectors are built from that log later, at their own pace. Capture never waits for analysis, and nothing is dropped without being counted.

> **Status: Phase 0 (ground truth).** There is no capture code yet. The platform is fixed and measured, and the design decisions are being written down as ADRs. See [`docs/STATE.md`](docs/STATE.md).

## Why it exists

It is the capture layer of **ESE-P15**, a host intrusion detection system:

```
eBPF capture (this repo) → provenance graph → detection (rules + ML) → FPGA network enforcement
```

The previous capture layer (ESE-P15 v3.7) taught us where capture breaks:
- the kernel couldn't be tested;
- the graph was built inside the event callback;
- the event layout wasn't versioned;
- caps dropped data silently;
- "opened with write permission" was recorded instead of "wrote N bytes".

This repo is a rebuild designed around those lessons. v3.7 is kept only as a reference oracle.

## Design in one paragraph

- **Platform:** Ubuntu 26.04 LTS on its GA 7.0 kernel, pinned.
- **Kernel side:** BPF programs written in C with libbpf and CO-RE. They attach to `fexit` on the VFS read/write paths, to the `sock_send_length`/`sock_recv_length` tracepoints and the io_uring completion tracepoint, and to LSM-named kernel functions for paths and capability flags.
- **Filtering:** in-kernel filtering only by *who* and *what kind*. No sampling, no time windows, no in-kernel deduplication.
- **Transport:** two BPF ring buffers. The spine ring (lifecycle and capability events) is never shed; the bulk ring carries data flows.
- **Daemon:** a small C daemon drains both rings into a segmented write-ahead log and a shared-memory ring.
- **Analysis tier:** Python reads both in numpy batches.
- **Schema:** one file (`schema/records.yaml`) generates the C header, the Python dtype and the docs.

## Repository layout (planned; created as each part lands)

```
.github/        CI workflows, PR template, CODEOWNERS
docs/           STATE.md, decisions (ADRs), proposals, runbooks, evidence, journal
schema/         records.yaml (single source of truth) + generator + generated outputs
bpf/            kernel-side programs (dual BSD/GPL)
daemon/         C loader, drain, write-ahead log, shared-memory ring
python/         analysis tier: reader, decoder, identity, graph, store, exporters
tests/          kernel behavioural tests, evasion corpus, fixtures
bench/          event-rate census, loss ramp, overhead harness
tools/          VM creation, importers, inspectors
third_party/    vendored, pinned dependencies (libbpf)
```

## How work happens here

- GitHub flow: `main` is protected, and every change is a small pull request with a test command and its output. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Every design decision is an ADR in [`docs/decisions/`](docs/decisions/), with evidence and a falsifier.
- Every number links to the raw output that produced it, under `docs/evidence/`.

## License

- Userspace code, tools and docs: **MIT** ([`LICENSE`](LICENSE)).
- eBPF programs under `bpf/`: **GPL-2.0-only OR BSD-2-Clause**. The kernel requires a GPL-compatible license for tracing programs to use GPL-only helpers.
- Each source file carries an SPDX identifier, and full texts are in [`LICENSES/`](LICENSES/).
- Vendored code under `third_party/` keeps its own license.
