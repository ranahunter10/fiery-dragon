# SPDX-License-Identifier: MIT
"""P15W v1.0 reader: segments and runs (docs/formats/p15w-v1.md, ADR-0007).

The rules are the spec's, in its order, and match the C scanner (daemon/wal.c p15w_scan_buf):

- a segment whose header fails a check is not read at all (HeaderError);
- the batches are walked from header_len, and the walk stops at the first batch that breaks
  any of rules 1-9 of §4;
- a stop at a torn tail is reported as a `Stop` with torn=True (what a crash leaves);
- any other stop is corruption: reported as a `Stop` with torn=False, never skipped silently.

CRC32C is google-crc32c's C implementation, pinned in python/requirements.txt. Its pure-Python
fallback is refused (STATE decision 12: "pinned, with no fallback"): it would be silent and
about 100 times slower.

    run = read_run(Path("/var/lib/p15/20261102T101500Z-1a2b3c4d"))
    for rec in run.records():          # every ring, merged by ts_ns (ADR-0006 rule 5)
        ...
"""

from __future__ import annotations

import heapq
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

import google_crc32c

from . import records as R

if google_crc32c.implementation != "c":
    raise ImportError("google-crc32c is using its pure-Python fallback; install the pinned wheel "
                      "(python/requirements.txt). The reader refuses the fallback.")

SEG_MAGIC = b"P15W"
BATCH_MAGIC = b"P15B"
MAJOR, MINOR = 1, 0
BYTE_ORDER = 0x01020304
PREFIX = struct.Struct("<4sHHIIIIII")         # §2.1, 32 bytes
ENTRY = struct.Struct("<HHI")                  # §2.2, 8 bytes
BATCH = struct.Struct("<4sHHIIQIIII")          # §3.1, 40 bytes
RINGS = ("spine", "bulk", "daemon")
MAX_PAYLOAD = 16 << 20
MAX_VALUE = 65536
KEY_RE = re.compile(rb"[a-z0-9._-]+\Z")
SEG_RE = re.compile(r"seg-(\d{8})\.p15w\Z")
IDENTITY_KEYS = ("run.id", "boot_id", "schema.hash")   # the same in every segment of a run

# §4's stop causes, numbered as in the spec
CAUSES = {
    1: "fewer than 40 bytes remain",
    2: "wrong batch magic",
    3: "batch header CRC does not match",
    4: "a reserved field or flags is not 0, or ring is not 0-2",
    5: "count or payload_len breaks §3.1",
    6: "payload_len is larger than the bytes remaining",
    7: "payload CRC does not match",
    8: "the records do not tile the payload, or their number is not count",
    9: "first_seq breaks §3.2",
}


def crc32c(data) -> int:
    return google_crc32c.value(bytes(data)) & 0xFFFFFFFF


class HeaderError(ValueError):
    """The segment header failed a check (§4 last paragraph): the segment is not read."""


class RunError(ValueError):
    """The run directory breaks §1 or a cross-segment rule (index gaps, boot_id, schema)."""


@dataclass(frozen=True)
class Batch:
    offset: int           # of the batch header, in the segment file
    ring: int
    count: int
    first_seq: int
    payload: memoryview


@dataclass(frozen=True)
class Stop:
    """Where a segment's walk ended before its end of file."""
    offset: int
    cause: int
    torn: bool
    detail: str

    def describe(self) -> str:
        kind = "torn tail" if self.torn else "CORRUPTION"
        return f"{kind} at byte {self.offset}: cause {self.cause} ({CAUSES[self.cause]}){': ' + self.detail if self.detail else ''}"


@dataclass
class Segment:
    path: Path
    index: int
    header_len: int
    meta: dict[str, str]
    size: int
    batches: list[Batch] = field(default_factory=list)
    stop: Stop | None = None
    seq_next: dict[int, int] = field(default_factory=dict)   # per ring, after the last valid batch


def parse_header(buf: bytes, expect_index: int | None = None) -> tuple[int, int, dict[str, str]]:
    """§2: returns (segment_index, header_len, metadata). Raises HeaderError on any failure."""
    if len(buf) < PREFIX.size:
        raise HeaderError("shorter than the 32-byte header prefix")
    magic, major, minor, bo, hlen, hcrc, index, nmeta, rsv = PREFIX.unpack_from(buf, 0)
    if magic != SEG_MAGIC:
        raise HeaderError(f"magic {magic!r} is not P15W")
    if (major, minor) != (MAJOR, MINOR):
        raise HeaderError(f"version {major}.{minor}: this reader reads 1.0 only")
    if bo != BYTE_ORDER:
        raise HeaderError(f"byte_order 0x{bo:08x}")
    if hlen < PREFIX.size or hlen % 8 or hlen > len(buf):
        raise HeaderError(f"header_len {hlen} (file {len(buf)} bytes)")
    if rsv:
        raise HeaderError("reserved prefix field is not 0")
    zeroed = bytearray(buf[:hlen])
    zeroed[16:20] = b"\0\0\0\0"
    if crc32c(zeroed) != hcrc:
        raise HeaderError("header CRC does not match")
    if expect_index is not None and index != expect_index:
        raise HeaderError(f"segment_index {index} differs from the file name's {expect_index}")
    meta: dict[str, str] = {}
    p = PREFIX.size
    for _ in range(nmeta):
        if p + ENTRY.size > hlen:
            raise HeaderError("metadata entry past header_len")
        klen, er, vlen = ENTRY.unpack_from(buf, p)
        if not 1 <= klen <= 255 or er or vlen > MAX_VALUE:
            raise HeaderError(f"metadata entry at {p}: key_len {klen}, reserved {er}, value_len {vlen}")
        k0 = p + ENTRY.size
        end = k0 + klen + vlen
        padded = (end + 7) & ~7
        if padded > hlen:
            raise HeaderError("metadata entry past header_len")
        key = bytes(buf[k0:k0 + klen])
        if not KEY_RE.match(key):
            raise HeaderError(f"metadata key {key!r} outside [a-z0-9._-]")
        try:
            val = bytes(buf[k0 + klen:end]).decode("utf-8")
        except UnicodeDecodeError as e:
            raise HeaderError(f"metadata value of {key!r} is not UTF-8") from e
        if any(buf[end:padded]):
            raise HeaderError(f"non-zero padding after metadata {key!r}")
        k = key.decode()
        if k in meta:
            raise HeaderError(f"metadata key {k!r} repeated")
        meta[k] = val
        p = padded
    if p != hlen:
        raise HeaderError(f"metadata ends at {p}, header_len is {hlen}")
    for r in RINGS:
        if f"seq.next.{r}" not in meta:
            raise HeaderError(f"seq.next.{r} missing")
    return index, hlen, meta


def _tiles(payload: memoryview, count: int) -> bool:
    p, n = 0, 0
    while p < len(payload):
        if len(payload) - p < R.HEADER_SIZE:
            return False
        rl = struct.unpack_from("<H", payload, p + 4)[0]
        if rl < R.HEADER_SIZE or rl % 8 or p + rl > len(payload):
            return False
        p += rl
        n += 1
    return n == count


def read_segment(path: Path, seq_expect: dict[int, int] | None = None) -> Segment:
    """Read one segment. seq_expect: the next first_seq per ring that the previous segment left
    (None for the first segment: its header's seq.next.* are taken as given)."""
    m = SEG_RE.match(path.name)
    buf = memoryview(path.read_bytes())
    index, hlen, meta = parse_header(buf, int(m.group(1)) if m else None)
    try:
        hdr_next = {i: int(meta[f"seq.next.{r}"]) for i, r in enumerate(RINGS)}
    except ValueError as e:
        raise HeaderError("seq.next.* is not a decimal number") from e
    if seq_expect is not None and hdr_next != seq_expect:
        raise HeaderError(f"seq.next {hdr_next} differs from where the previous segment ended {seq_expect}")
    seg = Segment(path, index, hlen, meta, len(buf), seq_next=dict(hdr_next))
    p = hlen
    while p < len(buf):
        cause, detail = 0, ""
        rem = len(buf) - p
        if rem < BATCH.size:
            cause = 1
        else:
            magic, ring, flags, count, plen, first, pcrc, rsv1, hcrc, rsv2 = BATCH.unpack_from(buf, p)
            if magic != BATCH_MAGIC:
                cause = 2
            elif crc32c(buf[p:p + 32]) != hcrc:
                cause = 3
            elif flags or rsv1 or rsv2 or ring > 2:
                cause = 4
            elif count < 1 or plen % 8 or plen < R.HEADER_SIZE * count or plen > MAX_PAYLOAD:
                cause, detail = 5, f"count {count}, payload_len {plen}"
            elif plen > rem - BATCH.size:
                cause = 6
            else:
                payload = buf[p + BATCH.size:p + BATCH.size + plen]
                if crc32c(payload) != pcrc:
                    cause = 7
                elif not _tiles(payload, count):
                    cause = 8
                elif first != seg.seq_next[ring]:
                    cause, detail = 9, f"{RINGS[ring]} first_seq {first}, expected {seg.seq_next[ring]}"
        if cause:
            end_of_batch = p + BATCH.size + (plen if rem >= BATCH.size else 0)
            torn = (cause in (1, 6) or (cause == 7 and end_of_batch == len(buf))
                    or not any(buf[p:]))
            seg.stop = Stop(p, cause, torn, detail)
            break
        seg.batches.append(Batch(p, ring, count, first, payload))
        seg.seq_next[ring] = first + count
        p += BATCH.size + plen
    return seg


@dataclass
class Run:
    path: Path
    segments: list[Segment]
    meta: dict[str, str]       # the first segment's header metadata

    @property
    def stops(self) -> list[tuple[Segment, Stop]]:
        return [(s, s.stop) for s in self.segments if s.stop]

    @property
    def corrupt(self) -> bool:
        return any(not st.torn for _, st in self.stops)

    def ring_records(self, ring: int, errors: list | None = None):
        """Every record of one ring, in sequence order. A record that fails its check raises
        RecordError; with `errors`, it is appended there instead and the walk goes on (the batch
        already proved that the records tile, so the next one starts at this one's len)."""
        for s in self.segments:
            for b in s.batches:
                if b.ring != ring:
                    continue
                p = 0
                for i in range(b.count):
                    try:
                        r = R.decode(b.payload, p, ring, b.first_seq + i)
                    except R.RecordError as e:
                        if errors is None:
                            raise
                        errors.append((ring, b.first_seq + i, e))
                        p += struct.unpack_from("<H", b.payload, p + 4)[0]
                        continue
                    p += r.h["len"]
                    yield r

    def records(self):
        """Every record of every ring, merged by ts_ns (ADR-0006 rule 5). Within a ring the order
        stays the ring's own (reservation order), which per task is causal order."""
        def keyed(ring):
            for r in self.ring_records(ring):
                yield (r.h["ts_ns"], ring, r.seq), r

        return (r for _, r in heapq.merge(*(keyed(i) for i in range(len(RINGS))), key=lambda kr: kr[0]))


def read_run(path: Path) -> Run:
    """Read a run directory (§1): contiguous segments from 00000000, one boot_id and schema
    hash throughout, the sequence carried across segments (§3.2)."""
    segs = sorted((p for p in path.iterdir() if SEG_RE.match(p.name)), key=lambda p: p.name)
    if not segs:
        raise RunError(f"{path}: no seg-*.p15w files")
    for i, p in enumerate(segs):
        if int(SEG_RE.match(p.name).group(1)) != i:
            raise RunError(f"{path}: segment {i} missing (found {p.name})")
    out: list[Segment] = []
    expect = None
    for p in segs:
        s = read_segment(p, expect)
        for k in IDENTITY_KEYS:
            if k not in s.meta:
                raise RunError(f"{p.name}: no {k} in the header")
            if out and s.meta[k] != out[0].meta[k]:
                raise RunError(f"{p.name}: {k} differs from segment 0")
        out.append(s)
        expect = dict(s.seq_next)
    meta = out[0].meta
    if meta["schema.hash"] != R.SCHEMA_HASH:
        raise RunError(f"schema.hash {meta['schema.hash'][:12]}... is not this reader's {R.SCHEMA_HASH[:12]}...: "
                       "decode with the schema that wrote it")
    return Run(path, out, meta)


def summary(run: Run) -> tuple[list[str], int]:
    """The record counts in p15w-inspect's words (daemon/p15w_inspect.c), so the end-to-end test
    can compare the two readers line for line. Returns (lines, problems)."""
    errors: list = []
    per_ring = [0] * len(RINGS)
    by_type: dict[int, int] = {}
    for ring in range(len(RINGS)):
        for r in run.ring_records(ring, errors):
            per_ring[ring] += 1
            by_type[r.h["type"]] = by_type.get(r.h["type"], 0) + 1
    lines = [f"records: spine {per_ring[0]}, bulk {per_ring[1]}, daemon {per_ring[2]}; invalid {len(errors)}"]
    names = {t: n for n, t in R.TYPES.items()}
    lines += [f"  {names[t]:<10} {by_type[t]}" for t in sorted(by_type)]
    for s, st in run.stops:
        lines.append(f"{s.path.name}: {st.describe()}")
    for ring, seq, e in errors:
        lines.append(f"invalid record: {RINGS[ring]} seq {seq}: {e.why}")
    return lines, len(errors) + sum(1 for _, st in run.stops if not st.torn)


def main(argv: list[str] | None = None) -> int:
    """python3 -m p15.wal RUN_DIR: check a run and print its record counts. Exit 0 if every
    segment is valid to its end (a torn tail is reported, and allowed) and every record passes."""
    import sys

    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python3 -m p15.wal RUN_DIR", file=sys.stderr)
        return 2
    try:
        run = read_run(Path(args[0]))
    except (HeaderError, RunError) as e:
        print(f"p15.wal: {e}", file=sys.stderr)
        return 1
    lines, problems = summary(run)
    print("\n".join(lines))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
