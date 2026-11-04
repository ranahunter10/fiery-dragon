# SPDX-License-Identifier: MIT
"""Test helper: build P15W segments and ADR-0008 records in memory, with every field open to
being broken on purpose. Tests only: the real writer is daemon/wal.c, and it_wal_c.py checks the
reader against it."""

import struct
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from p15 import records as R  # noqa: E402
from p15 import wal as W  # noqa: E402

BASE_META = {"run.id": "r1", "boot_id": "b1", "schema.hash": R.SCHEMA_HASH}


def rec(name: str, var: dict | None = None, length: int | None = None, version: int | None = None,
        **fields) -> bytes:
    """One record of type `name` (its latest version unless given): header fields as h_<name>,
    others by name, var tails in order."""
    t = R.TYPES[name]
    v = version or max(ver for (tt, ver) in R.gen.RECORDS if tt == t)
    lay = R.gen.RECORDS[(t, v)]
    a = np.zeros(1, lay.dtype)
    a["h"]["type"] = t
    a["h"]["version"] = v
    for k, v in fields.items():
        if k.startswith("h_"):
            a["h"][k[2:]] = v
        else:
            a[k] = v
    tail = b""
    for vname, _ in lay.var:
        b = (var or {}).get(vname, b"")
        if f"{vname}_len" not in fields:
            a[f"{vname}_len"] = len(b)
            a[f"{vname}_full"] = len(b)
        tail += b
    body = a.tobytes()[:lay.fixed_size] + tail
    body += b"\0" * (-len(body) % 8)
    n = len(body) if length is None else length
    if "h_len" not in fields:
        body = body[:4] + struct.pack("<H", n) + body[6:]
    return body.ljust(n, b"\0") if length and length > len(body) else body


def batch(ring: int, first_seq: int, recs: list[bytes], *, count=None, magic=W.BATCH_MAGIC, flags=0,
          rsv=0, bad_hcrc=False, bad_pcrc=False, plen=None) -> bytes:
    payload = b"".join(recs)
    n = len(recs) if count is None else count
    pl = len(payload) if plen is None else plen
    pcrc = W.crc32c(payload) ^ (1 if bad_pcrc else 0)
    head32 = struct.pack("<4sHHIIQII", magic, ring, flags, n, pl, first_seq, pcrc, rsv)
    hcrc = W.crc32c(head32) ^ (1 if bad_hcrc else 0)
    return head32 + struct.pack("<II", hcrc, 0) + payload


def header(index: int, meta: dict[str, str], *, magic=W.SEG_MAGIC, major=1, minor=0, bo=W.BYTE_ORDER,
           rsv=0, bad_crc=False, raw_entries: bytes | None = None, extra_len=0, count=None) -> bytes:
    ent = b""
    if raw_entries is None:
        for k, v in meta.items():
            kb, vb = k.encode(), v.encode()
            e = struct.pack("<HHI", len(kb), 0, len(vb)) + kb + vb
            ent += e + b"\0" * (-len(e) % 8)
    else:
        ent = raw_entries
    hlen = 32 + len(ent) + extra_len
    body = ent + b"\0" * extra_len
    pre = struct.pack("<4sHHIIIIII", magic, major, minor, bo, hlen, 0, index, len(meta) if count is None else count, rsv)
    crc = W.crc32c(pre + body) ^ (1 if bad_crc else 0)
    return pre[:16] + struct.pack("<I", crc) + pre[20:] + body


def meta_for(seq_next=(0, 0, 0), **extra) -> dict[str, str]:
    m = dict(BASE_META)
    for r, n in zip(W.RINGS, seq_next):
        m[f"seq.next.{r}"] = str(n)
    m.update(extra)
    return m


def write_run(d: Path, segments: list[bytes]) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    for i, s in enumerate(segments):
        (d / f"seg-{i:08d}.p15w").write_bytes(s)
    return d
