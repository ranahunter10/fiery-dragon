# SPDX-License-Identifier: MIT
"""The ADR-0008 records, decoded from the generated layouts (schema/generated/p15_records.py).

Every layout comes from the generated module: nothing here repeats a field name, size or offset.
Decoding checks each record the way the daemon's p15_rec_check does (daemon/records.c), and
refuses it otherwise. There are no defaults: an unknown (type, version), or a field that isn't
in the layout, is an error, never a zero (ADR-0008 rule 5, blueprint L7).
"""

from __future__ import annotations

import importlib.util
import socket
import sys
from pathlib import Path

import numpy as np

_GEN = Path(__file__).resolve().parents[2] / "schema" / "generated" / "p15_records.py"


def _load_generated():
    spec = importlib.util.spec_from_file_location("p15_records", _GEN)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load the generated layouts from {_GEN}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("p15_records", mod)
    spec.loader.exec_module(mod)
    return mod


gen = _load_generated()
HEADER_SIZE = gen.HEADER_SIZE
SCHEMA_HASH = gen.SCHEMA_HASH
TYPES = dict(gen.TYPES)
F_TRUNCATED = gen.F_TRUNCATED
F_READ_FAILED = gen.F_READ_FAILED
F_ISN = gen.F_ISN
F_KNOWN = F_TRUNCATED | F_READ_FAILED | F_ISN

NET_OPS = {1: "CONNECT", 2: "ACCEPT", 3: "LISTEN", 4: "BIND"}
RUN_STATES = {0: "RUNNING", 1: "DEGRADED", 2: "INVALID"}
INVARIANT = {0: "not checked", 1: "closed", 2: "broken"}
SNAP_KINDS = {1: "opening", 2: "closing"}
PROC_KTHREAD, PROC_EXITING = 1, 2      # PROC pflags (bpf/include/p15_snap.h)


class RecordError(ValueError):
    """A record that p15_rec_check would refuse. `why` uses the daemon's wording."""

    def __init__(self, why: str, offset: int):
        super().__init__(f"record at payload offset {offset}: {why}")
        self.why = why
        self.offset = offset


class Record:
    """One decoded record. `h` is the common header and `f` the type's fields, both plain dicts
    of Python ints and bytes; `var` holds the variable-length fields (bytes, as copied).
    A missing key raises KeyError: there is no default for any field."""

    __slots__ = ("ring", "seq", "name", "h", "f", "var")

    def __init__(self, ring: int, seq: int, name: str, h: dict, f: dict, var: dict):
        self.ring, self.seq, self.name, self.h, self.f, self.var = ring, seq, name, h, f, var

    @property
    def proc(self) -> tuple[int, int]:
        """The ADR-0009 process key within a run: (tgid, start_ns); boot_id is the run's."""
        return (self.h["tgid"], self.h["start_ns"])

    def __repr__(self) -> str:
        return f"Record({self.name} ring={self.ring} seq={self.seq} ts={self.h['ts_ns']} proc={self.proc})"


def decode(buf, off: int, ring: int, seq: int) -> Record:
    """Decode the record that starts at buf[off:]; buf is the batch payload. Never reads past
    the record's len or past buf (ADR-0008 rule 5)."""
    size = len(buf) - off
    if size < HEADER_SIZE:
        raise RecordError("shorter than the header", off)
    hv = gen.HEADER_DTYPE  # the header first, with its own dtype: len may be bad
    h = {k: int(v) for k, v in zip(hv.names, np.frombuffer(buf, hv, count=1, offset=off)[0].tolist())}
    n = h["len"]
    if n > size:
        raise RecordError("len beyond the bytes received", off)
    if n % 8:
        raise RecordError("len not a multiple of 8", off)
    lay = gen.RECORDS.get((h["type"], h["version"]))
    if lay is None:
        raise RecordError("unknown type or version", off)
    if n < lay.fixed_size:
        raise RecordError("len shorter than the fixed part", off)
    if h["flags"] & ~F_KNOWN:
        raise RecordError("unknown flag bits", off)
    if h["flags"] & F_ISN and not (lay.name == "NET" and h["version"] >= 2):
        raise RecordError("ISN flag on a record that has no ISN", off)
    row = np.frombuffer(buf, lay.dtype, count=1, offset=off)[0]
    f = {}
    for name in lay.dtype.names:
        if name in ("h", "_pad"):
            continue
        dt, o = lay.dtype.fields[name][:2]
        # char[N]: the exact N bytes (numpy's S dtype would drop trailing NULs, e.g. of 10.0.0.0)
        f[name] = bytes(buf[off + o:off + o + dt.itemsize]) if dt.kind == "S" else int(row[name])
    if lay.name == "NET" and h["version"] >= 2 and (f["reserved"] or (not h["flags"] & F_ISN and f["tcp_isn"])):
        # every byte has one meaning (records.c): the alignment field is zero, and so is an ISN nobody read
        raise RecordError("NET v2: non-zero reserved, or tcp_isn without P15_F_ISN", off)
    if lay.name == "END" and h["version"] >= 2 and f["reserved"]:
        raise RecordError("END v2: non-zero reserved", off)
    if lay.name == "PROC" and (f["reserved"] or f["kind"] not in (1, 2) or f["pflags"] & ~3):
        raise RecordError("PROC: non-zero reserved, unknown kind or unknown pflags", off)
    if lay.name == "SNAP_DONE" and f["kind"] not in (1, 2):
        raise RecordError("SNAP_DONE: unknown kind", off)
    var = {}
    if lay.var:
        used = 0
        for vname, vmax in lay.var:
            vl = f[f"{vname}_len"]
            if vl > vmax:
                raise RecordError("variable field beyond len", off)
            used += vl
        if lay.fixed_size + used > n:
            raise RecordError("variable field beyond len", off)
        # slack after the fields only on a BPF-built record whose read failed (records.c check_tail)
        slack_ok = lay.cls == "SPINE" and bool(h["flags"] & F_READ_FAILED)
        if n != (lay.fixed_size + used + 7) & ~7 and not slack_ok:
            raise RecordError("len larger than its fields need", off)
        p = off + lay.fixed_size
        for vname, _ in lay.var:
            vl = f[f"{vname}_len"]
            var[vname] = bytes(buf[p:p + vl])
            p += vl
        if any(bytes(buf[p:off + n])):
            raise RecordError("non-zero bytes after the variable fields", off)
    elif n != lay.fixed_size:
        raise RecordError("len differs from the fixed size", off)
    return Record(ring, seq, lay.name, h, f, var)


# ---- helpers for fields whose encoding is the kernel's ----

def kdev(kernel_dev: int) -> tuple[int, int]:
    """The kernel's internal dev_t (s_dev: major << 20 | minor, include/linux/kdev_t.h MINORBITS
    20) as (major, minor). It is not st_dev: os.makedev(major, minor) gives that."""
    return (kernel_dev >> 20, kernel_dev & ((1 << 20) - 1))


def net_addr(rec: Record, which: str) -> str:
    """laddr or raddr of a NET record as text: a.b.c.d, or the IPv6 form."""
    raw = rec.f[which]
    fam = rec.f["family"]
    if fam == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, raw[:4])
    if fam == socket.AF_INET6:
        return socket.inet_ntop(socket.AF_INET6, raw)
    raise RecordError(f"NET family {fam} is neither AF_INET nor AF_INET6", -1)


def endpoint(rec: Record, which: str) -> str:
    """'addr:port' (IPv6 in brackets) for which = 'l' (local) or 'r' (remote)."""
    a = net_addr(rec, which + "addr")
    port = rec.f[which + "port"]
    return f"[{a}]:{port}" if rec.f["family"] == socket.AF_INET6 else f"{a}:{port}"


def comm(raw: bytes) -> str:
    """A kernel comm (char[16]) as text."""
    return raw.split(b"\0", 1)[0].decode("utf-8", "backslashreplace")


def argv(rec: Record) -> list[str]:
    """An EXEC or PROC record's argv, split at NULs."""
    a = rec.var["argv"]
    if a.endswith(b"\0"):
        a = a[:-1]
    return [x.decode("utf-8", "backslashreplace") for x in a.split(b"\0")] if a else []
