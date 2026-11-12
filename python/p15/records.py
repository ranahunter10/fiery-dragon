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
FF_KNOWN = 0
for _n in dir(gen):
    if _n.startswith("FF_"):
        FF_KNOWN |= getattr(gen, _n)
OBJ_SUBVOL_UNKNOWN = 1                 # OBJFACTS oflags bit 0 (schema/records.toml)
# fflags each record may carry (schema/records.toml docs), and which part each OBJ_NEW-like flag announces
_FFLAGS_OK = {
    "OPEN": gen.FF_OBJ_NEW | gen.FF_PATH_MISSING | gen.FF_PATH_WALKED | gen.FF_PATH_RACED | gen.FF_PATH_ERROR |
    gen.FF_FULL_SIZE | gen.FF_KTHREAD,
    "OPEN_VERDICT": gen.FF_KTHREAD,
    "BACKING": gen.FF_OBJ_NEW | gen.FF_USER_OBJ_NEW | gen.FF_KTHREAD,
    "CLOSE": gen.FF_NEVER_OPENED | gen.FF_KTHREAD,
    "FD": gen.FF_PATH_ERROR,
    "FILE": gen.FF_OBJ_NEW,
    "FLOW": gen.FF_OBJ_NEW | gen.FF_UNREGISTERED | gen.FF_PEEK | gen.FF_VECTORED | gen.FF_START_UNKNOWN,
}
_PART_FLAG = {("OPEN", "facts"): gen.FF_OBJ_NEW, ("BACKING", "facts"): gen.FF_OBJ_NEW,
              ("BACKING", "user_facts"): gen.FF_USER_OBJ_NEW, ("FILE", "facts"): gen.FF_OBJ_NEW,
              ("FLOW", "facts"): gen.FF_OBJ_NEW}
_VFS_KINDS = (gen.FLOW_KIND_READ, gen.FLOW_KIND_WRITE)
# the records whose padding p15_rec_check also requires to be zero (records.c check_pad): every
# record since FLOW and FILE; the older ones are not checked (decision waiting, STATE)
_PAD_ZERO = ("FILE", "FLOW")


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
    if lay.name == "SNAP_DONE" and f.get("fd_pass", 0) > 1:
        raise RecordError("SNAP_DONE: fd_pass is neither 0 nor 1", off)
    if lay.name in _FFLAGS_OK:
        if f["fflags"] & ~_FFLAGS_OK[lay.name]:
            raise RecordError(f"{lay.name}: fflags bits this record never carries", off)
        if f.get("reserved", 0):
            raise RecordError(f"{lay.name}: non-zero reserved", off)
        if lay.name in ("OPEN", "FD") and bool(f["fflags"] & gen.FF_PATH_ERROR) != bool(f["path_err"]):
            raise RecordError(f"{lay.name}: path_err without PATH_ERROR, or PATH_ERROR without path_err", off)
        _ret = gen.FF_PATH_MISSING | gen.FF_PATH_WALKED   # written by the session's return (ADR-0029)
        if lay.name == "OPEN" and ((f["fflags"] & _ret) == _ret or
                                   (f["fflags"] & gen.FF_PATH_RACED and not f["fflags"] & gen.FF_PATH_WALKED)):
            raise RecordError("OPEN: PATH_WALKED with PATH_MISSING, or PATH_RACED without PATH_WALKED", off)
        if lay.name == "OPEN" and f["fflags"] & gen.FF_PATH_WALKED and f["fflags"] & (gen.FF_PATH_ERROR | gen.FF_FULL_SIZE):
            raise RecordError("OPEN: a walked path with PATH_ERROR or FULL_SIZE (those are the fentry's)", off)
        if lay.name == "OPEN" and not f["fflags"] & _ret and f["verdict"]:
            raise RecordError("OPEN: a verdict on an OPEN the fentry wrote (a denial is OPEN_VERDICT)", off)
        if lay.name == "OPEN_VERDICT" and f["verdict"] >= 0:
            raise RecordError("OPEN_VERDICT: the verdict is not a denial", off)
        if lay.name == "FILE" and f["seen"] not in (3, 4, 5):
            raise RecordError("FILE: unknown 'seen'", off)
        if lay.name == "FILE" and (bool(h["flags"] & F_TRUNCATED) != (f["name_full"] != f["name_len"]) or
                                   f["name_full"] < f["name_len"]):
            raise RecordError("FILE: name_full differs from name_len without TRUNCATED, or the reverse", off)
        if lay.name == "FLOW":
            _flow_check(f, off)
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
        # slack after the fields only on a BPF-built record whose read failed (records.c check_tail),
        # and on an OPEN reserved at full size because no path scratch slot was free (zero slack)
        slack_ok = (lay.cls == "SPINE" and bool(h["flags"] & F_READ_FAILED)) or \
            (lay.name == "OPEN" and bool(f["fflags"] & gen.FF_FULL_SIZE) and n == lay.max_size)
        if n != (lay.fixed_size + used + 7) & ~7 and not slack_ok:
            raise RecordError("len larger than its fields need", off)
        parts = dict(lay.parts)
        p = off + lay.fixed_size
        for vname, _ in lay.var:
            vl = f[f"{vname}_len"]
            if vname in parts:
                var[vname] = _part(buf, p, vl, parts[vname], lay.name, vname, f, off)
            else:
                var[vname] = bytes(buf[p:p + vl])
            p += vl
        if any(bytes(buf[p:off + n])):
            raise RecordError("non-zero bytes after the variable fields", off)
        if lay.name in _PAD_ZERO and "_pad" in lay.dtype.names:
            dt, o = lay.dtype.fields["_pad"][:2]
            if any(bytes(buf[off + o:off + o + dt.itemsize])):
                raise RecordError(f"{lay.name}: non-zero padding", off)
    elif n != lay.fixed_size:
        raise RecordError("len differs from the fixed size", off)
    return Record(ring, seq, lay.name, h, f, var)


def _flow_check(f: dict, off: int) -> None:
    """FLOW's own rules (ADR-0005 rules 2, 7, 8; schema/records.toml), as records.c check_flow."""
    ff, kind = f["fflags"], f["kind"]
    if kind not in gen.FLOW_KIND or f["reason"] not in gen.FLOW_REASON:
        raise RecordError("FLOW: unknown kind or reason", off)
    if f["count"] < 1 or f["bytes"] < f["count"] or (f["reason"] == gen.FLOW_REASON_SINGLE and f["count"] != 1):
        raise RecordError("FLOW: count 0, fewer bytes than events, or a SINGLE of count other than 1", off)
    if (ff & gen.FF_PEEK and kind != gen.FLOW_KIND_RECV) or \
            (ff & (gen.FF_VECTORED | gen.FF_START_UNKNOWN) and kind not in _VFS_KINDS):
        raise RecordError("FLOW: PEEK on a kind other than RECV, or VECTORED/START_UNKNOWN on a socket kind", off)
    if ff & gen.FF_OBJ_NEW and not ff & gen.FF_UNREGISTERED:
        raise RecordError("FLOW: facts on a registered open file (they travel in OPEN, FILE or FD)", off)
    if bool(ff & gen.FF_UNREGISTERED) != (f["reason"] == gen.FLOW_REASON_MAP_FULL) and \
            f["reason"] != gen.FLOW_REASON_SINGLE:
        raise RecordError("FLOW: UNREGISTERED without reason MAP_FULL, or MAP_FULL without UNREGISTERED", off)


def _part(buf, p: int, vl: int, pname: str, rname: str, vname: str, f: dict, off: int) -> dict | None:
    """A part field (schema [[part]]): absent, or the whole struct. Its presence must match the flag
    that announces it (OBJ_NEW for an OPEN's facts, ...); FD always carries its facts."""
    dt = gen.PARTS[pname]
    if vl not in (0, dt.itemsize) or f[f"{vname}_full"] != vl:
        raise RecordError(f"{rname}: {vname} is neither absent nor a whole {pname}", off)
    flag = _PART_FLAG.get((rname, vname))
    want = bool(f["fflags"] & flag) if flag is not None else True
    if bool(vl) != want:
        raise RecordError(f"{rname}: {vname} present without its flag, or its flag without it", off)
    if not vl:
        return None
    row = np.frombuffer(buf, dt, count=1, offset=p)[0]
    out = {k: int(row[k]) for k in dt.names}
    if pname == "OBJFACTS" and (out["oflags"] & ~OBJ_SUBVOL_UNKNOWN or out["seen"] not in (1, 2, 3, 4, 5)):
        raise RecordError("OBJFACTS: unknown oflags bits or an unknown 'seen'", off)
    return out


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
