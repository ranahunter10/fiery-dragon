#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""P11: can the analysis tier install its packages as binary wheels on Python 3.14?

For each package, ask PyPI's JSON API for every release and decide, with the same
tag rules pip uses (the `packaging` library), whether a wheel exists that this
interpreter can install without compiling anything. A wheel counts only if:

    it is not yanked, its filename parses, its Requires-Python admits the target
    Python, and one of its tags is in the target's supported tag set.

Every file that fails one of these checks is counted by reason, so nothing is
dropped silently. With --resolve, pip then resolves the full dependency closure
(--dry-run, binaries only) and its JSON report is saved.

Target:
    default            the running interpreter (packaging.tags.sys_tags()): run this
                       with the VM's Python 3.14 for the authoritative answer
    --python X.Y.Z     an emulated CPython X.Y.Z on manylinux x86_64 with --glibc 2.N

    python3 bench/probes/p11_wheels/wheels.py --out /var/tmp/fd-p11/run1
    python3 bench/probes/p11_wheels/wheels.py --python 3.14.4 --glibc 2.42 --out /tmp/p11 --resolve
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import platform
import subprocess
import sys
import urllib.request
from pathlib import Path

from packaging import tags as T
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import InvalidWheelFilename, parse_wheel_filename
from packaging.version import InvalidVersion, Version

# The Layer-3 analysis set from the blueprint (section 9.B, P11).
PACKAGES = ("torch", "torch-geometric", "numpy", "duckdb", "hypothesis", "atheris")
PYPI = "https://pypi.org/pypi/{}/json"
SKIP_REASONS = ("yanked", "not_wheel", "bad_filename", "requires_python", "no_matching_tag")


def emulated_tags(python: str, glibc_minor: int, arch: str = "x86_64") -> list[T.Tag]:
    """Supported tags, most preferred first, for CPython `python` (X.Y.Z) on glibc 2.`glibc_minor`."""
    major, minor = (int(p) for p in python.split(".")[:2])
    platforms = [f"manylinux_2_{m}_{arch}" for m in range(glibc_minor, 4, -1)]
    legacy = {17: "manylinux2014", 12: "manylinux2010", 5: "manylinux1"}
    platforms += [f"{legacy[m]}_{arch}" for m in (17, 12, 5) if glibc_minor >= m]
    platforms.append(f"linux_{arch}")
    abi = f"cp{major}{minor}"
    return (list(T.cpython_tags(python_version=(major, minor), abis=[abi], platforms=platforms))
            + list(T.compatible_tags(python_version=(major, minor), interpreter=abi, platforms=platforms)))


def classify_file(f: dict, rank: dict[T.Tag, int], python_version: str) -> tuple[str, int | None]:
    """Return (reason, best tag rank). reason is 'ok' or one of SKIP_REASONS."""
    if f.get("yanked"):
        return "yanked", None
    if f.get("packagetype") != "bdist_wheel":
        return "not_wheel", None
    try:
        _, _, _, wtags = parse_wheel_filename(f["filename"])
    except (InvalidWheelFilename, InvalidVersion):
        return "bad_filename", None
    req = f.get("requires_python")
    if req:
        try:
            if not SpecifierSet(req).contains(python_version, prereleases=True):
                return "requires_python", None
        except InvalidSpecifier:
            return "requires_python", None   # pip refuses an unparsable Requires-Python too
    ranks = [rank[t] for t in wtags if t in rank]
    if not ranks:
        return "no_matching_tag", None
    return "ok", min(ranks)


def assess(package: str, data: dict, tag_list: list[T.Tag], python_version: str) -> dict:
    """Verdict for one package from its PyPI JSON."""
    rank = {t: i for i, t in enumerate(tag_list)}
    latest = data["info"]["version"]
    versions = []
    for v in data.get("releases", {}):
        try:
            pv = Version(v)
        except InvalidVersion:
            continue
        if v == latest or not (pv.is_prerelease or pv.is_devrelease):
            versions.append((pv, v))
    versions.sort(reverse=True)

    out = {"package": package, "latest": latest, "last_serial": data.get("last_serial"),
           "latest_skipped": {r: 0 for r in SKIP_REASONS}, "latest_files": 0,
           "latest_best_wheel": None, "newest_installable": None, "newest_installable_wheel": None,
           "latest_has_sdist": False}
    for pv, v in versions:
        files = data["releases"][v]
        best = None
        for f in files:
            reason, r = classify_file(f, rank, python_version)
            if v == latest:
                out["latest_files"] += 1
                if f.get("packagetype") == "sdist" and not f.get("yanked"):
                    out["latest_has_sdist"] = True
                if reason != "ok":
                    out["latest_skipped"][reason] += 1
            if reason == "ok" and (best is None or r < best[0]):
                best = (r, f["filename"])
        if v == latest and best:
            out["latest_best_wheel"] = best[1]
        if best and out["newest_installable"] is None:
            out["newest_installable"], out["newest_installable_wheel"] = v, best[1]
    if out["latest_best_wheel"]:
        out["verdict"] = "binary (latest)"
    elif out["newest_installable"]:
        out["verdict"] = f"binary only up to {out['newest_installable']}"
    else:
        out["verdict"] = "no installable wheel"
    return out


def fetch(package: str) -> tuple[dict, dict]:
    with urllib.request.urlopen(PYPI.format(package), timeout=60) as r:
        raw = r.read()
    return json.loads(raw), {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def render(conds: dict, rows: list[dict]) -> str:
    out = [f"# P11 wheels: {conds['target']}", "",
           f"- UTC {conds['utc']}; checker Python {conds['checker_python']}; packaging {conds['packaging']}; "
           f"{conds['n_tags']} supported tags, most preferred `{conds['first_tag']}`", "",
           "| package | latest | verdict | best wheel for the target | files in latest: skipped by reason |",
           "|---|---|---|---|---|"]
    for r in rows:
        if "error" in r:
            out.append(f"| {r['package']} | ? | **ERROR** {r['error']} | | |")
            continue
        skipped = ", ".join(f"{k} {v}" for k, v in r["latest_skipped"].items() if v) or "none"
        wheel = r["latest_best_wheel"] or r["newest_installable_wheel"] or "none"
        out.append(f"| {r['package']} | {r['latest']} | {r['verdict']} | `{wheel}` | "
                   f"{r['latest_files']} files; {skipped} |")
    return "\n".join(out) + "\n"


MIN_PIP_FOR_RESOLVE = 25   # pip 24.0 downloaded the whole 555 MB torch wheel for a dry run; 26.2 read metadata only


def pip_major() -> tuple[int, str]:
    v = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True, text=True).stdout.split()
    return (int(v[1].split(".")[0]), v[1]) if len(v) > 1 else (0, "missing")


def resolve(args, out: Path) -> dict:
    """pip's own answer for the whole dependency closure: dry run, binaries only."""
    cmd = [sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--only-binary=:all:",
           "--quiet", "--report", str(out / "resolve.json")]
    for url in args.extra_index_url:
        cmd += ["--extra-index-url", url]
    if args.python:
        cmd += ["--target", str(out / "never-written"), "--python-version", args.python,
                "--implementation", "cp", "--abi", "cp" + "".join(args.python.split(".")[:2])]
        for t in sorted({t.platform for t in emulated_tags(args.python, args.glibc) if t.platform != "any"}):
            cmd += ["--platform", t]
    cmd += list(args.packages)
    p = subprocess.run(cmd, capture_output=True, text=True)
    (out / "resolve.log").write_text(" ".join(cmd) + "\n\n" + p.stdout + p.stderr)
    res = {"exit_code": p.returncode, "installs": None, "pip": pip_major()[1],
           "extra_index_urls": list(args.extra_index_url)}
    if p.returncode == 0:
        rep = json.loads((out / "resolve.json").read_text())
        res["installs"] = sorted(f"{i['metadata']['name']}=={i['metadata']['version']}" for i in rep["install"])
    return res


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("packages", nargs="*", default=list(PACKAGES))
    ap.add_argument("--python", help="emulate CPython X.Y.Z instead of using the running interpreter")
    ap.add_argument("--glibc", type=int, default=None, help="glibc minor version for --python (e.g. 42 for 2.42)")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--resolve", action="store_true", help="also run pip's dry-run resolver over the closure")
    ap.add_argument("--extra-index-url", action="append", default=[],
                    help="extra index for --resolve only, e.g. https://download.pytorch.org/whl/cpu")
    args = ap.parse_args(argv)
    if args.python and args.glibc is None:
        ap.error("--python needs --glibc")
    if args.extra_index_url and not args.resolve:
        ap.error("--extra-index-url only affects --resolve; the per-package check reads PyPI")
    if args.resolve and pip_major()[0] < MIN_PIP_FOR_RESOLVE:
        ap.error(f"--resolve needs pip >= {MIN_PIP_FOR_RESOLVE} (found {pip_major()[1]}): older pip may download "
                 "every wheel in full, e.g. 555 MB for torch. Upgrade pip in a venv first (see README)")
    if args.python and len(args.python.split(".")) != 3:
        ap.error("--python must be X.Y.Z, e.g. 3.14.4 (Requires-Python checks need the full version)")

    import packaging
    if args.python:
        tag_list, pyver = emulated_tags(args.python, args.glibc), args.python
        target = f"emulated CPython {args.python}, glibc 2.{args.glibc}, x86_64"
    else:
        tag_list, pyver = list(T.sys_tags()), platform.python_version()
        target = f"this interpreter: CPython {pyver} {platform.machine()} glibc {'.'.join(platform.libc_ver()[1:])}"
    args.out.mkdir(parents=True, exist_ok=False)
    conds = {"utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "target": target,
             "target_python": pyver, "checker_python": platform.python_version(), "packaging": packaging.__version__,
             "n_tags": len(tag_list), "first_tag": str(tag_list[0]), "packages": list(args.packages), "pypi": {}}
    rows = []
    for pkg in args.packages:
        try:
            data, meta = fetch(pkg)
        except Exception as e:  # recorded as a row and in the exit code, never dropped
            rows.append({"package": pkg, "error": f"{type(e).__name__}: {e}"})
            continue
        conds["pypi"][pkg] = meta | {"last_serial": data.get("last_serial")}
        rows.append(assess(pkg, data, tag_list, pyver))
    if args.resolve:
        conds["resolve"] = resolve(args, args.out)
    (args.out / "conditions.json").write_text(json.dumps(conds, indent=2) + "\n")
    (args.out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    report = render(conds, rows)
    if args.resolve:
        r = conds["resolve"]
        idx = "PyPI" + "".join(f" + {u}" for u in r["extra_index_urls"])
        if r["installs"] is None:
            body = "no resolution, see resolve.log"
        else:
            gpu = [i for i in r["installs"] if i.lower().startswith(("nvidia-", "cuda-", "triton"))]
            body = (f"{len(r['installs'])} distributions, {len(gpu)} of them GPU runtime (nvidia-*, cuda-*, triton): "
                    + ", ".join(r["installs"]))
        report += f"\npip {r['pip']} resolver (dry run, binaries only, {idx}): exit {r['exit_code']}; {body}\n"
    (args.out / "index.md").write_text(report)
    print(report)
    failed = any("error" in r for r in rows) or (args.resolve and conds["resolve"]["exit_code"] != 0)
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
