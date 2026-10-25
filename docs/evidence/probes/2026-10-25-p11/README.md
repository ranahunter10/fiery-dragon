# P11: analysis-tier wheels on the VM's Python 3.14 (2026-10-25)

**What:** `bench/probes/p11_wheels/wheels.py --resolve`, at commit `3b06193`, run twice:
1. against PyPI only;
2. with PyTorch's CPU-only index added (`--extra-index-url https://download.pytorch.org/whl/cpu`).

**Conditions:**
- VM `p15-dev-2604`, run 2026-10-25 01:12 UTC.
- **Target:** this interpreter, CPython 3.14.4 x86_64, glibc 2.43 (`ldd` printed `Ubuntu GLIBC 2.43-2ubuntu2.4`). That gives 1,350 supported wheel tags, most preferred `cp314-cp314-linux_x86_64`.
- The checker ran in a throwaway venv (`/var/tmp/fd-p11-venv`) with pip 26.2.2 and packaging 26.3. The system Python was not changed.
- PyPI state is pinned in each `conditions.json` by every package's `last_serial` and the sha256 of its JSON response.

**Integrity:**
- From the same `probes.tgz` as P6/P8: sha256 `0423aa06…33c2`, printed on the VM and matched on receipt.
- Files are copied byte for byte (`SHA256SUMS`). The `resolve.json` files are pip's own installation reports.

## Findings (MEAS)

1. **Every package's latest release ships a wheel this interpreter can install:**

   | Package | Latest | Wheel |
   |---|---|---|
   | torch | 2.14.1 | `cp314-cp314-manylinux_2_28` |
   | torch-geometric | 2.8.1 | `py3-none-any` |
   | numpy | 2.5.4 | `cp314`, manylinux_2_27/2_28 |
   | duckdb | 2.0.0 | `cp312-abi3`, the stable ABI |
   | hypothesis | 6.170.9 | `cp314`, manylinux2014 |
   | atheris | 3.1.0 | `cp314`, manylinux2014 |

2. **The whole dependency closure resolves with binaries only** (pip dry run, exit 0, both runs):
   - **PyPI only:** 52 distributions. **19 of them are GPU runtime** (`nvidia-*`, `cuda-*`, `triton`), which the VM has no use for.
   - **With the CPU index:** 33 distributions, **no GPU runtime**. Torch resolves to `2.14.1+cpu` from `download-r2.pytorch.org`. Everything else comes from PyPI, and the versions match the PyPI-only run.
3. **Answer to the blueprint question Q-D3 (Python 3.14 or a separate 3.12 venv):** nothing in the analysis set needs 3.12 or a compiler on 3.14. Which Python to use is still the maintainer's decision; see `docs/STATE.md`.

**Not established here:**
- Whether the packages *import and work* on 3.14. This is a resolver and metadata result, not an install-and-run test. The first Phase-1 analysis code settles that.
- PyG's optional compiled extensions (`pyg-lib`, `torch-scatter`, `torch-sparse`), which live on `data.pyg.org` and were not checked.
