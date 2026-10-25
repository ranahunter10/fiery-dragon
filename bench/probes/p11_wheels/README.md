# P11: binary wheels for the analysis tier on Python 3.14

**Question (blueprint §9.B, decision Q-D3):** can the analysis tier run on the VM's own Python 3.14, or does it need a separate 3.12 virtual environment? That depends on whether every package it needs, and every dependency of those, installs from a prebuilt wheel. Nothing should need compiling.

**Packages checked:** `torch`, `torch-geometric`, `numpy`, `duckdb`, `hypothesis`, `atheris` (the blueprint list).

## What [`wheels.py`](wheels.py) does

1. **Per package (PyPI JSON API):** it applies pip's own tag rules from the `packaging` library to every release. A wheel counts only if all of these hold:
   - it is not yanked;
   - its filename parses;
   - its `Requires-Python` admits the target Python;
   - one of its tags is in the target's supported set.

   Every file that fails a check is counted by reason, so nothing is dropped silently. The size and sha256 of each JSON response, and PyPI's `last_serial` for the package, are recorded in `conditions.json` to pin the index state.
2. **`--resolve`:** pip itself resolves the whole dependency closure with `install --dry-run --only-binary=:all: --report`. The JSON report is saved as `resolve.json`.
   - **Needs pip ≥ 25.** In the dev container, pip 24.0 downloaded the full 555 MB torch wheel for a dry run, while pip 26.2.2 read only the metadata (12 MB of cache). The script refuses older pip rather than downloading gigabytes.

**Target:**
- **Default:** the interpreter running the script. Run it with the VM's Python 3.14 for the authoritative answer.
- **`--python 3.14.4 --glibc N`:** emulates the target from any machine. This is a preview only, because the VM's glibc version is not yet recorded.

## Run on the VM

Run this after any measurement, since it uses the network and CPU. pip is upgraded **inside a throwaway venv only**; the system Python is untouched.

```bash
cd ~/fiery-dragon && git fetch -q && git checkout -q bench/probe-p11-wheels && git pull -q
python3 -m venv /var/tmp/fd-p11-venv && /var/tmp/fd-p11-venv/bin/pip install -q -U pip packaging
ts=$(date -u +%Y%m%dT%H%M%SZ); ldd --version | head -1
/var/tmp/fd-p11-venv/bin/python bench/probes/p11_wheels/wheels.py --resolve --out /var/tmp/fd-p11/$ts-pypi
/var/tmp/fd-p11-venv/bin/python bench/probes/p11_wheels/wheels.py --resolve \
    --extra-index-url https://download.pytorch.org/whl/cpu --out /var/tmp/fd-p11/$ts-cpu
tar czf ~/p11.tgz -C /var/tmp fd-p11 && sha256sum ~/p11.tgz
```

The second run adds PyTorch's CPU-only index. The VM has no GPU, and a plain PyPI resolve of torch pulls the CUDA runtime packages.

**Exit codes:**
- 0: every package was checked and, with `--resolve`, the closure resolved;
- 2: a fetch failed or pip could not resolve, and the table shows which.

## Tests

```bash
python3 -m unittest -v bench/probes/p11_wheels/test_wheels.py      # 12 tests, no network
```

Mutation check: 9 deliberate bugs, all caught. The bugs were:
- skip yanked;
- skip `Requires-Python`;
- wrong version order;
- first match instead of best tag;
- pre-releases counted;
- glibc bound off by one;
- errors not failing the exit code;
- the old-pip guard removed;
- skip reasons not counted.
