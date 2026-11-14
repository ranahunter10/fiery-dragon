# The integrated tree on the VM, 2026-11-14

Run by the maintainer on `p15-dev` (7.0.0-38-generic, 3 vCPU) with Dragon's VM test package (`vm_test.sh`). The tree is the local branch `vm/integration` at bb48c37, tree b2b99ec0. That branch is not for merging: it merges everything not yet on main, for this one test run:

- PR #90's head (13c46f8);
- #91;
- `net/socket-join`;
- PR #95 with its follow-up;
- Dragon's open-path, canary and file-map branches;
- `bench/flow-cost-witness` and `bench/soak-flow-stats`.

What each file is:

| File | What it holds |
|---|---|
| `run/setup.txt`, `run/submodules.txt` | the checkout, its tree checked, the submodules |
| `run/build.txt`, `run/test-c.txt`, `run/test-python.txt` | the build and the unit tests (C, and the 29 Python test files run with the venv's Python) |
| `run/it_p15d.txt` | the end-to-end test, every case, with `P15_IT_NET=1` |
| `run/canary_run.txt`, `run/canary_selfstats.txt` | 10 s with `--flow --canary-s 1`, and its SELF_STATS lines |
| `run/demo_*.txt` | the demo captured with `--flow`, its graph, and tracking from the injected `nc` |
| `run/mutants.txt` | the planted bugs only 7.0 can judge: 77, 80, 86 to 89, 108 |
| `run/matrix.txt`, `matrix/` | `tools/vm/measure_capture.sh --quick -- --flow`, every step's raw output (perf data left out: 9.4 MB) |
| `run/verdicts.txt`, `run/manifest.txt` | one line per step; the commit and kernel |

The results (E-0310):

- **End-to-end test:** PASS, 0 failed checks, no case skipped. All 27 cases ran, including cases 16 to 19 and 27 on 7.0.
- **Canary with `--flow`:** 9 canaries in 10 s, none missed, none late, want 0x7f (every bit). 23 links, 230 checks, none gone. The run ended `exit 0, state 0, invariant 1`.
- **Planted bugs:** 7 of 7 killed.
- **Matrix:** all 12 steps rc=0, and **no host stall** in the window, so its rates are quotable within the quick form's three rounds. The soak's recall is 100 % on every step kind, and every dropper chain, socket pair and memfd exec is in its graph.
- **Demo:** backward from the injected `nc`: curl → socket 8080 → webapp.py → sh → nc. Forward: nc → socket 4444 → `nc -l`.

`SHA256SUMS` covers every file here.
