# Small phase-0 probes

Each probe answers one question from the blueprint's probe table (§9.B) with a harness, raw output and a test suite.

| Probe | Question | Decides |
|---|---|---|
| [P6](p6_argv/README.md) | Read argv at syscall entry or at `sched_process_exec`? | spine exec design |
| [P8](p8_compat/README.md) | Do the hooks see compat (32-bit ABI) I/O and exec, and how are compat syscall ids reported? | compat row |
| P11 (separate PR) | Do the analysis packages install as binary wheels on Python 3.14? | Q-D3 |

**Not here:**
- **P7** (connect/accept hook layer) and **P9** (io_uring completion path) are covered by census v2 (E-0027 io_uring, E-0032 connect/accept).

**Shared plumbing:** [`probelib.py`](probelib.py) handles build, attach-and-wait, run as the sudo user, clean stop, and conditions.

**Running the tests:** each probe's tests run on their own, because both `run.py` modules share a name:

```bash
python3 -m unittest -v bench/probes/p6_argv/test_run.py
python3 -m unittest -v bench/probes/p8_compat/test_run.py
```
