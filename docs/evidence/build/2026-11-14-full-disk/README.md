# F-02, the WAL's free-space guard: container evidence (2026-11-14)

Dev container, kernel 6.18 (spine only: the file, flow and NET programs do not load here), 2 vCPU; `env.txt` has the kernel, the compiler and the commit the runs were made on (the commit before this README, amended into the delivered one). Design: `docs/research/2026-11-14-full-disk.md`. Journal: E-0312.

| File | Command | Result |
|---|---|---|
| `test-c.txt` | `make test-c` | all unit tests pass (test_space, test_wal's three new cases) |
| `it_p15d.txt` | `P15_IT_PID1=0 daemon/tests/it_p15d.sh build` | PASS, 0 failed checks; case 28 levels 2,3,1, 1,216 spine records shed (304 FORK, 304 EXIT), tree check `repaired`; case 29 a real ENOSPC survived |
| `mutants-109-121.txt` | `daemon/tests/mutate_p15d.py 109..121` | 11 of 13 killed, 110 and 111 NO BUILD (the mutant left a variable unused under -Werror) |
| `mutants-110-111-rerun.txt` | the same, 110 and 111 rewritten to drop the hysteresis margin | 2 of 2 killed |
| `py-mutants-191-192.txt` | `tools/ci/mutate_py.py 191 192` (reconcile adds the shed FORKs, EXITs) | 2 of 2 killed (192 survived until the EXIT test was added) |
| `mutate-records.txt` | `make mutate-records` | 120 of 120 killed (72, 73, 75 survived before test_records checked an unknown version per type) |

Mutant 122 (writer.c, shed FORKs uncounted) was killed by it_p15d's tree check in 118 s (this session's output: `killed 122 writer.c forks += h->type == P15_T_FORK;`).

Not run here: the VM. V-2 of the design review is expected to end with exit 3 (DEGRADED), not 4. `make hardening-check` reports "missing cet" for p15d and p15-spine in this container (Ubuntu 24.04's toolchain; a linked static library lacks the CET note); no build flag changed here; the VM run checks it.
