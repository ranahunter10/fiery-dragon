# The counters read without map syscalls (ADR-0026, 2026-11-07)

**Where:** the dev container (kernel 6.18, not the target). The VM run is pending.

**File:** [`container.txt`](container.txt): main's p15d and this branch's under `strace -e trace=bpf`, the C tests (plain, ASan/UBSan, clang), the gates, the spine self-test, the whole end-to-end test with the new case 7, and the planted-bug sweeps (p15d, the spine's EXEC program, records.c, Python).

## Results

| Claim | Grade | Where |
|---|---|---|
| main's p15d, 4 s with STATS every 200 ms: 385 `BPF_MAP_LOOKUP_BATCH` and 1 `BPF_MAP_UPDATE_ELEM` after the first event attach (each batch lookup takes `bpf_prog_active` once per element, ADR-0026 evidence 2) | MEAS | §1 |
| This branch, the same run: 0 map syscalls after the first attach; 2 updates before it (libbpf's rodata and `.bss` writes at load); 1,546 info calls after it (the skip counters, which take no `bpf_prog_active`) | MEAS | §2 |
| Every C test file 0 failures, plain, under ASan/UBSan and with clang; the gates clean | MEAS | §3–6 |
| Spine self-test passes; end-to-end test passes all cases (0 failed checks), case 7 included | MEAS | §7–8 |
| Case 7 fails ("got: 1") with the snapshot object loaded after the attach, the old order | MEAS | the sweep's mutant 9, §9 |
| p15d sweep: 28/30 killed in the full run; the other two (1 and 7) did not compile as first written (each left a parameter unused, which `-Werror` refuses), were rewritten to compile, and are killed in a rerun of those two. So 30/30, in two runs | MEAS | §9 |
| Spine EXEC sweep 14/14, records 44/44, Python 143/143; 17 Python test files 0 failed; CI lint clean | MEAS | §10–12 |

## CI (7.0.0-1017-azure, network capture on)
- The first CI run of this PR failed case 7 with "got: 1": with network capture on, the loader loaded the net object, and libbpf wrote its rodata, after the spine was attached. The dev container runs with `--no-net`, so it could not see this. Fixed in `loader.c` (every object loaded before any attach); the next CI run passes case 7 with 0 map syscalls after attach and 2,864 info calls, and the whole end-to-end test (PR #57's checks).

## Not yet
- The VM run: `it_p15d.sh` (case 7 under strace) and `mutate_p15d.py`.
