# Spine programs and self-test, dev container (2026-10-25)

**Where:** the cloud dev container (kernel 6.18.44, clang 18.1.3, root). **Not the target kernel**; the VM run is the authoritative one.

**What:** from `make clean`, at the commit that adds `bpf/progs/spine.bpf.c`, `daemon/` and the C tests ([`build-check-smoke.txt`](build-check-smoke.txt)):
- `make`: libbpf, bpftool, all BPF objects (spine included) and loaders;
- `make check`: Python and C unit tests, the schema check, the three-way layout check, evidence checksums;
- `make smoke`: the earlier smoke tests plus `p15-spine selftest`.

## Findings (MEAS, dev container)

1. **All four spine programs pass the verifier and attach on the first try:** `tp_btf/sched_process_fork`, `sched_process_exec`, `sched_process_exit` and `task_rename`. This includes the bounded copies of the EXEC filename and argv.
2. **The self-test passes all 21 checks.**
   - The test child produced exactly five records: RENAME by prctl, FORK of the grandchild, RENAME by exec, EXEC, EXIT.
   - All five carry the start time its FORK announced. The grandchild produced exactly one EXIT (status 7).
   - The EXEC argv is `true\0fd-selftest\0` (17 of 17 bytes) and the filename `/bin/true` (9 of 9).
   - Every record passed the length checks, and nothing was lost (`reserve_failed` 0 for every type).
3. The three-way layout check agrees on all five structs. The schema and the generated files are current.
