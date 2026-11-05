# Exact-size EXEC records, dev container (2026-10-25)

**Where:** the cloud dev container (kernel 6.18.44, gcc 13.3.0, clang 18.1.3, root). **Not the target**; the VM repeats it with `make check` and `sudo make smoke`.

**What:** ADR-0017 layer 1 (branch `feat/bpf-exec-exact-size`): the spine's EXEC built in per-CPU scratch and emitted with `bpf_ringbuf_output()` of exactly its `len`; the self-test checks every record's ring size; `p15_rec_check` refuses slack and non-zero bytes after EXEC's fields; `p15-spine` reads the counters after detaching and requires every type's books to close. [`run.txt`](run.txt), from a clean tree:

```bash
for c in "make clean" "make -j8" "make check" "make test-c-asan" "make CC=clang OUT=build-clang -j8 all test-c" \
         "make mutate-wal" "make mutate-py" "make smoke" "make mutate-spine"; do
  echo "\$ $c"; bash -c "$c" 2>&1 | grep -vE '^(cc|clang|gcc) |^  (CC|AR|LINK|GEN|INSTALL|MKDIR|CLANG|LD|BPF|GEN-SKEL)\b|^make\[|^mkdir|Auto-detecting|^\.\.\. |libbfd|disassembler'
  echo "[exit $?]"
done
```

## Findings (MEAS, dev container)

1. **The spine with OUTPUT-way EXEC passes the verifier and the self-test, now 22 checks,** including the new "every record takes exactly its len in the ring". After detaching, every type's counters close: `seen = emitted`, 0 reserve or build failures.
2. **The self-test is the gate for layer 1.** Built back to the maximum reservation, the spine fails exactly that check (`make mutate-spine` mutant 6; and `fixed` in the [cost run](../../probes/2026-10-25-exec-cost-container/README.md)).
3. **Mutation sweeps:** the EXEC program through the real self-test 7 of 7 (each mutant builds and loads; one equivalent left out and explained in the script); the Python gates and harnesses 34 of 34; the WAL 27 of 27.
4. All C tests pass under gcc, clang and ASan/UBSan, `-Werror`.
