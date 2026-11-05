# Daemon hardening and error discipline, dev container (2026-10-25)

**Where:** the cloud dev container (kernel 6.18.44, gcc 13.3.0, clang 18.1.3, root). **Not the target.** Nothing in this change touches the kernel side; the target VM repeats it with `make check` and `sudo make smoke`.

**What:** ADR-0019 G2 and G3 turned on for the existing daemon code (branch `chore/daemon-hardening`). [`run.txt`](run.txt) is the output of, from a clean tree:

```bash
for c in "make clean" "make -j8" "make check" "make test-c-asan" \
         "make CC=clang OUT=build-clang -j8 all test-c" "make mutate-wal" "make mutate-checks" "make smoke"; do
  echo "\$ $c"; bash -c "$c" 2>&1 | grep -vE '^(cc|clang|gcc) |^  (CC|AR|LINK|GEN|INSTALL|MKDIR|CLANG|LD|BPF|GEN-SKEL)\b|^make\[|^mkdir|Auto-detecting|^\.\.\. |libbfd|disassembler'
  echo "[exit $?]"
done
```

The filter drops compiler command lines and the libbpf/bpftool build chatter only; every test, check and sweep line is kept. `[exit N]` is the pipeline's status under `pipefail`.

## Findings (MEAS, dev container)

1. **The full flag set builds the existing code with gcc and with clang, `-Werror`.** The only findings were in the tests: 33 calls whose results the tests ignored (28 in `test_wal.c`, 5 in `test_selftest.c`), now each checked. Clang alone also flagged the two libbpf print callbacks (`-Wformat-nonliteral`), fixed with a `format` attribute.
2. **Ignoring a `P15_MUST_CHECK` result fails the build** under both compilers, and the same probe compiles when the result is used (`make must-check-test`). With the attribute removed from `p15w_tick`, the probe compiles and the target fails, so the check is a gate ([`must-check-revert.txt`](must-check-revert.txt)).
3. **The binary carries the hardening:** `build/p15-spine` is PIE, full RELRO (`BIND_NOW`), NX stack, imports `__stack_chk_fail` and `__*_chk` (FORTIFY), and has the IBT and SHSTK property (`make hardening-check`).
4. **One fatal path:** no `exit`/`_exit`/`abort` in `daemon/` outside 3 marked sites, all in the self-test's child and grandchild (`make exit-check`).
5. All C tests pass, also under ASan and UBSan. The WAL sweep still kills 27 of 27. The new checkers' sweep kills 21 of 21; it first showed 5 survivors, one from stale Python bytecode in the sweep itself (fixed: the sweep now runs with no bytecode) and four untested lexer edges (tests added).
6. The self-test still passes all its checks with the hardened build (`make smoke`).
