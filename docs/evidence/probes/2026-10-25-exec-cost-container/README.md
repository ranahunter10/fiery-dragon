# EXEC record cost, three ways, dev container (2026-10-25)

**Where:** the cloud dev container (kernel 6.18.44, 2 vCPUs, clang 18.1.3, root). **Not the target:** absolute costs are this host's only, and the VM repeats the run (`sudo make bench-exec-cost`).

**What:** the harness of [`bench/rb_cost/`](../../../../bench/rb_cost/README.md). The spine's EXEC program built three ways from the production source (`fixed`: reserve the maximum; `output`: per-CPU scratch, then `bpf_ringbuf_output` of `len`; `dynptr`: `bpf_ringbuf_reserve_dynptr` of `len`, argv read straight into the ring). Per round: a null-syscall baseline, then every way once per argv size (20, 200, 1,000 bytes) in a rotated order, 1,000 execs of `/bin/true` each, `bpf_stats` on throughout. 10 rounds, two sessions:

| Session | Raw | Summary | Code |
|---|---|---|---|
| 1 | [`exec-cost-session1.txt`](exec-cost-session1.txt) | [`summary-session1.md`](summary-session1.md) | the branch's BPF objects; the record checker before its two EXEC padding rules |
| 2 | [`exec-cost-session2.txt`](exec-cost-session2.txt) | [`summary-session2.md`](summary-session2.md) | the branch as committed |

The BPF code measured is the same in both. The summaries are `python3 bench/rb_cost/summarize.py <raw>`.

## Findings (MEAS, dev container, 2 sessions × 10 rounds)

1. **All three ways load, attach and deliver correct records:** 90,000 EXEC records per session checked by `p15_rec_check`, argv complete, ring size = `len` for `output` and `dynptr` and 1,344 B for `fixed`; 0 wrong in either session.
2. **The self-test separates them:** `output` and `dynptr` pass all checks; `fixed` fails exactly one, "every record takes exactly its len in the ring".
3. **Per-run cost is about 1.7–2.3 µs for every way, 15–22 null syscalls,** median per cell (session 1 had 161 execs by other processes in 90,000 runs, session 2 none).
4. **`output` versus `dynptr` is not resolved on this host.** Their paired medians differ by 12–124 ns, and the sign changes between sessions at the same argv size (1,000 B: `dynptr` −124 ns in session 1, +105 ns in session 2) and between sizes.
5. **`fixed` is cheaper at 200 and 1,000 B of argv** by a median 51–379 ns, in 8 to 10 of 10 rounds per cell; at 20 B the sign is mixed (8 of 10 in session 1, 5 of 10 in session 2). It is the one way with a single copy and no scratch lookup. It also takes 1,344 B of ring for every exec (E-0070, E-0073), which ADR-0017 layer 1 rules out.

## Not shown here

- Whether the `dynptr` way loads on 7.0.0-38: its two kfuncs are declared in the target's BTF ([`vmlinux-7.0.0-38.h`](../../../../bpf/vmlinux/vmlinux-7.0.0-38.h) lines 166838 and 166909, SRC), but only the VM run loads it.
- An ADR-0018 overhead estimate: these are raw per-run costs with `bpf_stats` on (about 20 ns per run, R-016), medians and ranges only.
