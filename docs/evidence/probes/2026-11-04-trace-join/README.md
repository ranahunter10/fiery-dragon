# p15-trace's client join: the accept can be stamped before its connect (2026-11-04)

**Where:** the VM (`p15-dev-2604`, 7.0.0-38-generic, 3 vCPU), `vm_verify.sh` run `20261104T164452Z` at commit `42eb513` (the tip of PR #44), and the dev container (6.18) for the fix, at commit `c112803`.

**Files:**
- [`vm-verify-20261104T164452Z-summary.txt`](vm-verify-20261104T164452Z-summary.txt): the maintainer's paste of that run's SUMMARY, the recur_probe rows and the end-to-end case 1 lines, as sent;
- [`container.txt`](container.txt): the fix's tests, the Python mutation sweep and the end-to-end test in the container.
- [`vm-verify-20261104T181920Z-summary.txt`](vm-verify-20261104T181920Z-summary.txt): the maintainer's paste of the VM rerun from step 14 on this PR's tip (`cc757c4`), as sent.

## Findings

1. **Step 14 fails on case 5 only (MEAS, VM).** 16 of 17 steps pass. In step 14, case 1 shows all 200 children's EXECs in the WAL and no kernel skip (ADR-0020's confirmation, E-0091). Case 5 fails 2 checks: p15-trace's summary and its client lines. It finds the client of one accept, not of both.
2. **The cause: one ACCEPT is stamped 12 µs before its own CONNECT (MEAS, VM; the maintainer's chat paste of `p15w-inspect -v` on case 5's run).**
   - ACCEPT on 127.0.0.1:18077: `ts_ns` 7016138659796, remote 127.0.0.1:55246.
   - The client's CONNECT: `ts_ns` 7016138671981, local 127.0.0.1:55246.
   - That is 12,185 ns later. Both values are from the paste. The run's segment is still on the VM, under that run's `it-runs/`, and is to be added here.
3. **Why it can happen (SRC).** Each NET record is stamped by an fexit program, that is, when the call returns. On loopback the server's `accept()` can return as soon as the handshake completes, while the client's `connect()` is still on its way back to user space. p15-trace took only a connect at or before the accept, so it dropped a correct match and counted it as `client_not_found`. That makes it a reader bug, not a capture loss: both records are in the WAL.
4. **The fix (MEAS, container).** p15-trace now takes the connect with the same endpoints and network namespace that is **nearest in time on either side** of the accept, within `JOIN_WINDOW_NS` = 5 s.
   - A new counter, `connect_after_accept`, counts the matches whose connect came after the accept. Both reports print it.
   - The join test covers:
     - the VM's 12,185 ns case;
     - both edges of the window, and one nanosecond beyond each;
     - two candidates in four orders;
     - a failed connect, another netns and another target, each inside the window.
   - Python tests: 23/23 in `test_trace.py`.
   - Planted bugs: 100/100 caught, 7 of them on the join (the netns rule, the window, `<` for `<=`, the old "earlier only" rule, the nearest-in-time choice, the new counter).
   - The end-to-end test passes. Case 5 is skipped here: fentry/fexit doesn't load in this container (E-0078). CI and the VM run it.
5. **The 5 s bound is a heuristic (INF), and a design choice for the maintainer.**
   - The two calls of one connection return microseconds apart (finding 2). A reused 4-tuple needs the old connection closed and a new handshake.
   - The bound doesn't guarantee that a reused port stays out of the window. On loopback `tcp_tw_reuse` allows reuse, and in this test the server closes first, so the client's side never enters TIME_WAIT.
   - What the bound does guarantee:
     - a connect seconds away is never joined;
     - inside the window, two candidates are counted in `endpoint_ambiguous`, and the nearer one is taken;
     - an accept with no candidate is counted in `client_not_found`.
   - The match stays labelled an inference.

6. **The VM passes on the fix (MEAS, VM, run `20261104T181920Z`, commit `cc757c4`).** The run resumed from step 14 (`FROM=14`), on the build from `42eb513`; the fix changes Python only. Steps 14–17 all pass:
   - step 14, the end-to-end test, with case 5's p15-trace checks (both clients found);
   - step 15, the p15d planted bugs. One soft lockup touched this step, and the script marked it;
   - step 16, the spine EXEC planted bugs;
   - step 17, the demo story.
   - Steps 1–13 are as in run `20261104T164452Z`, where all of them passed.
   - The pasted SUMMARY doesn't show how many of the 2 accepts had a connect after them, or the per-check lines. Those are in that run's `verify.log`.

## Not yet

- The failing run's segment and `c5-trace.txt`, from `~/vm-verify-20261104T164452Z/it-runs/`, re-read by the fixed p15-trace. The two timestamps in finding 2 are still from the chat paste.
