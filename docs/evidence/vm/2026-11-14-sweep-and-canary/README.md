# The planted-bug sweep on the VM, and the canary's case 23, 2026-11-14

Kit fd-vm-test4 on VM `p15-dev` (7.0.0-38-generic, 3 vCPU), local `vm/integration-3`, commit `2b71fe1` (`manifest.txt`): `vm/integration-2` with case 30 forced. Journal: E-0316.

| File | Result |
|---|---|
| `mutants.txt` | **18 of 18 planted bugs killed** (111-124 the disk guard, 125-128 the flow ring); the baseline passed. Bugs 121-126 are judged by `it_p15d`; this sweep did not record which checks killed them, and `it_p15d.txt` shows a canary case failing on its own in the same tree, so those six kills are to be confirmed with the sweep that now logs each kill's failed checks |
| `it_p15d.txt` | 2 failed checks, both case 23 (the canary under a 1.5 s drain pause): p15d exit 0, no LATE verdict. Case 21 in the same run: 2 verdicts and 1 unfinished in 5 s. Case 30 passed |

Cause of case 23 (SRC, from `daemon/drain.c` and `daemon/canary.c`): `p15_drain_poll` called `p15_canary_tick` before `after_poll`, which reads the file counters. The canary sees the open session's and the file free's runs only through those counters, so with file identity on it saw them one poll late; with a 1.5 s drain pause that is 1.5 s, and the first verdict could fall after the 6 s run ended (one canary in flight, counted unfinished, exit 0). The fix ticks after `after_poll`; case 23 now runs 8 s and prints its canary counts. In the dev container (spine only, no file counters) case 23 gives 2 LATE verdicts, 520 ms each.
