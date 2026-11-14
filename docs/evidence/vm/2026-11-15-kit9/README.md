# Kit fd-vm-test9 on the VM, 2026-11-15

`vm/integration-8` (`manifest.txt`): case 9's holder and the paused canary (E-0319's fixes). Journal: E-0320.

| File | Result |
|---|---|
| `it_p15d_1..3.txt` | 2 of 3 PASS. Run 1 failed case 23 only: `canaries 1 (missed 0, late 0, unfinished 0)`: its one canary was judged **in time**, so the staged 2 s of lateness had been excused or restarted (a VM freeze of at least 2 s inside the canary's window; the canary is built to forgive exactly that) |
| `mutants.txt`, `mutate-kills.txt` | 7 of 7 killed, each with a check of its own case (121-124 case 28, 122 also 29, 125 case 30, 126 the flow books, 131 the unit test). Kills 124 and 125 also list case 23 failing on its own |
| case 9 | passed in all 3 runs and all 6 end-to-end mutant runs |

Fix (commit "tests: the canary cases run until their verdict"): cases 22, 23 and 25 run p15d until its log shows the verdict they stage, so a canary forgiven for a VM freeze is followed by the next one instead of ending the case.
