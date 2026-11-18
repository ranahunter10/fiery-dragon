# Kit fd-vm-test10 on the VM, 2026-11-15

`vm/integration-9` (`manifest.txt`, tree `922d807…`): kit 9's tree plus "the canary cases run until their verdict". Journal: E-0321.

| File | Result |
|---|---|
| `build.txt`, `test-c.txt`, `test-python.txt` | PASS (30 Python test files, 0 failed) |
| `it_p15d_1..3.txt` | 3 of 3 PASS, 0 failed checks each (262, 265, 272 s). Case 23 judged LATE in every run (L:2002, L:2000, L:2001); case 21 no miss, no late; case 22 R:111:109 |
| `mutants.txt`, `mutate-kills.txt` | 6 of 6 killed (121-126, the end-to-end ones). Every failed check belongs to the killed bug's own case: 121-124 the disk guard (case 28/29), 125 the flow ring's reserve (case 30 and the flow retry), 126 the flow books. No case failed on its own in any of the six runs |

The sweep's own baseline passed too (302 s). The kit's `verdicts.txt` is not copied: the VM's results folder is reused across kits, so it lists earlier kits' steps as well (the old FAIL rows there are kits 2 and 7).
