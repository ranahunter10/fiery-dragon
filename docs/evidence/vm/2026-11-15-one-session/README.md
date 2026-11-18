# One complete session on the VM (kit fd-vm-test8), 2026-11-14/15

VM `p15-dev` (7.0.0-38-generic, 3 vCPU), local `vm/integration-7`, commit `62a9463` (`manifest.txt`). Journal: E-0319.

| Stage | Result |
|---|---|
| `it_p15d_1..3.txt` | **3 of 3 PASS, 0 failed checks, none skipped** |
| `flood.txt` | 9,034,852 FLOWs, none lost; nothing else lost; the victim's 2,000 OPENs, 2,000 CLOSEs, 100 connects all written; 11,568 deferrals |
| `disk.txt` | exit 3; 29,397,625 bulk records shed, spine 0; WAL valid |
| `canary_inspect.txt` | `--flow --canary-s 1`, 10 s: 8 canaries, missed 0, late 0, **stalled 4** (deadlines moved for the drain's oversleep), want 0x7f, 23 links |
| `mutants.txt`, `mutate-kills.txt` | **22 of 22 killed**, each with its failed checks. Every end-to-end kill (121-126) includes a check of its own case: 121, 122, 123, 124 in case 28 (122 also case 29), 125 in case 30 (no deferral), 126 in the flow books (exit 4) |

What the kill logs also showed: two cases failed on their own in some of the 6 end-to-end mutant runs, though not in the 3 `it` runs: case 9 (no FD row for the holder: kills 122, 124) and case 23 (no LATE: kills 123, 125). Causes and fixes are in E-0319.
