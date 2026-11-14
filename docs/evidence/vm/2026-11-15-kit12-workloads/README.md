# Kit fd-vm-test12 on the VM, 2026-11-15: two scenarios rerun, the web workload retimed

`vm/integration-11` (`manifest.txt`, tree `7fa4d03…`): kit 11's tree with the witness's
splice-into-socket rule, the git scenario as root, and a first masquerade fix. Journal: E-0323.

- **a1-exfil, rerun:** all four byte totals exact *as run*, in all 26 processes (`compare.txt`), with
  the corrected rule (`splice_to_socket 1`). The attack's reach holds, the catcher got 4,150 of
  4,150 bytes, and R1 fired. This confirms kit 11's recheck on a new run.
- **a4-masquerade:** still did not run as written (`coreutils: unknown program 'kworker'` with
  argv[0] set to sleep: Ubuntu 26.04's coreutils picks its tool from its own file name). Capture was
  exact for what ran (4 processes, 5 execs, 41 opens, bytes exact). The scenario now drops a copy
  of bash; rerun in kit 13.
- **w3-web cost, 7 rounds** (`cost-paired.txt`): paired ratio median 1.009, range 0.577 to 1.432,
  not resolved from 1. The untimed arms vary by up to about ±40 % per round on this host.
