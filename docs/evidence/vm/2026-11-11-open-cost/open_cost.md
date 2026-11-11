# open_cost: what capture adds to an open and a close (decision 22a.4)

Run: kernel=7.0.0-38-generic cpus=3 rounds=20 same=200000 distinct=20000 settle=1.0 idle=1.0 p15d_args=-.

20 rounds. Null syscall (getppid) without capture, median: 87.5 ns; with p15d: 89.1 ns.

## same: one file opened again and again (steady state); thread CPU time, primary

| arm | median per open+close | 95 % interval |
|---|---|---|
| none | 885.4 ns | 856.7 ns to 910.5 ns |
| none2 | 879.3 ns | 866.6 ns to 926.5 ns |
| p15d | 2,281.2 ns | 2,221.4 ns to 2,323.3 ns |

- **p15d against none:** overhead +157.77 %, 95 % interval +153.31 % to +162.41 %, Wilcoxon p = 1.91e-06
  - added per open+close 1,396.3 ns (95 % interval 1,367.6 ns to 1,440.6 ns), 15.95 null syscalls; ratio of medians 2.5766; effect p = 1.91e-06

## same: one file opened again and again (steady state); wall time, secondary

| arm | median per open+close | 95 % interval |
|---|---|---|
| none | 887.0 ns | 856.7 ns to 913.0 ns |
| none2 | 881.8 ns | 870.7 ns to 926.5 ns |
| p15d | 2,359.1 ns | 2,302.5 ns to 2,622.3 ns |

- **p15d against none:** overhead +174.20 %, 95 % interval +165.74 % to +182.93 %, Wilcoxon p = 1.91e-06
  - added per open+close 1,560.1 ns (95 % interval 1,456.8 ns to 1,669.9 ns), 17.82 null syscalls; ratio of medians 2.6597; effect p = 1.91e-06
  - notes: drift: the ratio of medians and e^HL differ by more than the A/A interval's width

## distinct: every open a first sighting (facts in the record); thread CPU time, primary

| arm | median per open+close | 95 % interval |
|---|---|---|
| none | 1,187.1 ns | 1,161.3 ns to 1,223.1 ns |
| none2 | 1,207.8 ns | 1,187.2 ns to 1,264.4 ns |
| p15d | 2,880.7 ns | 2,844.0 ns to 3,061.8 ns |

- **p15d against none:** overhead +145.94 %, 95 % interval +140.58 % to +154.90 %, Wilcoxon p = 1.91e-06
  - added per open+close 1,748.0 ns (95 % interval 1,662.3 ns to 1,860.5 ns), 19.97 null syscalls; ratio of medians 2.4267; effect p = 1.91e-06

## distinct: every open a first sighting (facts in the record); wall time, secondary

| arm | median per open+close | 95 % interval |
|---|---|---|
| none | 1,187.0 ns | 1,161.3 ns to 1,222.3 ns |
| none2 | 1,207.7 ns | 1,187.1 ns to 1,264.2 ns |
| p15d | 3,084.5 ns | 2,969.6 ns to 3,388.2 ns |

- **p15d against none:** overhead +168.29 %, 95 % interval +154.11 % to +184.30 %, Wilcoxon p = 1.91e-06
  - added per open+close 1,997.9 ns (95 % interval 1,821.9 ns to 2,213.6 ns), 22.82 null syscalls; ratio of medians 2.5986; effect p = 1.91e-06
  - notes: drift: the ratio of medians and e^HL differ by more than the A/A interval's width

## What the capture wrote and what it cost p15d

- opens expected 4,400,000; OPEN records with their path 4,400,000; PATH_MISSING records of the workload 0; CLOSE records 4,400,000; lost to the ring 0
- records per open+close: 2.000; bytes per open+close in the WAL: 171.6 (OPEN 115.6, CLOSE 56.0)
- opens carrying the object's facts: 9.1%
- opens by other processes during the traced arms: 330
- p15d idle: 14.65 ms of CPU per second (mean; median 14.99)
- p15d per open+close of the workload: 609.0 ns of CPU in the window (mean), 552.1 ns after the idle rate is taken off (median 554.4 ns)
- agent overhead of the opens (p15d's CPU above its idle rate / the two open events' CPU time without capture): mean 60.1%, median 60.6%, range 51.2% to 71.7%
- agent overhead of the whole workload, as eAudit defines it (all of p15d's CPU in the window / the workload's CPU time without capture, null syscalls included): mean 46.0%, median 46.0%

