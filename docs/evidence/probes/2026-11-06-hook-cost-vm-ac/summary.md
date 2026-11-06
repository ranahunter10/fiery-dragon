# hook_cost: the classic-tracepoint hook path against tp_btf (ADR-0020 confirmation 5)

Null syscall (getppid), median over rounds: 92.5 ns.

## rename, cpu time per event (primary; 20 rounds)

| arm | median | 95 % interval |
|---|---|---|
| none | 141.5 ns | 136.9 ns to 146.9 ns |
| none2 | 143.8 ns | 140.8 ns to 147.1 ns |
| tp | 200.6 ns | 194.0 ns to 205.4 ns |
| btf | 164.7 ns | 154.9 ns to 168.1 ns |

- **tp against none:** overhead +38.36 %, 95 % interval +30.78 % to +48.08 %, Wilcoxon p = 1.91e-06
  - added per event 56.1 ns (95 % interval 45.6 ns to 66.9 ns), 0.61 null syscalls; ratio of medians 1.4170; effect p = 1.91e-06
- **btf against none:** overhead +14.14 %, 95 % interval +10.63 % to +19.17 %, Wilcoxon p = 1.91e-06
  - added per event 21.1 ns (95 % interval 15.6 ns to 26.6 ns), 0.23 null syscalls; ratio of medians 1.1633; effect p = 1.91e-06
- **tp against btf (the ADR-0020 question):** overhead +21.90 %, 95 % interval +15.26 % to +28.35 %, Wilcoxon p = 1.91e-06
  - added per event 36.3 ns (95 % interval 24.6 ns to 46.1 ns), 0.39 null syscalls; ratio of medians 1.2180; effect p = 1.91e-06

## rename, wall time per event (secondary; 20 rounds)

| arm | median | 95 % interval |
|---|---|---|
| none | 141.6 ns | 136.9 ns to 147.2 ns |
| none2 | 144.7 ns | 141.3 ns to 147.8 ns |
| tp | 200.6 ns | 194.0 ns to 205.4 ns |
| btf | 164.7 ns | 154.9 ns to 168.0 ns |

- **tp against none:** overhead +38.32 %, 95 % interval +30.54 % to +48.13 %, Wilcoxon p = 1.91e-06
  - added per event 55.9 ns (95 % interval 45.4 ns to 66.8 ns), 0.60 null syscalls; ratio of medians 1.4164; effect p = 1.91e-06
- **btf against none:** overhead +14.08 %, 95 % interval +10.62 % to +19.15 %, Wilcoxon p = 1.91e-06
  - added per event 21.1 ns (95 % interval 15.4 ns to 26.6 ns), 0.23 null syscalls; ratio of medians 1.1628; effect p = 1.91e-06
- **tp against btf (the ADR-0020 question):** overhead +21.88 %, 95 % interval +15.26 % to +28.24 %, Wilcoxon p = 1.91e-06
  - added per event 36.3 ns (95 % interval 24.6 ns to 46.1 ns), 0.39 null syscalls; ratio of medians 1.2181; effect p = 1.91e-06

## exec, cpu time per event (primary; 20 rounds)

| arm | median | 95 % interval |
|---|---|---|
| none | 2,288,250.0 ns | 2,208,583.3 ns to 2,369,590.0 ns |
| none2 | 2,255,786.7 ns | 2,179,100.0 ns to 2,388,363.3 ns |
| tp | 2,229,365.0 ns | 2,162,820.0 ns to 2,377,306.7 ns |
| btf | 2,248,930.0 ns | 2,190,943.3 ns to 2,387,423.3 ns |
| spine | 2,302,863.3 ns | 2,233,600.0 ns to 2,451,603.3 ns |

- **tp against none:** not resolved on this host (A/A interval -2.60 % to +5.62 %)
  - added per event -41,710.0 ns (95 % interval -113,450.0 ns to 63,865.0 ns), -450.76 null syscalls; ratio of medians 0.9743; effect p = 0.216
- **btf against none:** not resolved on this host (A/A interval -2.60 % to +5.62 %)
  - added per event -16,854.2 ns (95 % interval -117,975.0 ns to 88,886.7 ns), -182.14 null syscalls; ratio of medians 0.9828; effect p = 0.674
- **spine EXEC (shipped) against none:** not resolved on this host (A/A interval -2.60 % to +5.62 %)
  - added per event 40,718.3 ns (95 % interval -27,155.0 ns to 110,120.0 ns), 440.05 null syscalls; ratio of medians 1.0064; effect p = 0.154
- **tp against btf (the ADR-0020 question):** not resolved on this host (A/A interval -2.60 % to +5.62 %)
  - added per event -4,787.5 ns (95 % interval -74,570.0 ns to 51,985.0 ns), -51.74 null syscalls; ratio of medians 0.9913; effect p = 0.927

## exec, wall time per event (secondary; 20 rounds)

| arm | median | 95 % interval |
|---|---|---|
| none | 2,443,477.3 ns | 2,344,173.0 ns to 2,519,298.1 ns |
| none2 | 2,396,279.4 ns | 2,314,452.9 ns to 2,548,019.0 ns |
| tp | 2,368,174.0 ns | 2,296,791.4 ns to 2,544,738.9 ns |
| btf | 2,392,292.5 ns | 2,325,825.6 ns to 2,551,573.5 ns |
| spine | 2,459,161.3 ns | 2,373,865.0 ns to 2,610,022.5 ns |

- **tp against none:** not resolved on this host (A/A interval -2.94 % to +5.51 %)
  - added per event -47,844.1 ns (95 % interval -127,959.4 ns to 74,313.4 ns), -517.06 null syscalls; ratio of medians 0.9692; effect p = 0.231
- **btf against none:** not resolved on this host (A/A interval -2.94 % to +5.51 %)
  - added per event -16,942.3 ns (95 % interval -130,415.8 ns to 100,239.1 ns), -183.10 null syscalls; ratio of medians 0.9791; effect p = 0.729
- **spine EXEC (shipped) against none:** not resolved on this host (A/A interval -2.94 % to +5.51 %)
  - added per event 45,352.9 ns (95 % interval -29,500.6 ns to 120,578.7 ns), 490.13 null syscalls; ratio of medians 1.0064; effect p = 0.154
- **tp against btf (the ADR-0020 question):** not resolved on this host (A/A interval -2.94 % to +5.51 %)
  - added per event -4,426.6 ns (95 % interval -79,934.0 ns to 59,033.0 ns), -47.84 null syscalls; ratio of medians 0.9899; effect p = 0.841

