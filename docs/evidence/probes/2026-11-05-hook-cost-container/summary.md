# hook_cost: the classic-tracepoint hook path against tp_btf (ADR-0020 confirmation 5)

Null syscall (getppid), median over rounds: 93.5 ns.

## rename, cpu time per event (primary; 20 rounds)

| arm | median | 95 % interval |
|---|---|---|
| none | 135.9 ns | 119.7 ns to 139.6 ns |
| none2 | 125.9 ns | 121.7 ns to 135.1 ns |
| tp | 163.7 ns | 157.7 ns to 176.4 ns |
| btf | 158.1 ns | 143.2 ns to 159.5 ns |

- **tp against none:** overhead +26.41 %, 95 % interval +17.44 % to +35.24 %, Wilcoxon p = 1.91e-05
  - added per event 35.6 ns (95 % interval 23.4 ns to 44.1 ns), 0.38 null syscalls; ratio of medians 1.2051; effect p = 1.91e-05
- **btf against none:** overhead +16.66 %, 95 % interval +14.23 % to +19.56 %, Wilcoxon p = 0.000105
  - added per event 22.1 ns (95 % interval 18.4 ns to 25.2 ns), 0.24 null syscalls; ratio of medians 1.1638; effect p = 0.000105
- **tp against btf (the ADR-0020 question):** overhead +9.85 %, 95 % interval +0.91 % to +16.55 %, Wilcoxon p = 0.0266
  - added per event 13.9 ns (95 % interval 0.8 ns to 24.7 ns), 0.15 null syscalls; ratio of medians 1.0355; effect p = 0.0266

## rename, wall time per event (secondary; 20 rounds)

| arm | median | 95 % interval |
|---|---|---|
| none | 137.4 ns | 119.9 ns to 150.4 ns |
| none2 | 130.9 ns | 121.7 ns to 137.9 ns |
| tp | 164.7 ns | 159.4 ns to 176.6 ns |
| btf | 160.7 ns | 150.5 ns to 164.1 ns |

- **tp against none:** overhead +24.60 %, 95 % interval +13.34 % to +35.06 %, Wilcoxon p = 0.000134
  - added per event 33.4 ns (95 % interval 19.1 ns to 44.3 ns), 0.36 null syscalls; ratio of medians 1.1982; effect p = 0.000134
- **btf against none:** overhead +17.00 %, 95 % interval +12.07 % to +21.19 %, Wilcoxon p = 0.000261
  - added per event 22.9 ns (95 % interval 16.6 ns to 27.8 ns), 0.25 null syscalls; ratio of medians 1.1691; effect p = 0.000261
- **tp against btf (the ADR-0020 question):** not resolved on this host (A/A interval -10.62 % to +0.56 %)
  - added per event 12.5 ns (95 % interval -1.9 ns to 22.7 ns), 0.13 null syscalls; ratio of medians 1.0249; effect p = 0.0532

## exec, cpu time per event (primary; 20 rounds)

| arm | median | 95 % interval |
|---|---|---|
| none | 910,501.7 ns | 803,830.0 ns to 991,770.0 ns |
| none2 | 917,850.0 ns | 857,740.0 ns to 989,540.0 ns |
| tp | 918,023.3 ns | 857,086.7 ns to 949,016.7 ns |
| btf | 966,616.7 ns | 878,783.3 ns to 1,014,030.0 ns |
| spine | 927,010.0 ns | 910,186.7 ns to 975,903.3 ns |

- **tp against none:** not resolved on this host (A/A interval -4.47 % to +4.50 %)
  - added per event 3,475.8 ns (95 % interval -52,738.3 ns to 59,506.7 ns), 37.18 null syscalls; ratio of medians 1.0083; effect p = 0.869
- **btf against none:** not resolved on this host (A/A interval -4.47 % to +4.50 %)
  - added per event 34,505.8 ns (95 % interval -47,285.0 ns to 110,851.7 ns), 369.06 null syscalls; ratio of medians 1.0616; effect p = 0.409
- **spine EXEC (shipped) against none:** not resolved on this host (A/A interval -4.47 % to +4.50 %)
  - added per event 13,438.3 ns (95 % interval -57,706.7 ns to 78,965.0 ns), 143.73 null syscalls; ratio of medians 1.0181; effect p = 0.596
- **tp against btf (the ADR-0020 question):** not resolved on this host (A/A interval -4.47 % to +4.50 %)
  - added per event -23,296.7 ns (95 % interval -115,151.7 ns to 56,401.7 ns), -249.17 null syscalls; ratio of medians 0.9497; effect p = 0.596

## exec, wall time per event (secondary; 20 rounds)

| arm | median | 95 % interval |
|---|---|---|
| none | 1,037,969.6 ns | 907,005.2 ns to 1,131,519.7 ns |
| none2 | 1,030,191.3 ns | 978,073.4 ns to 1,115,200.5 ns |
| tp | 1,031,317.4 ns | 983,994.8 ns to 1,066,760.8 ns |
| btf | 1,101,368.2 ns | 1,008,839.0 ns to 1,186,373.3 ns |
| spine | 1,044,323.9 ns | 1,017,653.9 ns to 1,123,303.6 ns |

- **tp against none:** not resolved on this host (A/A interval -4.39 % to +4.96 %)
  - added per event -8,901.0 ns (95 % interval -72,672.1 ns to 61,421.8 ns), -95.20 null syscalls; ratio of medians 0.9936; effect p = 0.812
- **btf against none:** not resolved on this host (A/A interval -4.39 % to +4.96 %)
  - added per event 43,095.8 ns (95 % interval -64,476.6 ns to 138,746.0 ns), 460.94 null syscalls; ratio of medians 1.0611; effect p = 0.409
- **spine EXEC (shipped) against none:** not resolved on this host (A/A interval -4.39 % to +4.96 %)
  - added per event 6,586.9 ns (95 % interval -75,014.3 ns to 87,107.1 ns), 70.45 null syscalls; ratio of medians 1.0061; effect p = 0.869
- **tp against btf (the ADR-0020 question):** not resolved on this host (A/A interval -4.39 % to +4.96 %)
  - added per event -45,758.3 ns (95 % interval -147,343.6 ns to 57,366.7 ns), -489.42 null syscalls; ratio of medians 0.9364; effect p = 0.43

