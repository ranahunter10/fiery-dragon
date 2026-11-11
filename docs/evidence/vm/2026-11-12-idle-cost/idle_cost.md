# idle_cost: p15d's CPU on an idle host (gate 3)

5 rounds of a 20 s window per arm, arms rotated each round. Budget (STATE decision 29): under 2 ms of CPU per second.

| arm | CPU ms/s, median | cheapest .. dearest round | polls/s | load, records/s (spine + bulk) | first arm / this | under the budget |
|---|---|---|---|---|---|---|
| max10 | 10.395 | 9.601 .. 10.911 | 95.3 | 2.1 | 1.00x | no |
| max50 | 2.859 | 2.483 .. 3.525 | 19.8 | 2.1 | 3.64x | no |
| max100 | 1.968 | 1.630 .. 3.350 | 10.0 | 2.5 | 5.28x | no |
| max200 | 1.143 | 1.094 .. 1.372 | 5.2 | 2.1 | 9.09x | yes |
| max500 | 0.823 | 0.818 .. 0.846 | 2.5 | 2.7 | 12.63x | yes |

Per thread, median ms/s over rounds:

| arm | p15d | p15d-writer |
|---|---|---|
| max10 | 9.819 | 0.546 |
| max50 | 2.278 | 0.525 |
| max100 | 1.422 | 0.547 |
| max200 | 0.613 | 0.530 |
| max500 | 0.301 | 0.542 |
