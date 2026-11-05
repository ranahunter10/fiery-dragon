# bench/quant: the statistics of ADR-0018

`paired.py` computes everything ADR-0018 rule 2 asks a timing report to show, from per-round times of a traced arm T, an untraced arm U and an A/A untraced arm U′:

| Output | What it is |
|---|---|
| per-arm median and interval | the median of each arm, with a distribution-free interval from order statistics |
| `ratio_of_medians` | median T ÷ median U |
| `effect` | the Hodges–Lehmann estimate of d = ln(T/U), with the exact Wilcoxon signed-rank interval |
| `effect_test` | the exact two-sided Wilcoxon p-value |
| `floor` | the same estimate and interval for the A/A control a = ln(U′/U) |
| `drift` | true when the ratio of medians and e^HL differ by more than the A/A interval's width |
| `verdict()` | an overhead is quoted only if p < 0.05 and HL lies outside the A/A interval; otherwise "not resolved on this host" |

The module uses only the standard library, so it runs in the VM's venv. Every exact table is built from integers (`fractions.Fraction`). Each table is checked in `test_paired.py` against brute-force enumeration and against the textbook values. In the dev container, scipy is an extra check.

```python
import paired
r = paired.paired_report(traced_times, untraced_times, aa_times)
print(r.verdict(), r.notes)
```
