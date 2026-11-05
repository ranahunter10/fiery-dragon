# ADR-0018's statistics as tested code (2026-11-05)

**Where:** the dev container, with Python 3.13 and scipy 1.18.1, for scipy's extra checks. **What:** `bench/quant/paired.py` and its tests. ADR-0018 was accepted on 2026-10-25, but its rule 2 statistics had never been written. ADR-0020's confirmation 5 can't be run without them.

**File:** [`container.txt`](container.txt): the tests, the mutation sweep and every unit-test file.

## Findings (MEAS, container)

1. **Each exact quantity agrees with an independent computation.**
   - The signed-rank null distribution equals brute-force enumeration of all 2^n sign patterns for n = 0..12.
   - The two-sided p-value equals enumeration on 200 random samples, and scipy's `method="exact"` on 100 more (n = 6..30).
   - The n = 10 tail values match Hollander and Wolfe: P(W+ ≤ 8) = 25/1024.
   - The order-statistic interval for the median equals enumeration for n = 6..15.
2. **The Hodges–Lehmann interval is the inverse of the test.** On 60 random samples, any θ inside it keeps H0 at 5 %, and θ just outside rejects it. For n = 10 it is [W(9), W(47)], the textbook interval.
3. **The verdict follows ADR-0018 rule 2.4.**
   - A clear 10 % effect is quoted.
   - No effect gives "not resolved".
   - A significant effect that lies inside the A/A floor is not quoted.
   - An effect outside a narrow floor but with p > 0.05 is not quoted.
   - Too few rounds is said, and so are dropped zeros and drift.
4. **The tests catch planted bugs.** All 13 mutants of `paired.py` are caught. The sweep found three gaps in the first version of the tests (the A/A arm's denominator, the p threshold, the zero-difference note), and each now has a test. The sweep total is 113/113.

## Not shown

- Any timing result. This is the tool; the hook-cost harness that uses it comes next.
