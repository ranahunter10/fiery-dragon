# SPDX-License-Identifier: MIT
"""ADR-0018 rule 2: the paired-timing statistics, as code with tests (never by hand).

Per round i an experiment times a traced arm T, an untraced arm U and an A/A untraced arm U'.
From those:

- the effect d_i = ln(T_i / U_i) and the A/A control a_i = ln(U'_i / U_i);
- each arm's median, with a distribution-free interval from order statistics;
- the ratio of the medians, median T / median U (Hoefler and Belli, rule 4);
- the paired effect: the Hodges-Lehmann estimate of d (the median of the Walsh averages),
  reported as overhead = e^HL - 1, with the exact Wilcoxon signed-rank interval and p-value;
- the A/A floor: the same estimate and interval for a;
- a drift flag, when the ratio of medians and e^HL differ by more than the A/A interval's width;
- the verdict: an overhead is quoted only if p < 0.05 and HL lies outside the A/A interval;
  otherwise "not resolved on this host".

Everything exact is computed with integers: the null distribution of the signed-rank statistic
W+ by dynamic programming over the 2^n sign patterns, the order-statistic intervals from the
binomial distribution. Zero differences are dropped (Wilcoxon's original rule) and counted;
tied |d| are counted, and when there are any, the exact tables are those of the untied case,
which the report says.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from fractions import Fraction


def median(xs: list[float]) -> float:
    s = sorted(xs)
    n = len(s)
    if n == 0:
        raise ValueError("median of nothing")
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def mean(xs: list[float]) -> float:
    """For costs that are sums (ADR-0018 rule 2.5)."""
    if not xs:
        raise ValueError("mean of nothing")
    return math.fsum(xs) / len(xs)


def harmonic_mean(xs: list[float]) -> float:
    """For rates (ADR-0018 rule 2.5)."""
    if not xs or any(x <= 0 for x in xs):
        raise ValueError("harmonic mean needs positive values")
    return len(xs) / math.fsum(1 / x for x in xs)


def _binom_cdf_half(n: int, k: int) -> Fraction:
    """P(Bin(n, 1/2) <= k), exactly."""
    if k < 0:
        return Fraction(0)
    return Fraction(sum(math.comb(n, i) for i in range(min(k, n) + 1)), 2 ** n)


@dataclass
class Interval:
    lo: float
    hi: float
    confidence: float          # the achieved coverage (exact tables are discrete), not the asked one


def median_ci(xs: list[float], conf: float = 0.95) -> Interval | None:
    """Distribution-free interval for the median: [x(j), x(n+1-j)] with the largest j such that
    P(Bin(n, 1/2) <= j-1) <= (1-conf)/2. None if n is too small for that confidence."""
    s = sorted(xs)
    n = len(s)
    half = Fraction(1 - conf).limit_denominator(10 ** 9) / 2
    j = 0
    while j + 1 <= n // 2 and _binom_cdf_half(n, j) <= half:
        j += 1
    if j == 0:
        return None
    return Interval(s[j - 1], s[n - j], float(1 - 2 * _binom_cdf_half(n, j - 1)))


def signed_rank_counts(n: int) -> list[int]:
    """counts[w] = how many of the 2^n sign patterns give W+ = w, for ranks 1..n (no ties)."""
    counts = [1]
    for r in range(1, n + 1):
        nxt = counts + [0] * r
        for w, c in enumerate(counts):
            nxt[w + r] += c
        counts = nxt
    return counts


def _ranks_abs(d: list[float]) -> tuple[list[float], int]:
    """Midranks of |d| (1-based) and the number of tied |d| values (values sharing a rank)."""
    order = sorted(range(len(d)), key=lambda i: abs(d[i]))
    ranks = [0.0] * len(d)
    ties = 0
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and abs(d[order[j + 1]]) == abs(d[order[i]]):
            j += 1
        r = (i + j + 2) / 2
        for k in range(i, j + 1):
            ranks[order[k]] = r
        if j > i:
            ties += j - i + 1
        i = j + 1
    return ranks, ties


@dataclass
class Wilcoxon:
    n_used: int                # differences that are not zero
    zeros: int                 # dropped
    ties: int                  # |d| values sharing a rank
    w_plus: float
    p_two_sided: float


def wilcoxon_exact(d: list[float]) -> Wilcoxon:
    """Exact two-sided Wilcoxon signed-rank test of 'median of d is 0'."""
    nz = [x for x in d if x != 0]
    n = len(nz)
    if n == 0:
        return Wilcoxon(0, len(d), 0, 0.0, 1.0)
    ranks, ties = _ranks_abs(nz)
    w = sum(r for r, x in zip(ranks, nz) if x > 0)
    counts = signed_rank_counts(n)
    total = 2 ** n
    lo = sum(counts[: math.floor(w) + 1])               # P(W+ <= w)
    hi = sum(counts[math.ceil(w):])                      # P(W+ >= w)
    p = min(1.0, 2 * min(lo, hi) / total)
    return Wilcoxon(n, len(d) - n, ties, w, p)


def walsh_averages(d: list[float]) -> list[float]:
    return sorted((d[i] + d[j]) / 2 for i in range(len(d)) for j in range(i, len(d)))


@dataclass
class HodgesLehmann:
    estimate: float
    ci: Interval | None        # None if n is too small for the confidence asked


def hodges_lehmann(d: list[float], conf: float = 0.95) -> HodgesLehmann:
    """The median of the Walsh averages, with the exact interval that inverts the signed-rank
    test: [W(k), W(M+1-k)] for the largest k with P(W+ <= k-1) <= (1-conf)/2 (Hollander and
    Wolfe, ch. 3)."""
    if not d:
        raise ValueError("Hodges-Lehmann of nothing")
    w = walsh_averages(d)
    m = len(w)
    est = median(w)
    counts = signed_rank_counts(len(d))
    total = 2 ** len(d)
    half = Fraction(1 - conf).limit_denominator(10 ** 9) / 2
    k = 0
    cum = 0
    while k + 1 <= (m + 1) // 2:
        cum_next = cum + counts[k]                      # P(W+ <= k) * total
        if Fraction(cum_next, total) > half:
            break
        cum = cum_next
        k += 1
    if k == 0:
        return HodgesLehmann(est, None)
    return HodgesLehmann(est, Interval(w[k - 1], w[m - k], float(1 - 2 * Fraction(cum, total))))


@dataclass
class Arm:
    n: int
    median: float
    ci: Interval | None


@dataclass
class PairedReport:
    """Everything ADR-0018 rule 2.3 asks a timing report to show, and the rule 2.4 verdict."""
    n: int
    traced: Arm
    untraced: Arm
    aa: Arm
    ratio_of_medians: float
    effect: HodgesLehmann                  # of d = ln(T/U)
    effect_test: Wilcoxon
    floor: HodgesLehmann                   # of a = ln(U'/U)
    floor_test: Wilcoxon
    drift: bool
    quotable: bool
    notes: list[str] = field(default_factory=list)

    @property
    def overhead(self) -> float:
        return math.exp(self.effect.estimate) - 1

    def verdict(self) -> str:
        if not self.quotable:
            fl = self.floor.ci
            span = f"A/A interval {_pct(fl.lo)} to {_pct(fl.hi)}" if fl else "A/A interval: n too small"
            return f"not resolved on this host ({span})"
        ci = self.effect.ci
        return (f"overhead {_pct(self.effect.estimate)}, 95 % interval {_pct(ci.lo)} to {_pct(ci.hi)}, "
                f"Wilcoxon p = {self.effect_test.p_two_sided:.3g}")


def _pct(log_ratio: float) -> str:
    return f"{(math.exp(log_ratio) - 1) * 100:+.2f} %"


def paired_report(traced: list[float], untraced: list[float], aa: list[float], conf: float = 0.95) -> PairedReport:
    if not (len(traced) == len(untraced) == len(aa)) or not traced:
        raise ValueError("the three arms need one value per round each")
    if any(x <= 0 for x in traced + untraced + aa):
        raise ValueError("times must be positive")
    d = [math.log(t / u) for t, u in zip(traced, untraced)]
    a = [math.log(v / u) for v, u in zip(aa, untraced)]

    def arm(xs: list[float]) -> Arm:
        return Arm(len(xs), median(xs), median_ci(xs, conf))

    effect, floor = hodges_lehmann(d, conf), hodges_lehmann(a, conf)
    et, ft = wilcoxon_exact(d), wilcoxon_exact(a)
    rom = median(traced) / median(untraced)
    notes = []
    drift = False
    if floor.ci is not None:
        drift = abs(rom - math.exp(effect.estimate)) > math.exp(floor.ci.hi) - math.exp(floor.ci.lo)
    else:
        notes.append("too few rounds for an A/A interval at this confidence")
    quotable = (effect.ci is not None and floor.ci is not None and et.p_two_sided < 0.05
                and not floor.ci.lo <= effect.estimate <= floor.ci.hi)
    for name, t in (("effect", et), ("A/A", ft)):
        if t.zeros:
            notes.append(f"{name}: {t.zeros} zero difference(s) dropped")
        if t.ties:
            notes.append(f"{name}: {t.ties} tied |difference| values; exact tables assume none")
    if drift:
        notes.append("drift: the ratio of medians and e^HL differ by more than the A/A interval's width")
    return PairedReport(len(d), arm(traced), arm(untraced), arm(aa), rom, effect, et, floor, ft, drift, quotable,
                        notes)
