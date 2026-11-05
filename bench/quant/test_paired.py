# SPDX-License-Identifier: MIT
"""Tests for paired.py. Every exact quantity is checked against an independent computation:
brute-force enumeration of all 2^n sign patterns (or of all subsets) for small n, the textbook
tables (Hollander and Wolfe), and scipy when it is installed (the VM's venv has no scipy, so
those tests skip there and run in the dev container)."""

import itertools
import math
import random
import sys
import unittest
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import paired as P  # noqa: E402

try:
    import scipy.stats as SS
except ImportError:          # the VM venv
    SS = None


def brute_counts(n):
    counts = [0] * (n * (n + 1) // 2 + 1)
    for signs in itertools.product((0, 1), repeat=n):
        counts[sum(r for r, s in zip(range(1, n + 1), signs) if s)] += 1
    return counts


def brute_p(d):
    """Two-sided exact p by enumerating every sign flip of the observed |d| ranks."""
    nz = [x for x in d if x != 0]
    ranks, _ = P._ranks_abs(nz)
    w = sum(r for r, x in zip(ranks, nz) if x > 0)
    allw = [sum(r for r, s in zip(ranks, signs) if s) for signs in itertools.product((0, 1), repeat=len(nz))]
    lo = sum(1 for x in allw if x <= w) / len(allw)
    hi = sum(1 for x in allw if x >= w) / len(allw)
    return min(1.0, 2 * min(lo, hi))


class SignedRankTest(unittest.TestCase):
    def test_counts_match_enumeration(self):
        for n in range(0, 13):
            with self.subTest(n=n):
                self.assertEqual(P.signed_rank_counts(n), brute_counts(n))

    def test_known_tail(self):
        # n = 10: P(W+ <= 8) = 25/1024 and P(W+ <= 9) = 33/1024 (Hollander and Wolfe, Table A.4)
        c = P.signed_rank_counts(10)
        self.assertEqual(sum(c[:9]), 25)
        self.assertEqual(sum(c[:10]), 33)

    def test_p_matches_enumeration(self):
        rnd = random.Random(7)
        for trial in range(200):
            n = rnd.randint(1, 11)
            d = [round(rnd.gauss(0.3, 1), 3) for _ in range(n)]
            with self.subTest(trial=trial, d=d):
                self.assertAlmostEqual(P.wilcoxon_exact(d).p_two_sided, brute_p(d), places=12)

    def test_all_positive(self):
        r = P.wilcoxon_exact([float(i) for i in range(1, 11)])
        self.assertEqual(r.w_plus, 55)
        self.assertAlmostEqual(r.p_two_sided, 2 / 1024)

    def test_zeros_dropped_and_counted(self):
        r = P.wilcoxon_exact([0.0, 0.0, 1.0, 2.0, -0.5])
        self.assertEqual((r.n_used, r.zeros), (3, 2))
        self.assertEqual(P.wilcoxon_exact([0.0, 0.0]).p_two_sided, 1.0)

    def test_ties_counted(self):
        self.assertEqual(P.wilcoxon_exact([1.0, -1.0, 2.0, 3.0]).ties, 2)

    @unittest.skipIf(SS is None, "scipy not installed (the VM venv)")
    def test_p_matches_scipy(self):
        rnd = random.Random(11)
        for trial in range(100):
            n = rnd.randint(6, 30)
            d = [rnd.gauss(0.2, 1) for _ in range(n)]       # continuous: no ties, no zeros
            with self.subTest(trial=trial):
                ref = SS.wilcoxon(d, alternative="two-sided", method="exact").pvalue
                self.assertAlmostEqual(P.wilcoxon_exact(d).p_two_sided, ref, places=10)


class HodgesLehmannTest(unittest.TestCase):
    def test_estimate_is_median_of_walsh(self):
        d = [0.3, -0.1, 0.5, 0.2]
        w = sorted((d[i] + d[j]) / 2 for i in range(4) for j in range(i, 4))
        self.assertEqual(P.walsh_averages(d), w)
        self.assertAlmostEqual(P.hodges_lehmann(d).estimate, P.median(w))

    def test_n10_uses_the_ninth_order_statistics(self):
        # n = 10, M = 55: the 95 % interval is [W(9), W(47)], coverage 1 - 2 * 25/1024 (H&W)
        d = [float(i) for i in range(10)]
        w = P.walsh_averages(d)
        ci = P.hodges_lehmann(d).ci
        self.assertEqual((ci.lo, ci.hi), (w[8], w[46]))
        self.assertAlmostEqual(ci.confidence, 1 - 2 * 25 / 1024)

    def test_too_few_rounds(self):
        self.assertIsNone(P.hodges_lehmann([0.1, 0.2, 0.3, 0.4, 0.5]).ci)    # n = 5 can't reach 95 %
        self.assertIsNotNone(P.hodges_lehmann([0.1, 0.2, 0.3, 0.4, 0.5, 0.6]).ci)

    def test_interval_inverts_the_test(self):
        # theta inside the interval: the test of d - theta keeps H0 at 5 %; just outside: rejects.
        rnd = random.Random(3)
        for trial in range(60):
            d = [rnd.gauss(0.05, 0.02) for _ in range(rnd.randint(8, 14))]
            ci = P.hodges_lehmann(d).ci
            eps = 1e-9
            with self.subTest(trial=trial):
                for theta in (ci.lo + eps, (ci.lo + ci.hi) / 2, ci.hi - eps):
                    self.assertGreater(P.wilcoxon_exact([x - theta for x in d]).p_two_sided, 0.05)
                for theta in (ci.lo - 1e-6, ci.hi + 1e-6):
                    self.assertLessEqual(P.wilcoxon_exact([x - theta for x in d]).p_two_sided, 0.05)


class MedianTest(unittest.TestCase):
    def test_median(self):
        self.assertEqual(P.median([3, 1, 2]), 2)
        self.assertEqual(P.median([4, 1, 2, 3]), 2.5)
        with self.assertRaises(ValueError):
            P.median([])

    def test_median_ci_n10(self):
        xs = [float(i) for i in range(10)]
        ci = P.median_ci(xs)
        self.assertEqual((ci.lo, ci.hi), (1.0, 8.0))                      # [x(2), x(9)]
        self.assertAlmostEqual(ci.confidence, 1 - 2 * 11 / 1024)

    def test_median_ci_matches_enumeration(self):
        for n in range(6, 16):
            j = max(j for j in range(1, n // 2 + 1)
                    if Fraction(sum(math.comb(n, i) for i in range(j)), 2 ** n) <= Fraction(1, 40))
            ci = P.median_ci([float(i) for i in range(n)])
            with self.subTest(n=n):
                self.assertEqual((ci.lo, ci.hi), (float(j - 1), float(n - j)))

    def test_median_ci_too_small(self):
        self.assertIsNone(P.median_ci([1.0, 2.0, 3.0, 4.0, 5.0]))

    def test_means(self):
        self.assertAlmostEqual(P.mean([1, 2, 3]), 2)
        self.assertAlmostEqual(P.harmonic_mean([1, 4, 4]), 2)
        with self.assertRaises(ValueError):
            P.harmonic_mean([1, 0])


class ReportTest(unittest.TestCase):
    def rounds(self, factor, n=12, seed=5, noise=0.002):
        rnd = random.Random(seed)
        u = [100 * math.exp(rnd.gauss(0, 0.1)) for _ in range(n)]
        t = [x * factor * math.exp(rnd.gauss(0, noise)) for x in u]
        aa = [x * math.exp(rnd.gauss(0, noise)) for x in u]
        return t, u, aa

    def test_clear_effect_is_quotable(self):
        r = P.paired_report(*self.rounds(1.10))
        self.assertTrue(r.quotable)
        self.assertAlmostEqual(r.overhead, 0.10, delta=0.005)
        self.assertLess(r.effect_test.p_two_sided, 0.05)
        self.assertIn("overhead +", r.verdict())

    def test_no_effect_is_not_resolved(self):
        r = P.paired_report(*self.rounds(1.0))
        self.assertFalse(r.quotable)
        self.assertIn("not resolved on this host", r.verdict())

    def test_effect_inside_the_floor_is_not_quoted(self):
        # a real 0.5 % effect under A/A noise of 3 %: p may be small, but HL sits inside the floor
        rnd = random.Random(9)
        u = [100 * math.exp(rnd.gauss(0, 0.1)) for _ in range(12)]
        t = [x * 1.005 * math.exp(rnd.gauss(0, 0.0005)) for x in u]
        aa = [x * math.exp(rnd.gauss(0, 0.03)) for x in u]
        r = P.paired_report(t, u, aa)
        self.assertLess(r.effect_test.p_two_sided, 0.05)
        self.assertFalse(r.quotable)

    def test_drift_flag(self):
        # the untraced arm drifts upward across rounds while T sits 10 % above each U: the paired
        # effect stays 10 %, and the medians' ratio moves with the drift; the flag says so
        u = [100 + 20 * i for i in range(12)]
        t = [x * 1.10 for x in u]
        aa = [x * (1 + 0.001 * ((-1) ** i)) for i, x in enumerate(u)]
        t[0] = t[0] * 3                                 # one outlier pulls the medians apart
        r = P.paired_report(t, u, aa)
        self.assertAlmostEqual(math.exp(r.effect.estimate), 1.10, places=3)
        self.assertGreater(r.ratio_of_medians, 1.15)       # pulled by the outlier
        self.assertTrue(r.drift)
        self.assertIn("drift", " ".join(r.notes))
        self.assertFalse(P.paired_report(*self.rounds(1.10)).drift)

    def test_floor_is_aa_against_untraced(self):
        # T is 10 % above U and U' is U plus noise: the floor must sit at 0, not at ln(U'/T) = -9.5 %
        t, u, aa = self.rounds(1.10)
        r = P.paired_report(t, u, aa)
        self.assertLess(abs(r.floor.estimate), 0.002)
        self.assertTrue(r.floor.ci.lo <= 0 <= r.floor.ci.hi)

    def test_p_must_be_below_five_percent(self):
        # HL lies outside a very narrow A/A floor, but the signs are mixed, so p is large: not quotable
        u = [100.0 + i for i in range(12)]
        d = [0.010, -0.008, 0.012, -0.009, 0.011, -0.007, 0.013, -0.010, 0.009, 0.002, -0.003, 0.004]
        t = [x * math.exp(e) for x, e in zip(u, d)]
        aa = [x * math.exp(1e-6 * (1 if i % 2 else -1) * (i + 1)) for i, x in enumerate(u)]
        r = P.paired_report(t, u, aa)
        self.assertGreater(r.effect_test.p_two_sided, 0.05)
        self.assertLess(r.effect_test.p_two_sided, 0.5)
        self.assertFalse(r.floor.ci.lo <= r.effect.estimate <= r.floor.ci.hi)
        self.assertFalse(r.quotable)

    def test_zero_differences_are_reported(self):
        t, u, _ = self.rounds(1.10)
        r = P.paired_report(t, u, list(u))                 # U' == U in every round: 12 zeros
        self.assertEqual(r.floor_test.zeros, 12)
        self.assertIn("A/A: 12 zero difference(s) dropped", r.notes)

    def test_too_few_rounds_is_said(self):
        r = P.paired_report(*self.rounds(1.1, n=5))
        self.assertFalse(r.quotable)
        self.assertIn("too few rounds", " ".join(r.notes))

    def test_bad_input(self):
        with self.assertRaises(ValueError):
            P.paired_report([1.0], [1.0, 2.0], [1.0])
        with self.assertRaises(ValueError):
            P.paired_report([0.0], [1.0], [1.0])


if __name__ == "__main__":
    unittest.main()
