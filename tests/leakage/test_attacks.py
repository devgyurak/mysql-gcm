#!/usr/bin/env python3
"""GWT tests for attack 1 and the baselines (amendment A17).

The known-answer case plants a mapping whose success is known in advance, so a
broken attack fails the test instead of silently reporting "no leakage".
"""

from __future__ import annotations

import unittest

from attacks import (
    equality_stats,
    frequency_attack,
    ngram_frequency,
    prior_surname_guess,
)
from metrics import reverse_injection, token_recovery
from names import KO_LANGUAGE, NameGenerator


class GivenPlantedMappingTest(unittest.TestCase):
    def test_given_planted_frequencies_when_frequency_attack_then_full_recovery(self) -> None:
        observed = {100: 40, 200: 30, 300: 20, 400: 10}
        prior = {"가": 0.4, "나": 0.3, "다": 0.2, "라": 0.1}
        truth = reverse_injection([(100, "가"), (200, "나"), (300, "다"), (400, "라")])
        recovered = token_recovery(frequency_attack(observed, prior, top_k=4), truth, observed)
        self.assertAlmostEqual(recovered.weighted, 1.0, places=6)

    def test_given_no_tokens_when_frequency_attack_then_control_recovers_nothing(self) -> None:
        self.assertEqual(frequency_attack({}, {"가": 1.0}), {})


class GivenAPriorTest(unittest.TestCase):
    def test_given_korean_statistics_when_prior_surname_guess_then_kim(self) -> None:
        dist = NameGenerator(KO_LANGUAGE, 1990, 0).surname_dist()
        self.assertEqual(prior_surname_guess(dist), "김")

    def test_given_names_when_ngram_frequency_then_normalised(self) -> None:
        freq = ngram_frequency(["김가", "김가"], (1,))
        self.assertAlmostEqual(sum(freq.values()), 1.0, places=9)
        self.assertEqual(set(freq), {"김", "가"})

    def test_given_repeated_names_when_equality_stats_then_unique_fraction(self) -> None:
        stats = equality_stats(["김가", "김가", "이나"])
        self.assertEqual(stats["distinct_full_names"], 2)
        self.assertAlmostEqual(float(stats["unique_full_fraction"]), 1 / 3, places=9)


if __name__ == "__main__":
    unittest.main()
