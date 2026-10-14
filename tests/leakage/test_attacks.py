#!/usr/bin/env python3
"""GWT tests for attacks 1-4 and the baselines (amendment A17).

The known-answer cases plant a mapping whose success is known in advance, so a
broken attack fails the test instead of silently reporting "no leakage".
"""

from __future__ import annotations

import unittest

from attacks import (
    cooccurrence_attack,
    equality_stats,
    frequency_attack,
    ngram_frequency,
    prior_surname_guess,
    reconstruct,
    reconstruction_attack,
    seeding_attack,
)
from metrics import reverse_injection, token_frequency, token_recovery
from names import KO_LANGUAGE, NameGenerator
from tokens import DEFAULT_ORDERS, TokenModel, token_table

NAMES = ["홍길동", "김철수", "이영희", "박민준", "최서연", "정도윤", "강하은", "조지훈"]


def _model_and_table(names: list[str]) -> tuple[TokenModel, tuple[tuple[int, ...], ...]]:
    model = TokenModel(16, 0)
    return model, token_table(model, names, DEFAULT_ORDERS)


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


class GivenTheCooccurrenceAttackTest(unittest.TestCase):
    def test_given_a_table_when_cooccurrence_then_every_token_is_matched(self) -> None:
        _model, table = _model_and_table(NAMES * 5)
        prior = ngram_frequency(NAMES * 5, DEFAULT_ORDERS)
        predicted = cooccurrence_attack(table, NAMES * 5, prior, DEFAULT_ORDERS)
        self.assertEqual(set(predicted), set(token_frequency(table)))

    def test_given_no_tokens_when_cooccurrence_then_control_recovers_nothing(self) -> None:
        self.assertEqual(
            cooccurrence_attack((), NAMES, ngram_frequency(NAMES, DEFAULT_ORDERS), DEFAULT_ORDERS),
            {},
        )


class GivenTheSeedingAttackTest(unittest.TestCase):
    def test_given_distinct_frequencies_when_seeding_then_full_recovery(self) -> None:
        observed = {100: 1000, 200: 500, 300: 100}
        prior = {"가": 0.5, "나": 0.3, "다": 0.2}
        known = [((100, 200, 300), "가나다")]
        predicted = seeding_attack(observed, known, prior, (1,))
        truth = reverse_injection([(100, "가"), (200, "나"), (300, "다")])
        recovered = token_recovery(predicted, truth, observed)
        self.assertAlmostEqual(recovered.weighted, 1.0, places=6)

    def test_given_no_tokens_when_seeding_then_control_recovers_nothing(self) -> None:
        self.assertEqual(seeding_attack({}, [], {"가": 1.0}, (1,)), {})


class GivenTheReconstructionTest(unittest.TestCase):
    def test_given_bigram_tokens_when_reconstruct_then_name_in_order(self) -> None:
        model, table = _model_and_table(["홍길동"])
        predicted = {token: gram for token, gram in model.items()}
        self.assertEqual(reconstruct(table[0], predicted), "홍길동")

    def test_given_true_mapping_when_reconstruction_attack_then_top1(self) -> None:
        model, table = _model_and_table(NAMES)
        predicted = {token: gram for token, gram in model.items()}
        candidates = [*NAMES, "김민준", "이서연"]
        top1, top5 = reconstruction_attack(table, predicted, candidates, NAMES, DEFAULT_ORDERS)
        self.assertAlmostEqual(top1, 1.0, places=9)
        self.assertAlmostEqual(top5, 1.0, places=9)


if __name__ == "__main__":
    unittest.main()
