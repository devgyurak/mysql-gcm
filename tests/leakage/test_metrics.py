#!/usr/bin/env python3
"""GWT tests for the leakage metrics (amendment A17)."""

from __future__ import annotations

import unittest

from metrics import (
    reverse_injection,
    shared_set_stats,
    surname_accuracy,
    token_frequency,
    token_recovery,
    unique_row_fraction,
)


class GivenATableTest(unittest.TestCase):
    def test_given_table_when_token_frequency_then_counts_rows_not_occurrences(self) -> None:
        table = ((1, 1, 2), (2, 3))
        self.assertEqual(token_frequency(table), {1: 1, 2: 2, 3: 1})

    def test_given_table_when_unique_row_fraction_then_distinct_sets_only(self) -> None:
        table = ((1, 2), (1, 2), (3,))
        self.assertAlmostEqual(unique_row_fraction(table), 1 / 3, places=9)

    def test_given_repeated_set_when_shared_stats_then_largest_set(self) -> None:
        stats = shared_set_stats(((1, 2), (1, 2), (3,)))
        self.assertEqual(stats["largest_shared_set"], 2)
        self.assertAlmostEqual(float(stats["rows_in_shared_set_fraction"]), 2 / 3, places=9)


class GivenARecoveryTest(unittest.TestCase):
    def test_given_reverse_injection_when_tokens_collide_then_one_token_two_grams(self) -> None:
        truth = reverse_injection([(5, "가"), (5, "나")])
        self.assertEqual(truth[5], frozenset({"가", "나"}))

    def test_given_all_correct_when_recovery_then_one(self) -> None:
        truth = {1: frozenset({"가"}), 2: frozenset({"나"})}
        recovery = token_recovery({1: "가", 2: "나"}, truth, {1: 1, 2: 3})
        self.assertAlmostEqual(recovery.unique, 1.0, places=9)
        self.assertAlmostEqual(recovery.weighted, 1.0, places=9)

    def test_given_one_wrong_when_weighted_then_occurrence_weighted(self) -> None:
        truth = {1: frozenset({"가"}), 2: frozenset({"나"})}
        recovery = token_recovery({1: "가", 2: "다"}, truth, {1: 1, 2: 3})
        self.assertAlmostEqual(recovery.unique, 0.5, places=9)
        self.assertAlmostEqual(recovery.weighted, 0.25, places=9)


class GivenASurnameGuessTest(unittest.TestCase):
    def test_given_guesses_when_accuracy_then_fraction_matching(self) -> None:
        self.assertAlmostEqual(surname_accuracy(["김", "이"], ["김", "박"]), 0.5, places=9)


if __name__ == "__main__":
    unittest.main()
