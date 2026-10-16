#!/usr/bin/env python3
"""GWT tests for the token-index variants and the utility model (amendment A17)."""

from __future__ import annotations

import unittest

from names import KO_LANGUAGE, NameGenerator
from variants import VARIANTS, build_table, query_model, utility

PEOPLE = NameGenerator(KO_LANGUAGE, 1990, 0).generate(50)


def _row_lengths(table: tuple[tuple[int, ...], ...]) -> list[int]:
    return [len(row) for row in table]


class GivenAVariantTest(unittest.TestCase):
    def test_given_v7_when_built_then_no_row_has_a_token(self) -> None:
        _model, table = build_table(PEOPLE, VARIANTS["V7"], 0)
        self.assertEqual(set(_row_lengths(table)), {0})

    def test_given_v6_when_built_then_refused_as_documented_only(self) -> None:
        with self.assertRaises(ValueError):
            build_table(PEOPLE, VARIANTS["V6"], 0)

    def test_given_v3_8_when_built_then_tokens_fit_eight_bits(self) -> None:
        _model, table = build_table(PEOPLE, VARIANTS["V3-8"], 0)
        self.assertTrue(all(token < 256 for row in table for token in row))

    def test_given_v5_when_built_then_every_row_has_the_same_length(self) -> None:
        _model, table = build_table(PEOPLE, VARIANTS["V5"], 0)
        self.assertEqual(len(set(_row_lengths(table))), 1)

    def test_given_v0_when_built_then_the_mapping_is_collision_free(self) -> None:
        model, table = build_table(PEOPLE, VARIANTS["V0"], 0)
        tokens = [t for row in table for t in row]
        self.assertEqual(len(set(tokens)), len({gram for _token, gram in model.items()}))

    def test_given_v4_when_built_then_more_distinct_tokens_than_v3_16(self) -> None:
        _model0, table0 = build_table(PEOPLE, VARIANTS["V3-16"], 0)
        _model4, table4 = build_table(PEOPLE, VARIANTS["V4"], 0)
        self.assertGreater(
            len({t for row in table4 for t in row}), len({t for row in table0 for t in row})
        )


class GivenTheUtilityModelTest(unittest.TestCase):
    def test_given_v0_when_utility_then_answerable_and_bounded(self) -> None:
        model, table = build_table(PEOPLE, VARIANTS["V0"], 0)
        result = utility(VARIANTS["V0"], model, table, query_model(PEOPLE, 50))
        self.assertGreater(result["answered_fraction"], 0.0)
        self.assertLessEqual(result["mean_candidate_fraction"], 1.0)

    def test_given_v7_when_utility_then_nothing_is_answerable(self) -> None:
        model, table = build_table(PEOPLE, VARIANTS["V7"], 0)
        result = utility(VARIANTS["V7"], model, table, query_model(PEOPLE, 50))
        self.assertEqual(result["answered_fraction"], 0.0)

    def test_given_people_when_query_model_then_four_kinds_each(self) -> None:
        self.assertEqual(len(query_model(PEOPLE, 10)), 40)


if __name__ == "__main__":
    unittest.main()
