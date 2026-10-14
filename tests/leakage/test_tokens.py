#!/usr/bin/env python3
"""GWT tests for the token model (amendment A17)."""

from __future__ import annotations

import unittest

from tokens import TokenModel, ngrams, token_table


class GivenTextTest(unittest.TestCase):
    def test_given_text_when_unigrams_then_characters(self) -> None:
        self.assertEqual(ngrams("홍길동", 1), ["홍", "길", "동"])

    def test_given_text_when_bigrams_then_adjacent_pairs(self) -> None:
        self.assertEqual(ngrams("홍길동", 2), ["홍길", "길동"])

    def test_given_short_text_when_bigram_then_empty(self) -> None:
        self.assertEqual(ngrams("김", 2), [])


class GivenTokenModelTest(unittest.TestCase):
    def test_given_model_when_same_ngram_twice_then_same_token(self) -> None:
        model = TokenModel(16, 0)
        self.assertEqual(model.token("김"), model.token("김"))

    def test_given_model_when_repeated_ngram_then_row_tokens_deduplicate(self) -> None:
        model = TokenModel(16, 0)
        self.assertEqual(model.row_tokens("가가", (1,)), (model.token("가"),))

    def test_given_model_when_bits_two_then_tokens_fit(self) -> None:
        model = TokenModel(2, 0)
        table = token_table(model, ["가나다", "라마"], (1,))
        self.assertTrue(all(0 <= token < 4 for row in table for token in row))


if __name__ == "__main__":
    unittest.main()
