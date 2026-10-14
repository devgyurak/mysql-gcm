#!/usr/bin/env python3
"""The deterministic keyed n-gram token model (design amendment A17).

A17 models the token function directly rather than computing it: whatever the
PRF is, the attacker sees the same ``(row, token)`` graph, so the model here is a
**random injection** of the n-gram space — an injective relabelling — truncated
to ``b`` bits, which behaves as a random function below the space's entropy.

**No key and no cryptographic operation.** The harness holds no key material.
"""

from __future__ import annotations

import random
from collections.abc import Iterable, Sequence

DEFAULT_ORDERS: tuple[int, ...] = (1, 2, 3)
DEFAULT_BITS = 16


def ngrams(text: str, order: int) -> list[str]:
    """The ``order``-grams of ``text`` as character substrings."""
    return [text[i : i + order] for i in range(len(text) - order + 1)]


class TokenModel:
    """A seeded random injection n-gram -> b-bit token."""

    def __init__(self, bits: int, seed: int) -> None:
        self.bits = bits
        self._rng = random.Random(seed)  # noqa: S311 - token labels, not key material
        self._map: dict[str, int] = {}

    def token(self, ngram: str) -> int:
        token = self._map.get(ngram)
        if token is None:
            token = self._rng.getrandbits(self.bits)
            self._map[ngram] = token
        return token

    def row_tokens(self, text: str, orders: Sequence[int]) -> tuple[int, ...]:
        """The deduplicated token multiset of one row, sorted for determinism."""
        seen = {self.token(g) for order in orders for g in ngrams(text, order)}
        return tuple(sorted(seen))

    def items(self) -> tuple[tuple[int, str], ...]:
        """Every ``(token, n-gram)`` pair the injection has assigned."""
        return tuple((token, ngram) for ngram, token in self._map.items())


def token_table(
    model: TokenModel, texts: Iterable[str], orders: Sequence[int]
) -> tuple[tuple[int, ...], ...]:
    return tuple(model.row_tokens(text, orders) for text in texts)
