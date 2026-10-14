#!/usr/bin/env python3
"""Leakage metrics for the n-gram token experiment (design amendment A17).

Attack-independent measurements are computed here alongside the attack results,
because "the attack failed" is not evidence of safety (A17, "Metrics and
baselines").
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

Row = tuple[int, ...]
Table = tuple[Row, ...]


def token_frequency(table: Table) -> dict[int, int]:
    """How often each token occurs across rows (a token counts once per row)."""
    return dict(Counter(token for row in table for token in set(row)))


def unique_row_fraction(table: Table) -> float:
    """Fraction of rows whose token set no other row shares."""
    signatures = Counter(row for row in table)
    unique = sum(1 for row in table if signatures[row] == 1)
    return unique / len(table) if table else 0.0


def shared_set_stats(table: Table) -> dict[str, float | int]:
    """Attack-independent structure: how much rows share an identical token set."""
    signatures = Counter(row for row in table)
    sizes = sorted(signatures.values(), reverse=True)
    largest = sizes[0] if sizes else 0
    in_multi = sum(size for size in sizes if size > 1)
    return {
        "distinct_token_sets": len(signatures),
        "largest_shared_set": largest,
        "rows_in_shared_set": in_multi,
        "rows_in_shared_set_fraction": in_multi / len(table) if table else 0.0,
    }


@dataclass(frozen=True)
class Recovery:
    """Token recovery, over unique tokens and weighted by occurrence."""

    unique: float
    weighted: float
    predicted: int
    correct_unique: int


def token_recovery(
    predicted: Mapping[int, str],
    truth: Mapping[int, frozenset[str]],
    frequency: Mapping[int, int],
) -> Recovery:
    """Fraction of tokens whose predicted n-gram is one the token really carries."""
    tokens = list(truth)
    total_weight = sum(frequency.get(t, 0) for t in tokens)
    correct = [t for t in tokens if predicted.get(t) in truth[t]]
    unique = len(correct) / len(tokens) if tokens else 0.0
    weighted = sum(frequency.get(t, 0) for t in correct) / total_weight if total_weight else 0.0
    return Recovery(
        unique=unique, weighted=weighted, predicted=len(tokens), correct_unique=len(correct)
    )


def surname_accuracy(predicted: Sequence[str], truth: Sequence[str]) -> float:
    pairs = list(zip(predicted, truth, strict=True))
    correct = sum(1 for guess, real in pairs if guess == real)
    return correct / len(pairs) if pairs else 0.0


def reverse_injection(model_tokens: Iterable[tuple[int, str]]) -> dict[int, frozenset[str]]:
    """Ground truth a token carries: every n-gram the injection mapped to it."""
    truth: dict[int, set[str]] = {}
    for token, ngram in model_tokens:
        truth.setdefault(token, set()).add(ngram)
    return {token: frozenset(ngrams) for token, ngrams in truth.items()}
