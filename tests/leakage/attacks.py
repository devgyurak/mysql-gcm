#!/usr/bin/env python3
"""Attacks and baselines for the n-gram token experiment (design amendment A17).

Attack 1 is the frequency rank / maximum-likelihood matching: rank the observed
tokens by how often they occur, rank the candidate n-grams by their public
frequency, and match them. The assignment is solved with SciPy's Hungarian
algorithm on the top-K tokens and greedily by rank for the rest (A17, "Experiment
harness conventions").

The baselines B0 (length and prior only) and B1/B1' (whole-name and split
`gcm_encrypt_det` equality) are measured here too, because every result is
reported as an increment over them.
"""

from __future__ import annotations

import math
import random
from collections import Counter
from collections.abc import Mapping, Sequence

import numpy as np
from names import Dist
from scipy.optimize import linear_sum_assignment
from tokens import ngrams

TokenFreq = Mapping[int, int]
NgramFreq = Mapping[str, float]


def frequency_attack(observed: TokenFreq, prior: NgramFreq, top_k: int = 200) -> dict[int, str]:
    """Match tokens to n-grams by frequency: Hungarian on top-K, rank for the rest."""
    tokens = sorted(observed, key=lambda t: (-observed[t], t))
    candidates = sorted(prior, key=lambda g: (-prior[g], g))
    if not tokens or not candidates:
        return {}
    matched_tokens = tokens[: min(top_k, len(tokens))]
    matched_candidates = candidates[: min(top_k, len(candidates), len(tokens))]
    observed_total = sum(observed.values())
    cost = np.array(
        [
            [
                abs(math.log(observed[t] / observed_total) - math.log(max(prior[g], 1e-12)))
                for g in matched_candidates
            ]
            for t in matched_tokens
        ]
    )
    row_ind, col_ind = linear_sum_assignment(cost)
    predicted = {
        matched_tokens[int(r)]: matched_candidates[int(c)]
        for r, c in zip(row_ind, col_ind, strict=True)
    }
    for index, token in enumerate(tokens):
        predicted.setdefault(token, candidates[min(index, len(candidates) - 1)])
    return predicted


def prior_surname_guess(dist: Dist) -> str:
    """B0: the attacker's best surname with no tokens is the prior's arg-max."""
    return max(dist.observed(), key=lambda item: item[1])[0]


def sample_names(
    surnames: Dist, male: Dist, female: Dist, count: int, rng: random.Random
) -> list[str]:
    """Draw whole names from the perturbed public statistics."""
    names: list[str] = []
    for _ in range(count):
        given = male if rng.random() < 0.5 else female
        names.append(surnames.sample(rng) + given.sample(rng))
    return names


def prior_full_name_frequency(names: Sequence[str]) -> dict[str, float]:
    """The prior over whole names, from the sampled public statistics."""
    counts: Counter[str] = Counter(names)
    total = sum(counts.values())
    return {name: count / total for name, count in counts.items()}


def ngram_frequency(names: Sequence[str], orders: Sequence[int]) -> dict[str, float]:
    """The public n-gram frequency prior over ``orders``, normalised."""
    counts: Counter[str] = Counter()
    for name in names:
        for order in orders:
            counts.update(ngrams(name, order))
    total = sum(counts.values())
    return {gram: count / total for gram, count in counts.items()}


def prior_top1(full_name_freq: Mapping[str, float]) -> str:
    return max(full_name_freq, key=lambda name: full_name_freq[name])


def top1_accuracy(predicted: str, truth: Sequence[str]) -> float:
    correct = sum(1 for name in truth if name == predicted)
    return correct / len(truth) if truth else 0.0


def equality_stats(full_names: Sequence[str]) -> dict[str, float | int]:
    """B1 and B1': what whole-name and split deterministic equality expose."""
    full = Counter(full_names)
    surnames = Counter(name[0] for name in full_names)
    givens = Counter(name[1:] for name in full_names)
    n = len(full_names)
    return {
        "distinct_full_names": len(full),
        "unique_full_fraction": sum(1 for c in full.values() if c == 1) / n,
        "distinct_surnames": len(surnames),
        "distinct_given_names": len(givens),
        "unique_surname_fraction": sum(1 for c in surnames.values() if c == 1) / n,
        "unique_given_fraction": sum(1 for c in givens.values() if c == 1) / n,
    }
