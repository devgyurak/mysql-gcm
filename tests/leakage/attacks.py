#!/usr/bin/env python3
"""Attacks and baselines for the n-gram token experiment (design amendment A17).

Attack 1 is the frequency rank / maximum-likelihood matching: rank the observed
tokens by how often they occur, rank the candidate n-grams by their public
frequency, and match them. The assignment is solved with SciPy's Hungarian
algorithm on the top-K tokens and greedily by rank for the rest (A17, "Experiment
harness conventions").

Attack 2 refines that match by the n-gram co-occurrence graph; attack 3 seeds from
m rows whose plaintext the attacker knows or injected; attack 4 reconstructs the
name from the mapped tokens, as retrieval with a top-1/top-5 result.

The baselines B0 (length and prior only) and B1/B1' (whole-name and split
`gcm_encrypt_det` equality) are measured here too, because every result is
reported as an increment over them.
"""

from __future__ import annotations

import math
import random
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import TypeVar

import numpy as np
from metrics import Table, token_frequency
from names import Dist
from scipy.optimize import linear_sum_assignment
from tokens import ngrams

T = TypeVar("T")
_Item = TypeVar("_Item")

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


def _pair_counts(groups: Iterable[Sequence[_Item]], index: Mapping[_Item, int]) -> np.ndarray:
    """Co-occurrence counts of the items that appear together in one group."""
    size = len(index)
    matrix = np.zeros((size, size))
    for group in groups:
        present = sorted({index[item] for item in group if item in index})
        for a in present:
            for b in present:
                if a != b:
                    matrix[a, b] += 1.0
    return matrix


def _cosine(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    left_norm = np.linalg.norm(left, axis=1, keepdims=True)
    right_norm = np.linalg.norm(right, axis=1, keepdims=True)
    safe_left = np.where(left_norm == 0, 1.0, left_norm)
    safe_right = np.where(right_norm == 0, 1.0, right_norm)
    return (left / safe_left) @ (right / safe_right).T


def cooccurrence_attack(
    table: Table,
    prior_names: Sequence[str],
    prior_freq: NgramFreq,
    orders: Sequence[int],
    top_k: int = 40,
    sample: int = 2000,
) -> dict[int, str]:
    """Attack 2: refine the frequency match by the n-gram co-occurrence graph.

    Rows are vectors of the tokens they contain; for each token the neighbours it
    co-occurs with are its profile. The candidate n-gram with the most similar
    public profile is chosen (cosine similarity, Hungarian assignment). The
    profile is bounded to the top-K tokens and a row sample so the attack stays
    polynomial on 300k rows.
    """
    observed = token_frequency(table)
    top_tokens = sorted(observed, key=lambda t: (-observed[t], t))[:top_k]
    top_grams = sorted(prior_freq, key=lambda g: (-prior_freq[g], g))[:top_k]
    if not top_tokens or not top_grams:
        return {}
    token_index = {token: i for i, token in enumerate(top_tokens)}
    gram_index = {gram: i for i, gram in enumerate(top_grams)}
    observed_profile = _pair_counts(
        ([t for t in row if t in token_index] for row in table[:sample]), token_index
    )
    prior_profile = _pair_counts(
        (
            [g for order in orders for g in ngrams(name, order) if g in gram_index]
            for name in prior_names[:sample]
        ),
        gram_index,
    )
    similarity = _cosine(observed_profile, prior_profile)
    row_ind, col_ind = linear_sum_assignment(-similarity)
    predicted = {
        top_tokens[int(r)]: top_grams[int(c)] for r, c in zip(row_ind, col_ind, strict=True)
    }
    fallback = frequency_attack(observed, prior_freq)
    for token in observed:
        predicted.setdefault(token, fallback.get(token, ""))
    return predicted


def seeding_attack(
    observed: TokenFreq,
    known: Sequence[tuple[tuple[int, ...], str]],
    prior_freq: NgramFreq,
    orders: Sequence[int],
) -> dict[int, str]:
    """Attack 3: seed from m rows whose plaintext the attacker knows or injected.

    Each known row aligns its tokens to the n-grams of the known name with a
    within-row Hungarian match on frequency rank; the remaining tokens fall back
    to the frequency match.
    """
    grams_rank = {g: i for i, g in enumerate(sorted(prior_freq, key=lambda g: (-prior_freq[g], g)))}
    tokens_rank = {t: i for i, t in enumerate(sorted(observed, key=lambda t: (-observed[t], t)))}
    predicted: dict[int, str] = {}
    for row, name in known:
        grams = sorted({g for order in orders for g in ngrams(name, order) if g in grams_rank})
        tokens = [t for t in row if t in tokens_rank]
        if not grams or not tokens:
            continue
        cost = np.array(
            [[abs(tokens_rank[t] - grams_rank[g]) for g in grams] for t in tokens[: len(grams)]]
        )
        row_ind, col_ind = linear_sum_assignment(cost)
        predicted.update(
            {tokens[int(r)]: grams[int(c)] for r, c in zip(row_ind, col_ind, strict=True)}
        )
    fallback = frequency_attack(observed, prior_freq)
    for token in observed:
        predicted.setdefault(token, fallback.get(token, ""))
    return predicted


def reconstruct(row_tokens: Sequence[int], predicted: Mapping[int, str]) -> str:
    """Attack 4: order a row's bigram tokens into a name via the char path."""
    bigrams = [predicted[t] for t in row_tokens if len(predicted.get(t, "")) == 2]
    edges: dict[str, list[str]] = {}
    in_degree: Counter[str] = Counter()
    for bigram in bigrams:
        edges.setdefault(bigram[0], []).append(bigram[1])
        in_degree[bigram[1]] += 1
    starts = [char for char in edges if in_degree[char] == 0]
    start = starts[0] if starts else (bigrams[0][0] if bigrams else "")
    chars = [start] if start else []
    current = start
    while current in edges and edges[current]:
        current = edges[current].pop(0)
        chars.append(current)
    if len(chars) > 1:
        return "".join(chars)
    singles = [predicted[t] for t in row_tokens if len(predicted.get(t, "")) == 1]
    return "".join(singles)


def reconstruction_attack(
    table: Table,
    predicted: Mapping[int, str],
    candidates: Sequence[str],
    truth: Sequence[str],
    orders: Sequence[int],
    top_k: int = 5,
) -> tuple[float, float]:
    """Attack 4 as retrieval: rank candidate names by token-set overlap; top-1/top-5."""
    candidate_sets = [
        (name, {g for order in orders for g in ngrams(name, order)}) for name in candidates
    ]
    top1 = top5 = 0
    for row, real in zip(table, truth, strict=True):
        present = {predicted[t] for t in row if t in predicted}
        ranked = sorted(candidate_sets, key=lambda pair: -len(pair[1] & present))
        if ranked and ranked[0][0] == real:
            top1 += 1
        if any(ranked[i][0] == real for i in range(min(top_k, len(ranked)))):
            top5 += 1
    n = len(truth)
    return (top1 / n if n else 0.0, top5 / n if n else 0.0)
