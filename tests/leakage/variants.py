#!/usr/bin/env python3
"""Token-index variants and the utility model (design amendment A17).

Each variant is a way the side table could be built, and each carries its
leakage number *and* a utility number — leakage without utility is not a result
(A17, "Variants"). The utility model is explicit because there is no real
workload: a query is answerable if all its tokens are in the table, and its
candidate set is the rows that contain them.

V6 (per-row salt / Bloom) is structurally impossible for an index that must be
searched by token, so it is recorded and not built.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from metrics import Table, shared_set_stats, unique_row_fraction
from names import Person
from tokens import TokenModel, ngrams


@dataclass(frozen=True)
class Variant:
    name: str
    orders: tuple[int, ...]
    bits: int = 16
    homophonic: int = 1
    padding: int = 0
    documented_only: bool = False


VARIANTS: dict[str, Variant] = {
    "V0": Variant("V0", (1, 2, 3)),
    "V1": Variant("V1", (2,)),
    "V2": Variant("V2", (3,)),
    "V3-8": Variant("V3-8", (1, 2, 3), bits=8),
    "V3-12": Variant("V3-12", (1, 2, 3), bits=12),
    "V3-16": Variant("V3-16", (1, 2, 3), bits=16),
    "V4": Variant("V4", (1, 2, 3), homophonic=4),
    "V5": Variant("V5", (1, 2, 3), padding=8),
    "V6": Variant("V6", (1, 2, 3), documented_only=True),
    "V7": Variant("V7", ()),
}

DUMMY_BASE = 1 << 40  # padding tokens live above any b-bit token (b <= 16)


def build_table(people: Sequence[Person], variant: Variant, seed: int) -> tuple[TokenModel, Table]:
    """Build the side table for one variant. V6 is refused, not built."""
    if variant.documented_only:
        raise ValueError(f"{variant.name} is documented only and cannot be built")
    model = TokenModel(variant.bits, seed)
    rows: list[tuple[int, ...]] = []
    for person in people:
        text = person.full_name()
        tokens: set[int] = set()
        occurrence = 0
        for order in variant.orders:
            for gram in ngrams(text, order):
                base = model.token(gram)
                if variant.homophonic > 1:
                    base = base * variant.homophonic + (occurrence % variant.homophonic)
                tokens.add(base)
                occurrence += 1
        for index in range(variant.padding):
            tokens.add(DUMMY_BASE + index)
        rows.append(tuple(sorted(tokens)))
    return model, tuple(rows)


def _row_index(table: Table) -> dict[int, list[int]]:
    index: dict[int, list[int]] = {}
    for row_id, row in enumerate(table):
        for token in row:
            index.setdefault(token, []).append(row_id)
    return index


def _candidate_rows(index: Mapping[int, list[int]], options: set[int]) -> set[int]:
    rows: set[int] = set()
    for token in options:
        rows.update(index[token])
    return rows


def utility(
    variant: Variant, model: TokenModel, table: Table, queries: Sequence[str]
) -> dict[str, float]:
    """Answerability and candidate-set size for an explicit query model."""
    index = _row_index(table)
    universe = set(index)
    answered = 0
    fractions: list[float] = []
    for query in queries:
        option_sets: list[set[int]] = []
        for order in variant.orders:
            for gram in ngrams(query, order):
                base = model.token(gram)
                if variant.homophonic > 1:
                    option_sets.append(
                        {base * variant.homophonic + k for k in range(variant.homophonic)}
                    )
                else:
                    option_sets.append({base})
        if not option_sets or not all(options & universe for options in option_sets):
            continue
        answered += 1
        candidate_rows = set(range(len(table)))
        for options in option_sets:
            candidate_rows &= _candidate_rows(index, options & universe)
        fractions.append(len(candidate_rows) / len(table))
    total = len(queries)
    return {
        "answered_fraction": answered / total if total else 0.0,
        "mean_candidate_fraction": sum(fractions) / len(fractions) if fractions else 1.0,
        "mean_row_tokens": sum(len(row) for row in table) / len(table) if table else 0.0,
        "distinct_tokens": len(universe),
    }


def query_model(people: Sequence[Person], per_kind: int) -> list[str]:
    """The three mixes A17 names: whole name, given name, surname, one syllable."""
    queries: list[str] = []
    for person in people[:per_kind]:
        queries.extend([person.full_name(), person.given, person.surname, person.given[0]])
    return queries


def variant_summary(variant: Variant, model: TokenModel, table: Table) -> Mapping[str, object]:
    return {
        "variant": variant.name,
        "orders": list(variant.orders),
        "bits": variant.bits,
        "homophonic": variant.homophonic,
        "padding": variant.padding,
        "unique_row_fraction": unique_row_fraction(table),
        "shared_set": shared_set_stats(table),
    }
