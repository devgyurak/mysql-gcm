#!/usr/bin/env python3
"""Synthetic name generation for the leakage experiment (design amendment A17).

Builds synthetic Korean and Latin people from the committed public aggregates in
``tests/leakage/data`` plus a modelled tail, so the experiment has a named ground
truth to attack. A17 models the token function directly, so this module performs
**no cryptographic operation and holds no key material**.

Every distribution keeps the mass the committed top-K does not cover as a
``tail``: a draw from the tail is a name the attacker cannot name from the public
statistics alone, which is what makes the tail worth keeping rather than
renormalising away. The tail *pools* are modelled (recombined syllables), not a
claim about any real frequency.
"""

from __future__ import annotations

import json
import random
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

DATA_DIR = Path(__file__).with_name("data")

KO_LANGUAGE = "ko"
LATIN_LANGUAGE = "latin"

# Modelled tails: the names the committed top-K does not cover. Deliberately
# ordinary-looking but rare, so the attacker can neither see them in the prior nor
# guess them from frequency alone.
KO_SURNAME_TAIL: tuple[str, ...] = tuple(
    "팽 승 간 갈 감 견 계 곡 궁 근 묵 맹 제 제갈 남궁 선우 사공 황보 독고".split()
)
KO_GIVEN_TAIL: tuple[str, ...] = tuple(
    "가온 다온 라온 마루 보람 슬기 한결 나래 다움 여울 초롱 "
    "하늬 고운 빛나 아름 로운 해든 별하 이든 로아".split()
)
LATIN_SURNAME_TAIL: tuple[str, ...] = tuple(
    "Yamamoto Kowalski Novak Petrov Silva Costa Haas Krause Ivanov Rossi "
    "Dubois Nakamura Khan Ali Haddad Okafor Ng Tran Santos Fischer".split()
)
LATIN_GIVEN_TAIL: tuple[str, ...] = tuple(
    "Aurora Bodhi Caspian Delphine Elias Freya Gideon Hazel Idris Juniper Kai "
    "Leilani Marcus Nadia Orion Priya Quinn Rowan Soren Talia".split()
)


def _read_data(name: str) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads((DATA_DIR / name).read_text(encoding="utf-8")))


@dataclass(frozen=True)
class Person:
    """One synthetic person. ``full_name`` follows the language's name order."""

    language: str
    surname: str
    given: str
    sex: str
    birth_year: int

    def full_name(self) -> str:
        if self.language == KO_LANGUAGE:
            return self.surname + self.given
        return f"{self.given} {self.surname}"


class Dist:
    """A categorical distribution over observed names plus a modelled tail."""

    def __init__(
        self,
        items: Sequence[tuple[str, float]],
        tail: float,
        tail_pool: Sequence[str],
    ) -> None:
        self._items: tuple[tuple[str, float], ...] = tuple(items)
        self.tail = tail
        self._tail_pool: tuple[str, ...] = tuple(tail_pool)

    def observed(self) -> tuple[tuple[str, float], ...]:
        return self._items

    def top_k(self, k: int) -> tuple[str, ...]:
        return tuple(name for name, _ in self._items[:k])

    def prob(self, name: str) -> float:
        for observed, weight in self._items:
            if observed == name:
                return weight
        return 0.0

    def sample(self, rng: random.Random) -> str:
        draw = rng.random()
        cumulative = 0.0
        for name, weight in self._items:
            cumulative += weight
            if draw < cumulative:
                return name
        return rng.choice(self._tail_pool)

    def truncate(self, k: int) -> Dist:
        kept = self._items[:k]
        moved = sum(weight for _, weight in self._items[k:])
        return Dist(kept, self.tail + moved, self._tail_pool)

    def noised(self, rng: random.Random, alpha: float) -> Dist:
        """Dirichlet noise on the observed weights, keeping their shape and the tail."""
        observed_mass = 1.0 - self.tail
        draws = [weight * rng.gammavariate(alpha, 1.0) for _, weight in self._items]
        total = sum(draws)
        items = [
            (name, observed_mass * draw / total)
            for (name, _), draw in zip(self._items, draws, strict=True)
        ]
        return Dist(items, self.tail, self._tail_pool)


class NameGenerator:
    """Draws synthetic people from a committed distribution for one cohort."""

    COHORTS: tuple[int, ...] = (1960, 1990)

    def __init__(self, language: str, cohort: int, seed: int) -> None:
        self.language = language
        self.cohort = cohort
        self._rng = random.Random(seed)  # noqa: S311 - synthetic names, not key material

    def surname_dist(self) -> Dist:
        if self.language == KO_LANGUAGE:
            data = _read_data("ko_surnames.json")
            total = int(data["population"])
            items = [(str(s), int(c) / total) for s, c in data["surnames"]]
            tail = 1.0 - sum(weight for _, weight in items)
            return Dist(items, tail, KO_SURNAME_TAIL)
        data = _read_data("latin_surnames.json")
        total = int(data["population"])
        items = [(str(s), int(c) / total) for s, c in data["surnames"]]
        tail = 1.0 - sum(weight for _, weight in items)
        return Dist(items, tail, LATIN_SURNAME_TAIL)

    def given_dist(self, sex: str) -> Dist:
        if self.language == KO_LANGUAGE:
            data = _read_data("ko_given.json")
            cohorts = data["cohorts"]
            assert isinstance(cohorts, dict)  # noqa: S101 - fixed data shape
            key = str(min(self.COHORTS, key=lambda c: abs(c - self.cohort)))
            pairs = cohorts[key][sex]
            items = [(str(n), float(w)) for n, w in pairs]
            tail = 1.0 - sum(weight for _, weight in items)
            return Dist(items, tail, KO_GIVEN_TAIL)
        data = _read_data("latin_given.json")
        pairs = data[sex]
        items = [(str(n), float(w)) for n, w in pairs]
        tail = 1.0 - sum(weight for _, weight in items)
        return Dist(items, tail, LATIN_GIVEN_TAIL)

    def generate(self, count: int) -> list[Person]:
        surnames = self.surname_dist()
        male = self.given_dist("male")
        female = self.given_dist("female")
        people: list[Person] = []
        for _ in range(count):
            sex = "male" if self._rng.random() < 0.5 else "female"
            given = (male if sex == "male" else female).sample(self._rng)
            people.append(
                Person(
                    language=self.language,
                    surname=surnames.sample(self._rng),
                    given=given,
                    sex=sex,
                    birth_year=self.cohort + self._rng.randint(-5, 5),
                )
            )
        return people
