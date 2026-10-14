#!/usr/bin/env python3
"""GWT tests for the synthetic name generator (amendment A17)."""

from __future__ import annotations

import random
import unittest

from names import KO_LANGUAGE, LATIN_LANGUAGE, Dist, NameGenerator


def _surname_counts(generator: NameGenerator, count: int) -> dict[str, int]:
    dist = generator.surname_dist()
    rng = random.Random(1234)  # noqa: S311 - synthetic names, not key material
    counts: dict[str, int] = {}
    for _ in range(count):
        name = dist.sample(rng)
        counts[name] = counts.get(name, 0) + 1
    return counts


def _mass(dist: Dist) -> float:
    return sum(weight for _, weight in dist.observed()) + dist.tail


class GivenAKoreanGeneratorTest(unittest.TestCase):
    def test_given_korean_when_generating_then_surnames_are_hangul(self) -> None:
        people = NameGenerator(KO_LANGUAGE, 1990, 7).generate(200)
        surnames = [p.surname for p in people]
        self.assertTrue(all(all("\uac00" <= ch <= "\ud7a3" for ch in s) for s in surnames))

    def test_given_korean_when_full_name_then_surname_first(self) -> None:
        person = NameGenerator(KO_LANGUAGE, 1990, 7).generate(1)[0]
        self.assertEqual(person.full_name(), person.surname + person.given)

    def test_given_latin_when_full_name_then_given_first(self) -> None:
        person = NameGenerator(LATIN_LANGUAGE, 1990, 7).generate(1)[0]
        self.assertEqual(person.full_name(), f"{person.given} {person.surname}")


class GivenASeedTest(unittest.TestCase):
    def test_given_same_seed_when_generating_twice_then_identical(self) -> None:
        first = NameGenerator(KO_LANGUAGE, 1990, 42).generate(50)
        second = NameGenerator(KO_LANGUAGE, 1990, 42).generate(50)
        self.assertEqual(first, second)

    def test_given_different_seeds_when_generating_then_different(self) -> None:
        first = NameGenerator(KO_LANGUAGE, 1990, 1).generate(50)
        second = NameGenerator(KO_LANGUAGE, 1990, 2).generate(50)
        self.assertNotEqual(first, second)


class GivenASurnameDistTest(unittest.TestCase):
    def test_given_korean_when_sampling_many_then_kim_is_the_most_common(self) -> None:
        counts = _surname_counts(NameGenerator(KO_LANGUAGE, 1990, 3), 20_000)
        self.assertEqual(max(counts, key=lambda s: counts[s]), "김")

    def test_given_latin_when_sampling_many_then_tail_is_drawn(self) -> None:
        # Latin's committed top-60 covers only 13% of the census, so most draws must be
        # the tail — the bug this test exists to catch drew the tail 0 times.
        dist = NameGenerator(LATIN_LANGUAGE, 1990, 5).surname_dist()
        rng = random.Random(7)  # noqa: S311 - synthetic names, not key material
        observed = {name for name, _ in dist.observed()}
        draws = [dist.sample(rng) for _ in range(20_000)]
        tail_fraction = sum(1 for name in draws if name not in observed) / len(draws)
        self.assertAlmostEqual(tail_fraction, dist.tail, delta=0.02)

    def test_given_ko_and_latin_when_total_mass_then_one(self) -> None:
        ko = NameGenerator(KO_LANGUAGE, 1990, 0).surname_dist()
        latin = NameGenerator(LATIN_LANGUAGE, 1990, 0).surname_dist()
        self.assertAlmostEqual(_mass(ko), 1.0, places=9)
        self.assertAlmostEqual(_mass(latin), 1.0, places=9)

    def test_given_truncate_when_top_k_then_tail_absorbs_the_moved_mass(self) -> None:
        dist = NameGenerator(KO_LANGUAGE, 1990, 0).surname_dist()
        moved = sum(weight for _, weight in dist.observed()[10:])
        self.assertAlmostEqual(dist.truncate(10).tail, dist.tail + moved, places=9)

    def test_given_noised_when_total_mass_then_one(self) -> None:
        dist = NameGenerator(LATIN_LANGUAGE, 1990, 0).surname_dist()
        rng = random.Random(9)  # noqa: S311 - synthetic names, not key material
        self.assertAlmostEqual(_mass(dist.noised(rng, 0.5)), 1.0, places=9)


if __name__ == "__main__":
    unittest.main()
