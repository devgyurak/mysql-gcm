#!/usr/bin/env python3
"""Run one leakage configuration (design amendment A17).

Builds synthetic names, tokenises them, runs attack 1 (frequency matching) and
measures it against baselines B0 and B1/B1'. Results are JSON on stdout and a
human summary on stderr (stack-python rule); the caller commits the JSON with its
seeds and command, and CI runs only a small smoke.

No cryptographic operation and no key material: the token function is modelled
directly, so there is no key to hold (A17, "What is modelled, and what is not").
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections.abc import Sequence

from attacks import (
    cooccurrence_attack,
    equality_stats,
    frequency_attack,
    ngram_frequency,
    prior_full_name_frequency,
    prior_surname_guess,
    reconstruction_attack,
    sample_names,
    seeding_attack,
    top1_accuracy,
)
from metrics import (
    reverse_injection,
    shared_set_stats,
    surname_accuracy,
    token_frequency,
    token_recovery,
    unique_row_fraction,
)
from names import NameGenerator
from tokens import DEFAULT_BITS, DEFAULT_ORDERS, TokenModel, token_table


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Leakage of keyed n-gram tokens (A17)")
    parser.add_argument("--language", choices=("ko", "latin"), default="ko")
    parser.add_argument("--cohort", type=int, default=1990)
    parser.add_argument("--rows", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--orders", type=int, nargs="+", default=list(DEFAULT_ORDERS))
    parser.add_argument("--bits", type=int, default=DEFAULT_BITS)
    parser.add_argument("--token-seed", type=int, default=7)
    parser.add_argument("--top-k", type=int, default=200)
    parser.add_argument("--attack", type=int, choices=(1, 2, 3, 4), default=1)
    parser.add_argument("--seed-rows", type=int, default=10, help="known rows for attack 3")
    parser.add_argument("--recon-rows", type=int, default=2000, help="rows for attack 4")
    parser.add_argument("--recon-candidates", type=int, default=1000, help="names for attack 4")
    parser.add_argument(
        "--prior-cohort", type=int, default=None, help="cohort mismatch (default: same)"
    )
    parser.add_argument("--prior-samples", type=int, default=200_000)
    parser.add_argument("--prior-seed", type=int, default=11)
    parser.add_argument(
        "--prior-alpha", type=float, default=50.0, help="Dirichlet noise (higher = closer)"
    )
    parser.add_argument("--prior-top-k", type=int, default=40, help="prior truncation")
    return parser


def run(args: argparse.Namespace) -> dict[str, object]:
    orders: Sequence[int] = args.orders
    generator = NameGenerator(args.language, args.cohort, args.seed)
    people = generator.generate(args.rows)
    full_names = [person.full_name() for person in people]

    model = TokenModel(args.bits, args.token_seed)
    table = token_table(model, full_names, orders)

    rng = random.Random(args.prior_seed)  # noqa: S311 - synthetic names, not key material
    prior_cohort = args.cohort if args.prior_cohort is None else args.prior_cohort
    prior = NameGenerator(args.language, prior_cohort, args.prior_seed)
    surnames = prior.surname_dist().truncate(args.prior_top_k).noised(rng, args.prior_alpha)
    male = prior.given_dist("male").truncate(args.prior_top_k).noised(rng, args.prior_alpha)
    female = prior.given_dist("female").truncate(args.prior_top_k).noised(rng, args.prior_alpha)
    prior_names = sample_names(surnames, male, female, args.prior_samples, rng)

    observed = token_frequency(table)
    ngram_prior = ngram_frequency(prior_names, orders)
    if args.attack == 2:
        predicted = cooccurrence_attack(table, prior_names, ngram_prior, orders)
    elif args.attack == 3:
        known = [(table[i], full_names[i]) for i in range(args.seed_rows)]
        predicted = seeding_attack(observed, known, ngram_prior, orders)
    else:
        predicted = frequency_attack(observed, ngram_prior, args.top_k)
    recovery = token_recovery(predicted, reverse_injection(model.items()), observed)

    full_name_freq = prior_full_name_frequency(prior_names)
    b0_surname = [prior_surname_guess(surnames)] * args.rows
    candidate_names = sorted(full_name_freq, key=lambda name: -full_name_freq[name])[
        : args.recon_candidates
    ]
    recon_rows = min(args.recon_rows, args.rows)
    top1, top5 = reconstruction_attack(
        table[:recon_rows], predicted, candidate_names, full_names[:recon_rows], orders
    )
    return {
        "config": vars(args),
        "leakage": {
            "attack": args.attack,
            "token_recovery_unique": recovery.unique,
            "token_recovery_weighted": recovery.weighted,
            "distinct_tokens": recovery.predicted,
            "tokens_recovered": recovery.correct_unique,
            "reconstruction_top1": top1,
            "reconstruction_top5": top5,
            "unique_row_fraction": unique_row_fraction(table),
            "shared_set": shared_set_stats(table),
        },
        "baselines": {
            "b0_surname_accuracy": surname_accuracy(b0_surname, [p.surname for p in people]),
            "b0_full_name_top1": top1_accuracy(
                max(full_name_freq, key=lambda k: full_name_freq[k]), full_names
            ),
            "b1_b1_prime": equality_stats(full_names),
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run(args)
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    leakage = result["leakage"]
    assert isinstance(leakage, dict)  # noqa: S101 - our own shape
    print(
        f"{args.language} N={args.rows} orders={args.orders} bits={args.bits}: "
        f"token recovery weighted={leakage['token_recovery_weighted']:.3f}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
