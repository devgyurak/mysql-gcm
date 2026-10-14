#!/usr/bin/env python3
"""Run the A17 experiment matrix and print the result JSON (design amendment A17).

The judged configuration is S2, incomplete side knowledge, N = 300k, over 20 seeds
(A17, "Adoption criteria"). Every variant is run under attack 3 (known-row seeding,
the strongest) and the four attacks are compared on V0. Results are printed as JSON;
the caller commits them under docs/assets/leakage/ with the command and seeds.

The full run is slow and is not in CI (A17, "Experiment harness conventions"); the
committed JSON is the record.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

import run

LANGUAGES: tuple[str, ...] = ("ko", "latin")
SEEDS: tuple[int, ...] = tuple(range(1, 21))
VARIANTS: tuple[str, ...] = ("V0", "V1", "V2", "V3-8", "V3-12", "V3-16", "V4", "V5", "V7")
ATTACKS: tuple[int, ...] = (1, 2, 3)
ROWS = 300_000
BASE: tuple[str, ...] = (
    "--rows",
    str(ROWS),
    "--prior-samples",
    "50000",
    "--recon-rows",
    "500",
    "--recon-candidates",
    "300",
)
# Every metric that is averaged over seeds. The rest of a run's record (the config and
# the variant's shape) is identical across seeds and is kept from the first run.
SCALARS: tuple[str, ...] = (
    "token_recovery_unique",
    "token_recovery_weighted",
    "reconstruction_top1",
    "reconstruction_top5",
    "unique_row_fraction",
)
UTILITY_SCALARS: tuple[str, ...] = (
    "answered_fraction",
    "mean_candidate_fraction",
    "mean_row_tokens",
    "distinct_tokens",
)
EQUALITY_SCALARS: tuple[str, ...] = (
    "distinct_full_names",
    "unique_full_fraction",
    "distinct_surnames",
    "distinct_given_names",
    "unique_surname_fraction",
    "unique_given_fraction",
)


def _one(extra: Sequence[str]) -> dict[str, object]:
    args = run.build_parser().parse_args([*BASE, *extra])
    return run.run(args)


def _mean_std(values: list[float]) -> dict[str, float]:
    return {"mean": statistics.fmean(values), "std": statistics.pstdev(values)}


def _aggregate(records: list[dict[str, object]]) -> dict[str, object]:
    leakage = [cast("dict[str, Any]", record["leakage"]) for record in records]
    utility = [cast("dict[str, Any]", record["utility"]) for record in records]
    baselines = [cast("dict[str, Any]", record["baselines"]) for record in records]
    equality = [cast("dict[str, Any]", b["b1_b1_prime"]) for b in baselines]
    return {
        "variant": records[0]["variant"],
        "leakage": {
            metric: _mean_std([float(row[metric]) for row in leakage]) for metric in SCALARS
        },
        "utility": {
            metric: _mean_std([float(row[metric]) for row in utility]) for metric in UTILITY_SCALARS
        },
        "baselines": {
            "b0_surname_accuracy": _mean_std([float(b["b0_surname_accuracy"]) for b in baselines]),
            "b0_full_name_top1": _mean_std([float(b["b0_full_name_top1"]) for b in baselines]),
            "b1_b1_prime": {
                metric: _mean_std([float(row[metric]) for row in equality])
                for metric in EQUALITY_SCALARS
            },
        },
    }


def _config() -> dict[str, object]:
    return {
        "rows": ROWS,
        "seeds": list(SEEDS),
        "variants": list(VARIANTS),
        "attacks": list(ATTACKS),
        "languages": list(LANGUAGES),
        "base_args": list(BASE),
    }


def _write(path: Path, results: dict[str, dict[str, object]]) -> None:
    """Rewrite the whole file after each key, so a killed run resumes with its progress."""
    payload = {"config": _config(), "results": results}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="A17 experiment matrix")
    parser.add_argument("--out", type=Path, default=None, help="write here (rewritten per key)")
    parser.add_argument("--resume", action="store_true", help="skip keys already in --out")
    args = parser.parse_args()
    results: dict[str, dict[str, object]] = {}
    if args.out is not None and args.resume and args.out.exists():
        existing = json.loads(args.out.read_text(encoding="utf-8"))
        results = cast("dict[str, dict[str, object]]", existing.get("results", {}))
    for language in LANGUAGES:
        for variant in VARIANTS:
            attacks = ATTACKS if variant == "V0" else (3,)
            for attack in attacks:
                key = f"{language}:{variant}:{attack}"
                if key in results:
                    print(f"skip {key}", file=sys.stderr)
                    continue
                records = [
                    _one(
                        [
                            "--language",
                            language,
                            "--variant",
                            variant,
                            "--attack",
                            str(attack),
                            "--seed",
                            str(seed),
                            # A different prior per seed, so the reported std is the
                            # spread over priors, not over data with one fixed prior.
                            "--prior-seed",
                            str(seed * 7919 + 11),
                        ]
                    )
                    for seed in SEEDS
                ]
                results[key] = _aggregate(records)
                if args.out is not None:
                    _write(args.out, results)
                print(f"done {key}", file=sys.stderr)
    if args.out is None:
        json.dump(
            {"config": _config(), "results": results},
            sys.stdout,
            ensure_ascii=False,
            indent=2,
        )
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
