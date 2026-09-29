#!/usr/bin/env python3
"""Turn Google Benchmark JSON into ratios against the bare-OpenSSL reference, and gate on them.

Absolute nanoseconds from a shared CI runner are not comparable with the same runner an hour
later, let alone a different one. So what this gates is each case divided by a reference case
measured in the same process — the trick tests/load/run.py uses against `AES_DECRYPT`, one layer
down. See tests/bench/bench_support.h for why the reference is a bare EVP call.

Cases with no meaningful reference (nonce derivation, envelope parsing) are reported but not
ratio-gated: there is no OpenSSL operation to divide them by, and an absolute ceiling on a
shared runner is a flaky test rather than a gate.

Output: JSON on stdout, human summary on stderr, gate result via exit code (stack-python rule).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

# Each ratio is <case> / <reference>. seal_random and seal_det share a reference on purpose:
# what separates them is precisely what this project adds, a fresh nonce in one case and two
# HMACs in the other, and both are measured against the same bare seal.
RATIO_PAIRS = {
    "seal_random": ("gcm/seal_random", "ref/seal"),
    "seal_det": ("gcm/seal_det", "ref/seal"),
    "open": ("gcm/open", "ref/open"),
}


def load_results(path: str) -> dict[str, float]:
    """Maps benchmark name to cpu_time in nanoseconds."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    results: dict[str, float] = {}
    for entry in doc.get("benchmarks", []):
        # An aggregate (mean/median/stddev) repeats a name with a suffix; skip those and keep
        # the single measurement, so --benchmark_repetitions does not double-count.
        if entry.get("run_type") == "aggregate":
            continue
        if entry.get("error_occurred"):
            name, why = entry["name"], entry.get("error_message")
            raise SystemExit(f"benchmark {name} reported an error: {why}")
        results[entry["name"]] = float(entry["cpu_time"])
    if not results:
        raise SystemExit(f"{path} contains no benchmark results")
    return results


def sizes_for(results: dict[str, float], prefix: str) -> list[int]:
    found: list[int] = []
    for name in results:
        if not name.startswith(prefix + "/"):
            continue
        suffix = name[len(prefix) + 1 :]
        if suffix.isdigit():
            found.append(int(suffix))
    return sorted(found)


def comparisons(results: dict[str, float]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case, (measured, reference) in RATIO_PAIRS.items():
        for size in sizes_for(results, measured):
            ours = results[f"{measured}/{size}"]
            base = results.get(f"{reference}/{size}")
            if base is None:
                raise SystemExit(f"no reference {reference}/{size} for {measured}/{size}")
            rows.append(
                {
                    "case": case,
                    "size": size,
                    "cpu_ns": round(ours, 1),
                    "reference_ns": round(base, 1),
                    "ratio": round(ours / base, 3),
                }
            )
    return rows


def recorded(results: dict[str, float]) -> list[dict[str, Any]]:
    """Cases without a reference: reported so a change is visible in the artifact."""
    named = [name for name in results if not name.startswith(("gcm/", "ref/"))]
    return [{"name": name, "cpu_ns": round(results[name], 2)} for name in sorted(named)]


def gate(rows: list[dict[str, Any]], baseline_path: str) -> list[str]:
    """Returns the violations, empty when every ratio is within budget."""
    with open(baseline_path, encoding="utf-8") as fh:
        baseline = json.load(fh)
    ceilings = baseline.get("max_ratio")
    if ceilings is None:
        print(
            f"{baseline_path} has no max_ratio: recording only, not gating. "
            "Fill it from three CI runs before relying on it.",
            file=sys.stderr,
        )
        return []

    violations: list[str] = []
    for row in rows:
        key = f"{row['case']}/{row['size']}"
        ceiling = ceilings.get(key)
        if ceiling is None:
            # A missing ceiling is a gap in the baseline, not a pass. A new case would
            # otherwise be added and silently ungated.
            violations.append(f"{key}: no ceiling in {baseline_path}")
            continue
        if row["ratio"] > float(ceiling):
            violations.append(f"{key}: ratio {row['ratio']} > {ceiling}")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", help="Google Benchmark --benchmark_out JSON")
    parser.add_argument("--gate", help="baseline JSON to check the ratios against")
    parser.add_argument("--out", help="write the summary JSON here as well as to stdout")
    args = parser.parse_args()

    results = load_results(args.results)
    rows = comparisons(results)
    summary: dict[str, Any] = {"comparisons": rows, "recorded": recorded(results)}

    for row in rows:
        print(
            f"  {row['case']:<12} {row['size']:>6}B  "
            f"{row['cpu_ns']:>9.1f} ns vs ref {row['reference_ns']:>9.1f} ns  "
            f"ratio {row['ratio']}",
            file=sys.stderr,
        )

    text = json.dumps(summary, indent=2, sort_keys=True)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    if not args.gate:
        return 0
    violations = gate(rows, args.gate)
    for violation in violations:
        print(f"GATE: {violation}", file=sys.stderr)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
