"""Regression checks for the load runner's temporary server policy."""

import unittest
from collections import Counter
from typing import cast
from unittest.mock import MagicMock, call, patch

import run as load_runner


def measurement(variant: str, p95_ms: float) -> load_runner.Measurement:
    return load_runner.Measurement(
        rows=100, concurrency=1, variant=variant, p50_ms=p95_ms, p95_ms=p95_ms, max_ms=p95_ms
    )


def predecessor_counts(primer: str, sequence: list[str]) -> Counter[tuple[str, str]]:
    """How often each ordered (previous, current) pair occurs in one session's order."""
    return Counter(zip([primer, *sequence[:-1]], sequence, strict=True))


VARIANTS = ["plain_len", "gcm_len", "gcm", "aes"]


class Schedule(unittest.TestCase):
    def test_given_four_variants_when_scheduled_then_every_predecessor_is_balanced(self) -> None:
        # Given: the runner's four variants and its 40 measured runs each.
        runs = load_runner.MEASURED_RUNS
        # When
        primer, sequence = load_runner.query_schedule(VARIANTS, runs)
        # Then: all 16 ordered pairs, each runs/4 times, and every variant runs `runs` times.
        pairs = predecessor_counts(primer, sequence)
        self.assertEqual(len(pairs), len(VARIANTS) ** 2)
        self.assertEqual(set(pairs.values()), {runs // len(VARIANTS)})
        self.assertEqual(Counter(sequence), Counter({v: runs for v in VARIANTS}))

    def test_given_runs_not_a_multiple_of_the_variants_when_scheduled_then_refused(self) -> None:
        # Given: 41 runs over four variants, which cannot be balanced.
        runs = 41
        # When / Then
        with self.assertRaises(ValueError):
            load_runner.query_schedule(VARIANTS, runs)


class Decomposition(unittest.TestCase):
    def test_given_three_variants_when_decomposed_then_shares_sum_to_the_gcm_query(self) -> None:
        # Given: a scan floor of 10 ms, 40 ms more to decrypt, 2 ms more to LIKE the result.
        by_variant = {
            "plain_len": measurement("plain_len", 10.0),
            "gcm_len": measurement("gcm_len", 50.0),
            "gcm": measurement("gcm", 52.0),
        }
        # When
        parts = load_runner.decompose(100_000, 1, by_variant)
        # Then: the three shares are the differences, add up to the whole, and the per-row
        #       figure is the decrypt share over the rows.
        self.assertEqual(parts["floor_p95_ms"], 10.0)
        self.assertEqual(parts["decrypt_call_p95_diff_ms"], 40.0)
        self.assertEqual(parts["like_vs_len_p95_diff_ms"], 2.0)
        self.assertEqual(
            cast(float, parts["floor_p95_ms"])
            + cast(float, parts["decrypt_call_p95_diff_ms"])
            + cast(float, parts["like_vs_len_p95_diff_ms"]),
            parts["gcm_p95_ms"],
        )
        self.assertAlmostEqual(cast(float, parts["decrypt_call_p95_diff_pct"]), 76.9, places=1)
        self.assertEqual(parts["decrypt_call_p95_diff_ns_per_row"], 400.0)

    def test_given_no_rows_when_decomposed_then_per_row_cost_is_absent(self) -> None:
        # Given: nothing was scanned.
        by_variant = {
            "plain_len": measurement("plain_len", 1.0),
            "gcm_len": measurement("gcm_len", 2.0),
            "gcm": measurement("gcm", 3.0),
        }
        # When
        parts = load_runner.decompose(0, 1, by_variant)
        # Then: no division by zero, and no made-up per-row number.
        self.assertIsNone(parts["decrypt_call_p95_diff_ns_per_row"])

    def test_given_zero_gcm_time_when_decomposed_then_shares_have_no_percentage(self) -> None:
        # Given: a gcm p95 of zero, which a broken run could report.
        by_variant = {
            "plain_len": measurement("plain_len", 0.0),
            "gcm_len": measurement("gcm_len", 0.0),
            "gcm": measurement("gcm", 0.0),
        }
        # When
        parts = load_runner.decompose(10, 1, by_variant)
        # Then
        self.assertIsNone(parts["floor_pct"])
        self.assertIsNone(parts["decrypt_call_p95_diff_pct"])
        self.assertIsNone(parts["like_vs_len_p95_diff_pct"])


class EncryptionFloor(unittest.TestCase):
    def test_given_floor_24_when_loading_finishes_then_restore_24(self) -> None:
        # Given: a server whose administrator chose a non-default floor.
        conn = MagicMock()
        with (
            patch.object(load_runner, "scalar", return_value=24),
            patch.object(load_runner, "execute") as execute,
        ):
            # When: the AES-128 fixture finishes loading.
            with load_runner.encryption_floor(conn, 16):
                pass
            # Then: restore the actual previous value, not the default.
            self.assertEqual(
                execute.call_args_list,
                [
                    call(conn, "SET GLOBAL gcm.min_key_bytes = %s", (16,)),
                    call(conn, "SET GLOBAL gcm.min_key_bytes = %s", (24,)),
                ],
            )

    def test_given_floor_32_when_loading_raises_then_restore_32_and_propagate(self) -> None:
        # Given: the default policy and an AES-128 load that fails.
        conn = MagicMock()
        with (
            patch.object(load_runner, "scalar", return_value=32),
            patch.object(load_runner, "execute") as execute,
        ):
            # When: an insert fails while the floor is lowered.
            with self.assertRaisesRegex(RuntimeError, "fixture insert failed"):
                with load_runner.encryption_floor(conn, 16):
                    raise RuntimeError("fixture insert failed")
            # Then: the error reaches the caller after the policy is restored.
            self.assertEqual(
                execute.call_args_list,
                [
                    call(conn, "SET GLOBAL gcm.min_key_bytes = %s", (16,)),
                    call(conn, "SET GLOBAL gcm.min_key_bytes = %s", (32,)),
                ],
            )

    def test_given_floor_16_when_loading_aes256_then_touch_nothing(self) -> None:
        # Given: AES-128 is already permitted by the administrator.
        conn = MagicMock()
        with (
            patch.object(load_runner, "scalar", return_value=16),
            patch.object(load_runner, "execute") as execute,
        ):
            # When: this run needs only AES-256.
            with load_runner.encryption_floor(conn, 32):
                pass
            # Then: the policy is neither lowered nor rewritten; no SET is issued at all.
            self.assertEqual(execute.call_args_list, [])
