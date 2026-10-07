"""Regression checks for the load runner's temporary server policy."""

import unittest
from typing import cast
from unittest.mock import MagicMock, call, patch

import run as load_runner


def measurement(variant: str, p95_ms: float) -> load_runner.Measurement:
    return load_runner.Measurement(
        rows=100, concurrency=1, variant=variant, p50_ms=p95_ms, p95_ms=p95_ms, max_ms=p95_ms
    )


class Decomposition(unittest.TestCase):
    def test_given_three_variants_when_decomposed_then_shares_sum_to_the_gcm_query(self) -> None:
        # Given: a scan floor of 10 ms, 40 ms more to decrypt, 2 ms more to LIKE the result.
        by_variant = {
            "plain": measurement("plain", 10.0),
            "gcm_nolike": measurement("gcm_nolike", 50.0),
            "gcm": measurement("gcm", 52.0),
        }
        # When
        parts = load_runner.decompose(100_000, 1, by_variant)
        # Then: the three shares are the differences, add up to the whole, and the per-row
        #       figure is the decrypt share over the rows.
        self.assertEqual(parts["scan_like_floor_ms"], 10.0)
        self.assertEqual(parts["udf_decrypt_tag_ms"], 40.0)
        self.assertEqual(parts["like_on_udf_result_ms"], 2.0)
        self.assertEqual(
            cast(float, parts["scan_like_floor_ms"])
            + cast(float, parts["udf_decrypt_tag_ms"])
            + cast(float, parts["like_on_udf_result_ms"]),
            parts["gcm_p95_ms"],
        )
        self.assertAlmostEqual(cast(float, parts["udf_decrypt_tag_pct"]), 76.9, places=1)
        self.assertEqual(parts["udf_decrypt_tag_ns_per_row"], 400.0)

    def test_given_no_rows_when_decomposed_then_per_row_cost_is_absent(self) -> None:
        # Given: nothing was scanned.
        by_variant = {
            "plain": measurement("plain", 1.0),
            "gcm_nolike": measurement("gcm_nolike", 2.0),
            "gcm": measurement("gcm", 3.0),
        }
        # When
        parts = load_runner.decompose(0, 1, by_variant)
        # Then: no division by zero, and no made-up per-row number.
        self.assertIsNone(parts["udf_decrypt_tag_ns_per_row"])

    def test_given_zero_gcm_time_when_decomposed_then_shares_have_no_percentage(self) -> None:
        # Given: a gcm p95 of zero, which a broken run could report.
        by_variant = {
            "plain": measurement("plain", 0.0),
            "gcm_nolike": measurement("gcm_nolike", 0.0),
            "gcm": measurement("gcm", 0.0),
        }
        # When
        parts = load_runner.decompose(10, 1, by_variant)
        # Then
        self.assertIsNone(parts["scan_like_floor_pct"])
        self.assertIsNone(parts["udf_decrypt_tag_pct"])
        self.assertIsNone(parts["like_on_udf_result_pct"])


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
