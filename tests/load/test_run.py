"""Regression checks for the load runner's temporary server policy."""

import unittest
from unittest.mock import MagicMock, call, patch

import run as load_runner


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

    def test_given_floor_16_when_loading_aes256_then_do_not_raise_the_floor(self) -> None:
        # Given: AES-128 is already permitted by the administrator.
        conn = MagicMock()
        with (
            patch.object(load_runner, "scalar", return_value=16),
            patch.object(load_runner, "execute") as execute,
        ):
            # When: this run needs only AES-256.
            with load_runner.encryption_floor(conn, 32):
                pass
            # Then: both the temporary and restored policy remain 16.
            self.assertEqual(
                execute.call_args_list,
                [
                    call(conn, "SET GLOBAL gcm.min_key_bytes = %s", (16,)),
                    call(conn, "SET GLOBAL gcm.min_key_bytes = %s", (16,)),
                ],
            )
