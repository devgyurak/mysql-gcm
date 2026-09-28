"""Given a non-deterministic encryption on the primary, when the change reaches
the replica under ROW binlog, then both hold the identical bytes.

This is the test behind the ROW-binlog requirement in docs/design.md §6: under
statement-based replication the replica would run gcm_encrypt again and store a
different nonce."""

# ruff: noqa: S608
# S608 (SQL built from an f-string) is not applicable here: the only interpolated
# parts are the module-level schema and table constants, and every value travels as
# a bound parameter, which is also what keeps the plaintext out of the statement text.

from __future__ import annotations

from typing import TYPE_CHECKING

from ._sql import execute, fresh_table, row, wait_until_replicated

if TYPE_CHECKING:
    from runner import Context

PLAINTEXT = "홍길동"


def given_a_random_nonce_value_on_the_primary_when_replicated_then_bytes_are_identical(
    ctx: Context,
) -> None:
    # Given
    fresh_table(ctx, "repl", "id INT PRIMARY KEY, rnd VARBINARY(128), det VARBINARY(128)")
    execute(
        ctx.primary,
        f"INSERT INTO {ctx.schema()}.repl VALUES "
        "(1, gcm_encrypt(%s, UNHEX(%s)), gcm_encrypt_det(%s, UNHEX(%s)))",
        (PLAINTEXT, ctx.key_hex, PLAINTEXT, ctx.key_hex),
    )
    primary_rnd, primary_det = row(
        ctx.primary, f"SELECT HEX(rnd), HEX(det) FROM {ctx.schema()}.repl WHERE id = 1"
    )

    # When
    wait_until_replicated(ctx)

    # Then
    replica_rnd, replica_det, decrypted, korean_like = row(
        ctx.replica,
        f"SELECT HEX(rnd), HEX(det), gcm_decrypt(rnd, UNHEX(%s)), "
        "gcm_decrypt(det, UNHEX(%s)) LIKE %s "
        f"FROM {ctx.schema()}.repl WHERE id = 1",
        (ctx.key_hex, ctx.key_hex, "%길%"),
    )
    assert replica_rnd == primary_rnd, "random-nonce bytes diverged between primary and replica"
    assert replica_det == primary_det, "deterministic bytes diverged"
    assert decrypted == PLAINTEXT, decrypted
    assert int(str(korean_like)) == 1, "native LIKE on the decrypted value failed on the replica"


def run(ctx: Context) -> None:
    given_a_random_nonce_value_on_the_primary_when_replicated_then_bytes_are_identical(ctx)
