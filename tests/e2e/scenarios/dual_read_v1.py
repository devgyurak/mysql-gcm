"""Given a legacy AES_ENCRYPT value wrapped as a v1 envelope, when gcm_decrypt
reads it, then it returns what AES_DECRYPT returns — a migration needs no
re-encryption (docs/design.md amendment A3)."""

# ruff: noqa: S608
# S608 (SQL built from an f-string) is not applicable here: the only interpolated
# parts are the module-level schema and table constants, and every value travels as
# a bound parameter, which is also what keeps the plaintext out of the statement text.

from __future__ import annotations

from typing import TYPE_CHECKING

from ._sql import error_code, execute, fresh_table, row

if TYPE_CHECKING:
    from runner import Context

PLAINTEXT = "홍길동"
IV_HEX = "101112131415161718191a1b1c1d1e1f"
ER_UDF_ERROR = 3200


def given_a_v1_envelope_when_decrypted_then_it_matches_the_builtin(ctx: Context) -> None:
    # Given
    fresh_table(ctx, "legacy", "id INT PRIMARY KEY, c VARBINARY(128)")
    execute(ctx.primary, "SET SESSION block_encryption_mode = 'aes-256-cbc'")
    execute(
        ctx.primary,
        f"INSERT INTO {ctx.schema()}.legacy VALUES (1, CONCAT(UNHEX('01'), UNHEX(%s), "
        "AES_ENCRYPT(%s, UNHEX(%s), UNHEX(%s))))",
        (IV_HEX, PLAINTEXT, ctx.key_hex, IV_HEX),
    )

    # When
    plaintext, version, length = row(
        ctx.primary,
        f"SELECT gcm_decrypt(c, UNHEX(%s)), HEX(LEFT(c, 1)), LENGTH(c) "
        f"FROM {ctx.schema()}.legacy WHERE id = 1",
        (ctx.key_hex,),
    )

    # Then
    assert plaintext == PLAINTEXT, plaintext
    assert version == "01", version
    assert int(str(length)) == 33, length


def given_a_v1_envelope_when_decrypted_with_an_aad_then_it_is_rejected(ctx: Context) -> None:
    # Given: the row written above is still in place
    # When
    code = error_code(
        ctx.primary,
        f"SELECT gcm_decrypt(c, UNHEX(%s), 'anything') FROM {ctx.schema()}.legacy WHERE id = 1",
        (ctx.key_hex,),
    )

    # Then: v1 predates AAD and cannot bind one
    assert code == ER_UDF_ERROR, f"expected ER_UDF_ERROR, got {code}"


def run(ctx: Context) -> None:
    given_a_v1_envelope_when_decrypted_then_it_matches_the_builtin(ctx)
    given_a_v1_envelope_when_decrypted_with_an_aad_then_it_is_rejected(ctx)
