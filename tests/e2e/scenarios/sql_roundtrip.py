"""Given a row written with SQL gcm_encrypt, when it is read back through
gcm_decrypt, then the original plaintext returns."""

# ruff: noqa: S608
# S608 (SQL built from an f-string) is not applicable here: the only interpolated
# parts are the module-level schema and table constants, and every value travels as
# a bound parameter, which is also what keeps the plaintext out of the statement text.

from __future__ import annotations

from typing import TYPE_CHECKING

from ._sql import execute, fresh_table, row

if TYPE_CHECKING:
    from runner import Context

PLAINTEXT = "홍길동"


def given_a_row_encrypted_by_the_server_when_decrypted_then_plaintext_returns(
    ctx: Context,
) -> None:
    # Given
    fresh_table(ctx, "roundtrip", "id INT PRIMARY KEY, enc VARBINARY(128)")
    execute(
        ctx.primary,
        f"INSERT INTO {ctx.schema()}.roundtrip VALUES (1, gcm_encrypt(%s, UNHEX(%s)))",
        (PLAINTEXT, ctx.key_hex),
    )

    # When
    plaintext, envelope_length, charset = row(
        ctx.primary,
        f"SELECT gcm_decrypt(enc, UNHEX(%s)), LENGTH(enc), CHARSET(gcm_decrypt(enc, UNHEX(%s))) "
        f"FROM {ctx.schema()}.roundtrip WHERE id = 1",
        (ctx.key_hex, ctx.key_hex),
    )

    # Then
    assert plaintext == PLAINTEXT, f"expected {PLAINTEXT!r}, got {plaintext!r}"
    assert int(str(envelope_length)) == len(PLAINTEXT.encode()) + 29, envelope_length
    assert charset == "utf8mb4", charset


def run(ctx: Context) -> None:
    given_a_row_encrypted_by_the_server_when_decrypted_then_plaintext_returns(ctx)
