"""Given a value sealed with one AAD, when it is opened with another, then the tag
check fails — the AAD is authenticated (spec/envelope.md §4)."""

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
AAD = "patients.name"
OTHER_AAD = "patients.other"
ER_UDF_ERROR = 3200


def given_a_value_sealed_with_one_aad_when_opened_with_another_then_the_tag_fails(
    ctx: Context,
) -> None:
    # Given
    fresh_table(ctx, "aad", "id INT PRIMARY KEY, enc VARBINARY(128)")
    execute(
        ctx.primary,
        f"INSERT INTO {ctx.schema()}.aad VALUES (1, gcm_encrypt_det(%s, UNHEX(%s), %s))",
        (PLAINTEXT, ctx.key_hex, AAD),
    )

    # When
    code = error_code(
        ctx.primary,
        f"SELECT gcm_decrypt(enc, UNHEX(%s), %s) FROM {ctx.schema()}.aad WHERE id = 1",
        (ctx.key_hex, OTHER_AAD),
    )

    # Then
    assert code == ER_UDF_ERROR, f"expected ER_UDF_ERROR, got {code}"


def given_a_value_sealed_with_an_aad_when_opened_with_the_same_aad_then_it_returns(
    ctx: Context,
) -> None:
    # Given: the row written above
    # When
    plaintext = row(
        ctx.primary,
        f"SELECT gcm_decrypt(enc, UNHEX(%s), %s) FROM {ctx.schema()}.aad WHERE id = 1",
        (ctx.key_hex, AAD),
    )[0]

    # Then
    assert plaintext == PLAINTEXT, plaintext


def run(ctx: Context) -> None:
    given_a_value_sealed_with_one_aad_when_opened_with_another_then_the_tag_fails(ctx)
    given_a_value_sealed_with_an_aad_when_opened_with_the_same_aad_then_it_returns(ctx)
