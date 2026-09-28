"""Given Korean names stored with gcm_encrypt_det, when the server filters them
with native LIKE, then only the matching rows come back.

This is the scenario the project exists for (docs/design.md §1.2)."""

# ruff: noqa: S608
# S608 (SQL built from an f-string) is not applicable here: the only interpolated
# parts are the module-level schema and table constants, and every value travels as
# a bound parameter, which is also what keeps the plaintext out of the statement text.

from __future__ import annotations

from typing import TYPE_CHECKING

from ._sql import execute, fresh_table, rows

if TYPE_CHECKING:
    from runner import Context

NAMES = ("김철수", "홍길동", "박길수")


def given_encrypted_korean_names_when_filtered_with_like_then_only_matches_return(
    ctx: Context,
) -> None:
    # Given
    fresh_table(ctx, "patients", "id INT PRIMARY KEY, name_enc VARBINARY(128)")
    execute(
        ctx.primary,
        f"INSERT INTO {ctx.schema()}.patients VALUES "
        "(1, gcm_encrypt_det(%s, UNHEX(%s))), "
        "(2, gcm_encrypt_det(%s, UNHEX(%s))), "
        "(3, gcm_encrypt_det(%s, UNHEX(%s)))",
        (NAMES[0], ctx.key_hex, NAMES[1], ctx.key_hex, NAMES[2], ctx.key_hex),
    )

    # When
    matched = rows(
        ctx.primary,
        f"SELECT id FROM {ctx.schema()}.patients "
        "WHERE gcm_decrypt(name_enc, UNHEX(%s)) LIKE %s ORDER BY id",
        (ctx.key_hex, "%길%"),
    )

    # Then
    assert [int(str(r[0])) for r in matched] == [2, 3], matched


def run(ctx: Context) -> None:
    given_encrypted_korean_names_when_filtered_with_like_then_only_matches_return(ctx)
