"""gcm.strict on MySQL 9.0 and later, where component sysvars carry session scope
(docs/design.md amendment A5).

Given two sessions, when only one sets gcm.strict = OFF, then the other still
errors on a tag mismatch. The runner selects this scenario or
strict_scope_global, so neither body needs a version branch."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._sql import error_code, execute, row

if TYPE_CHECKING:
    from runner import Context

ER_UDF_ERROR = 3200


def given_two_sessions_when_one_turns_strict_off_then_the_other_still_errors(
    ctx: Context,
) -> None:
    # Given: a tampered envelope, and two sessions on the *same* server — one with
    # strict off, one left at the default. Two sessions on one server is the only way
    # to show session scope; a second server would pass even without it.
    tampered = _tampered_envelope(ctx)
    relaxed = ctx.primary
    strict = ctx.primary2
    execute(relaxed, "SET SESSION gcm.strict = OFF")

    # When
    relaxed_is_null = row(
        relaxed, "SELECT gcm_decrypt(UNHEX(%s), UNHEX(%s)) IS NULL", (tampered, ctx.key_hex)
    )[0]
    strict_code = error_code(
        strict, "SELECT gcm_decrypt(UNHEX(%s), UNHEX(%s))", (tampered, ctx.key_hex)
    )

    # Then
    assert int(str(relaxed_is_null)) == 1, "the relaxed session should see NULL"
    assert strict_code == ER_UDF_ERROR, f"the other session should still error, got {strict_code}"
    execute(relaxed, "SET SESSION gcm.strict = DEFAULT")


def given_a_session_with_strict_off_when_the_global_changes_then_the_session_keeps_its_value(
    ctx: Context,
) -> None:
    # Given
    execute(ctx.primary, "SET SESSION gcm.strict = OFF")
    execute(ctx.primary, "SET GLOBAL gcm.strict = ON")

    # When
    session_value, global_value = row(
        ctx.primary, "SELECT @@SESSION.gcm.strict, @@GLOBAL.gcm.strict"
    )

    # Then
    assert int(str(session_value)) == 0, "the session value must survive a global change"
    assert int(str(global_value)) == 1, global_value
    execute(ctx.primary, "SET SESSION gcm.strict = DEFAULT")


def _tampered_envelope(ctx: Context) -> str:
    """A valid envelope with its last tag byte flipped, as hex."""
    envelope = str(
        row(ctx.primary, "SELECT HEX(gcm_encrypt_det('홍길동', UNHEX(%s)))", (ctx.key_hex,))[0]
    )
    return envelope[:-2] + ("00" if envelope[-2:] != "00" else "FF")


def run(ctx: Context) -> None:
    given_two_sessions_when_one_turns_strict_off_then_the_other_still_errors(ctx)
    given_a_session_with_strict_off_when_the_global_changes_then_the_session_keeps_its_value(ctx)
