"""gcm.strict on MySQL 8.0 and 8.4, where component sysvars have no session scope
(docs/design.md amendment A5).

Given a tampered envelope, when gcm.strict is changed globally, then every session
follows it — and SET SESSION is rejected by the server. The runner selects this
scenario or strict_scope_session, so neither body needs a version branch."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._sql import error_code, execute, row

if TYPE_CHECKING:
    from runner import Context

ER_UDF_ERROR = 3200
ER_INCORRECT_GLOBAL_LOCAL_VAR = 1229


def given_strict_is_global_only_when_set_session_is_attempted_then_the_server_rejects_it(
    ctx: Context,
) -> None:
    # Given: a server whose component sysvars predate session scope
    # When
    code = error_code(ctx.primary, "SET SESSION gcm.strict = OFF")

    # Then
    assert code == ER_INCORRECT_GLOBAL_LOCAL_VAR, f"expected 1229, got {code}"


def given_a_tampered_envelope_when_strict_is_off_globally_then_decrypt_returns_null(
    ctx: Context,
) -> None:
    # Given
    tampered = _tampered_envelope(ctx)
    execute(ctx.primary, "SET GLOBAL gcm.strict = OFF")

    # When
    is_null = row(
        ctx.primary, "SELECT gcm_decrypt(UNHEX(%s), UNHEX(%s)) IS NULL", (tampered, ctx.key_hex)
    )[0]

    # Then
    assert int(str(is_null)) == 1, "a tag mismatch should be NULL while strict is off"
    execute(ctx.primary, "SET GLOBAL gcm.strict = DEFAULT")


def given_a_tampered_envelope_when_strict_is_back_on_then_decrypt_errors(ctx: Context) -> None:
    # Given
    tampered = _tampered_envelope(ctx)
    execute(ctx.primary, "SET GLOBAL gcm.strict = ON")

    # When
    code = error_code(
        ctx.primary, "SELECT gcm_decrypt(UNHEX(%s), UNHEX(%s))", (tampered, ctx.key_hex)
    )

    # Then
    assert code == ER_UDF_ERROR, f"expected ER_UDF_ERROR, got {code}"


def given_strict_turned_off_by_another_session_when_decrypting_then_this_one_follows(
    ctx: Context,
) -> None:
    """The value is written by one session and read by another.

    This is the contract the 8.0/8.4 read path has to keep. `strict_enabled()` used to
    load the registration's storage byte directly, with no synchronisation against the
    server's write under LOCK_global_system_variables; it goes through
    component_sys_variable_register::get_variable() now, which takes that same mutex.

    What this case pins is the *observable* contract — a GLOBAL change made elsewhere is
    seen by the next statement here. It cannot prove a data race is gone; no test can,
    and a sanitizer build is the tool for that. It would catch the read regressing to a
    cached or default value, which is the way a well-meaning change to that function
    would most likely break it.
    """
    # Given: a tampered envelope, and strict turned off from a *different* session
    tampered = _tampered_envelope(ctx)
    execute(ctx.primary, "SET GLOBAL gcm.strict = OFF")
    try:
        # When: the other session decrypts it
        is_null = row(
            ctx.primary2,
            "SELECT gcm_decrypt(UNHEX(%s), UNHEX(%s)) IS NULL",
            (tampered, ctx.key_hex),
        )[0]

        # Then
        assert int(str(is_null)) == 1, "a GLOBAL change from another session must be observed here"
    finally:
        # try/finally because this is GLOBAL: a failed assertion here would otherwise
        # leave strict off for every scenario that runs after it on the same server, and
        # the next failure would be in a file that did nothing wrong (testing rule: a
        # global sysvar is restored by the case that changed it).
        execute(ctx.primary, "SET GLOBAL gcm.strict = DEFAULT")


def _tampered_envelope(ctx: Context) -> str:
    """A valid envelope with its last tag byte flipped, as hex."""
    envelope = str(
        row(ctx.primary, "SELECT HEX(gcm_encrypt_det('홍길동', UNHEX(%s)))", (ctx.key_hex,))[0]
    )
    return envelope[:-2] + ("00" if envelope[-2:] != "00" else "FF")


def run(ctx: Context) -> None:
    given_strict_is_global_only_when_set_session_is_attempted_then_the_server_rejects_it(ctx)
    given_a_tampered_envelope_when_strict_is_off_globally_then_decrypt_returns_null(ctx)
    given_strict_turned_off_by_another_session_when_decrypting_then_this_one_follows(ctx)
    given_a_tampered_envelope_when_strict_is_back_on_then_decrypt_errors(ctx)
