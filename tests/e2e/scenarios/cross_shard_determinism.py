"""Sharding properties, on two servers that share no binary log
(docs/design.md amendment A8).

What a sharded deployment needs from this component, and what each scenario here
pins down:

* moving rows between shards must not require re-encryption — the destination
  decrypts with the original key and AAD;
* deterministic ciphertext must be comparable across shards, which holds only when
  key, plaintext *and* AAD match — so "one AAD convention per key" is a rule that
  crosses shard boundaries, not a per-server one;
* random-nonce ciphertext must never be used as a routing key, because two shards
  (and two calls) produce different bytes for the same plaintext.

Not covered here, because it is a property of query planning rather than of the
server: `gcm_decrypt(...) LIKE '%김%'` cannot by itself select a shard. Without a
routing predicate every shard is queried and each decrypts its own candidates.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._sql import row

if TYPE_CHECKING:
    from runner import Context

PLAINTEXT = "홍길동"
AAD = "patients.name"
OTHER_AAD = "patients.alias"


def given_two_shards_when_sealing_the_same_value_then_deterministic_bytes_match(
    ctx: Context,
) -> None:
    # Given: two independent servers and one key
    # When: each seals the same plaintext with the same AAD, deterministically
    on_a = row(
        ctx.primary,
        "SELECT HEX(gcm_encrypt_det(%s, UNHEX(%s), %s))",
        (PLAINTEXT, ctx.key_hex, AAD),
    )[0]
    on_b = row(
        ctx.shard_b,
        "SELECT HEX(gcm_encrypt_det(%s, UNHEX(%s), %s))",
        (PLAINTEXT, ctx.key_hex, AAD),
    )[0]

    # Then: identical bytes, so a deterministic column joins and compares across shards
    assert on_a == on_b, "deterministic ciphertext diverged between two shards"


def given_a_value_sealed_on_one_shard_when_read_on_the_other_then_no_reencryption_is_needed(
    ctx: Context,
) -> None:
    # Given: an envelope produced on shard A
    envelope_hex = row(
        ctx.primary,
        "SELECT HEX(gcm_encrypt(%s, UNHEX(%s), %s))",
        (PLAINTEXT, ctx.key_hex, AAD),
    )[0]

    # When: the same bytes are handed to shard B, as a row migration would
    plaintext = row(
        ctx.shard_b,
        "SELECT gcm_decrypt(UNHEX(%s), UNHEX(%s), %s)",
        (str(envelope_hex), ctx.key_hex, AAD),
    )[0]

    # Then: it opens there with the original key and AAD, untouched
    assert plaintext == PLAINTEXT, f"expected {PLAINTEXT!r}, got {plaintext!r}"


def given_two_shards_when_one_uses_a_different_aad_then_the_bytes_no_longer_match(
    ctx: Context,
) -> None:
    # Given: two shards, one key, one plaintext
    # When: the shards disagree about the AAD
    on_a = row(
        ctx.primary,
        "SELECT HEX(gcm_encrypt_det(%s, UNHEX(%s), %s))",
        (PLAINTEXT, ctx.key_hex, AAD),
    )[0]
    on_b = row(
        ctx.shard_b,
        "SELECT HEX(gcm_encrypt_det(%s, UNHEX(%s), %s))",
        (PLAINTEXT, ctx.key_hex, OTHER_AAD),
    )[0]

    # Then: the envelopes differ, so a per-shard AAD silently breaks cross-shard
    # equality — the AAD convention has to be fixed per key, not per shard
    assert on_a != on_b, "a differing AAD should change the envelope"


def given_two_shards_when_sealing_with_a_random_nonce_then_the_bytes_differ(
    ctx: Context,
) -> None:
    # Given: two shards and one key
    # When: each seals the same plaintext with the random-nonce function
    on_a = row(ctx.primary, "SELECT HEX(gcm_encrypt(%s, UNHEX(%s)))", (PLAINTEXT, ctx.key_hex))[0]
    on_b = row(ctx.shard_b, "SELECT HEX(gcm_encrypt(%s, UNHEX(%s)))", (PLAINTEXT, ctx.key_hex))[0]

    # Then: different bytes — which is why a random-nonce value cannot be a routing key
    assert on_a != on_b, "two random nonces collided; this should be astronomically rare"


def run(ctx: Context) -> None:
    given_two_shards_when_sealing_the_same_value_then_deterministic_bytes_match(ctx)
    given_a_value_sealed_on_one_shard_when_read_on_the_other_then_no_reencryption_is_needed(ctx)
    given_two_shards_when_one_uses_a_different_aad_then_the_bytes_no_longer_match(ctx)
    given_two_shards_when_sealing_with_a_random_nonce_then_the_bytes_differ(ctx)
