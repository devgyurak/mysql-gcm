#!/usr/bin/env python3
"""Regenerate ``spec/test-vectors.json`` for the server's conformance tests.

This is an internal fixture generator, not an application encryption library.
Its fixed keys and nonces are public test inputs and must never be used for
application data. The MySQL component owns the runtime encryption API.

The file has two halves:

* ``kind: "nist"`` — NIST CAVP GCM known-answer tests, imported by
  ``scripts/import-nist.py`` (pass ``--rsp-dir``; without it the NIST cases
  already in the file are carried over unchanged, so the file can be
  regenerated offline).
* everything else — project vectors produced directly with ``cryptography``:
  deterministic envelopes, the v1 legacy envelope, and the failure
  cases (tampering, truncation, unknown version, wrong key length).

Nothing here is random: every nonce is either derived or hard-coded, so two runs
produce identical bytes and a diff means a real change.

    scripts/gen-vectors.py [--rsp-dir /tmp/gcmtestvectors] [--check]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "spec" / "test-vectors.json"
SCHEMA_VERSION = 1
DET_NONCE_LABEL = b"mysql-gcm/v1/det-nonce"

# The version byte is a function of the key length (design A10, spec §2).
# This mirrors kSuites in src/envelope.cc; the C++ vector test consumes both.
RANDOM_VERSION = {32: 0x02, 16: 0x04}
DET_VERSION = {32: 0x03, 16: 0x05}

#: Test key from the testing rule: never a real key, never PHI.
KEY = bytes(range(32))
#: A second key, used to show that a valid envelope fails under the wrong key.
KEY_ALT = bytes((b + 0x80) % 256 for b in range(32))

# design A10: the suite follows the key length, so the AES-128 fixture is just a
# shorter key. Deliberately NOT a prefix of KEY -- a prefix would make the
# truncation failure mode look like a legitimate fixture.
KEY_128 = bytes((b * 7 + 3) % 256 for b in range(16))
#: Fixed nonces for the random-variant vectors: production uses RAND_bytes, but a
#: vector has to be reproducible, so these are passed directly to AESGCM.
NONCE_A = bytes.fromhex("000000000000000000000001")
NONCE_B = bytes.fromhex("0f1e2d3c4b5a69788796a5b4")
#: Fixed IV for the legacy v1 vector.
IV_LEGACY = bytes.fromhex("101112131415161718191a1b1c1d1e1f")

HONG = "홍길동".encode()
KIM = "김철수".encode()


def _hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Fixture-only HMAC, using the vetted primitive from cryptography."""
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(message)
    return mac.finalize()


def _require(condition: bool, message: str) -> None:
    """Keep fixture validation active even when Python runs with optimization."""
    if not condition:
        raise ValueError(message)


def vec(**kw: Any) -> dict[str, Any]:
    """Order the keys the way the schema documents them."""
    order = [
        "id",
        "kind",
        "key_hex",
        "nonce_key_hex",
        "nonce_hex",
        "aad_hex",
        "plaintext_hex",
        "envelope_hex",
        "expect",
        "note",
    ]
    return {k: kw[k] for k in order if k in kw}


def det_vector(
    vid: str, plaintext: bytes, aad: bytes, note: str, key: bytes = KEY
) -> dict[str, Any]:
    version = DET_VERSION[len(key)]
    nonce_key = _hmac_sha256(key, DET_NONCE_LABEL)
    nonce = _hmac_sha256(nonce_key, plaintext)[:12]
    env = bytes([version]) + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
    return vec(
        id=vid,
        kind="det",
        key_hex=key.hex(),
        nonce_key_hex=nonce_key.hex(),
        nonce_hex=nonce.hex(),
        aad_hex=aad.hex(),
        plaintext_hex=plaintext.hex(),
        envelope_hex=env.hex(),
        expect="ok",
        note=note,
    )


def random_vector(
    vid: str, nonce: bytes, plaintext: bytes, aad: bytes, note: str, key: bytes = KEY
) -> dict[str, Any]:
    version = RANDOM_VERSION[len(key)]
    return vec(
        id=vid,
        kind="random",
        key_hex=key.hex(),
        nonce_hex=nonce.hex(),
        aad_hex=aad.hex(),
        plaintext_hex=plaintext.hex(),
        envelope_hex=(bytes([version]) + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)).hex(),
        expect="ok",
        note=note,
    )


def legacy_envelope(plaintext: bytes, key: bytes = KEY, iv: bytes = IV_LEGACY) -> bytes:
    """Build a v1 envelope the way a migration would: 0x01 || iv || CBC(PKCS#7)."""
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return bytes([0x01]) + iv + enc.update(padded) + enc.finalize()


def flip_last_bit(data: bytes, index: int) -> bytes:
    out = bytearray(data)
    out[index] ^= 0x01
    return bytes(out)


def project_vectors() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    # --- deterministic variant -------------------------------------------------
    out.append(det_vector("det-empty", b"", b"", "empty plaintext still produces 29 bytes"))
    out.append(det_vector("det-korean-hong", HONG, b"", "the Korean LIKE case, UTF-8 encoded"))
    out.append(det_vector("det-korean-kim", KIM, b"", "second Korean name, different nonce"))
    out.append(det_vector("det-ascii", b"patient-42", b"", "join-key shaped value"))
    out.append(det_vector("det-aad", b"patient-42", b"patients.emr_id", "AAD binds the column"))
    out.append(
        det_vector("det-256b", bytes(range(256)), b"", "every byte value, no UTF-8 assumption")
    )

    same = det_vector(
        "det-korean-hong-repeat", HONG, b"", "same input as det-korean-hong: same bytes"
    )
    _require(same["envelope_hex"] == out[1]["envelope_hex"], "determinism broken")
    out.append(same)

    # --- random variant (replayed with a fixed nonce) --------------------------
    out.append(random_vector("random-empty", NONCE_A, b"", b"", "empty plaintext, empty AAD"))
    out.append(
        random_vector("random-korean", NONCE_B, HONG, b"", "random-nonce twin of det-korean-hong")
    )
    out.append(random_vector("random-aad", NONCE_B, b"patient-42", b"patients.emr_id", "AAD bound"))

    # --- legacy v1 (decrypt only) ---------------------------------------------
    out.append(
        vec(
            id="legacy-cbc-korean",
            kind="legacy",
            key_hex=KEY.hex(),
            nonce_hex=IV_LEGACY.hex(),
            aad_hex="",
            plaintext_hex=HONG.hex(),
            envelope_hex=legacy_envelope(HONG).hex(),
            expect="ok",
            note="dual-read: 0x01 || iv || AES-256-CBC(PKCS#7); never produced by the component",
        )
    )
    out.append(
        vec(
            id="legacy-cbc-block-aligned",
            kind="legacy",
            key_hex=KEY.hex(),
            nonce_hex=IV_LEGACY.hex(),
            aad_hex="",
            plaintext_hex=(b"0123456789abcdef").hex(),
            envelope_hex=legacy_envelope(b"0123456789abcdef").hex(),
            expect="ok",
            note="exactly one block of plaintext gets a full block of padding",
        )
    )

    # --- failure: tampering ----------------------------------------------------
    good = bytes.fromhex(str(out[1]["envelope_hex"]))  # det-korean-hong
    tamper = [
        ("bad-tag-last-byte", flip_last_bit(good, len(good) - 1), "tag bit flipped"),
        ("bad-tag-nonce-flip", flip_last_bit(good, 1), "nonce bit flipped: tag no longer verifies"),
        ("bad-tag-ct-flip", flip_last_bit(good, 13), "ciphertext bit flipped"),
    ]
    for vid, env, note in tamper:
        out.append(
            vec(
                id=vid,
                kind="det",
                key_hex=KEY.hex(),
                aad_hex="",
                plaintext_hex="",
                envelope_hex=env.hex(),
                expect="bad_tag",
                note=note,
            )
        )
    out.append(
        vec(
            id="bad-tag-wrong-key",
            kind="det",
            key_hex=KEY_ALT.hex(),
            aad_hex="",
            plaintext_hex="",
            envelope_hex=good.hex(),
            expect="bad_tag",
            note="valid envelope, wrong key: authentication, not garbage plaintext",
        )
    )
    out.append(
        vec(
            id="bad-tag-aad-mismatch",
            kind="det",
            key_hex=KEY.hex(),
            aad_hex=b"other.column".hex(),
            plaintext_hex="",
            envelope_hex=str(out[4]["envelope_hex"]),
            expect="bad_tag",
            note="det-aad decrypted with a different AAD",
        )
    )

    # --- failure: malformed envelope ------------------------------------------
    for n in (0, 1, 12, 28):
        out.append(
            vec(
                id=f"bad-envelope-truncated-{n}",
                kind="det",
                key_hex=KEY.hex(),
                aad_hex="",
                plaintext_hex="",
                envelope_hex=good[:n].hex(),
                expect="bad_envelope",
                note=f"{n} bytes: below the 29-byte minimum",
            )
        )
    # 0x04 and 0x05 left this list when AES-128 took them (design A10). 0x06 and
    # 0x07 are allocated to AES-192 by the same amendment but are NOT implemented,
    # so they must still be rejected -- that is the case most likely to rot into a
    # silent accept when the suite table grows, which is why it is pinned here.
    for version in (0x00, 0x06, 0x07, 0x7F, 0xFF):
        body = bytes([version]) + good[1:]
        out.append(
            vec(
                id=f"bad-envelope-version-{version:02x}",
                kind="det",
                key_hex=KEY.hex(),
                aad_hex="",
                plaintext_hex="",
                envelope_hex=body.hex(),
                expect="bad_envelope",
                note="unimplemented or reserved version byte is an error, never a NULL",
            )
        )
    legacy = legacy_envelope(HONG)
    out.append(
        vec(
            id="bad-envelope-legacy-misaligned",
            kind="legacy",
            key_hex=KEY.hex(),
            aad_hex="",
            plaintext_hex="",
            envelope_hex=legacy[:-1].hex(),
            expect="bad_envelope",
            note="v1 body must be a multiple of the 16-byte block",
        )
    )
    out.append(
        vec(
            id="bad-envelope-legacy-short",
            kind="legacy",
            key_hex=KEY.hex(),
            aad_hex="",
            plaintext_hex="",
            envelope_hex=legacy[:20].hex(),
            expect="bad_envelope",
            note="v1 needs version + iv + at least one block (33 bytes)",
        )
    )
    out.append(
        vec(
            id="bad-envelope-legacy-with-aad",
            kind="legacy",
            key_hex=KEY.hex(),
            aad_hex=b"patients.emr_id".hex(),
            plaintext_hex="",
            envelope_hex=legacy.hex(),
            expect="bad_envelope",
            note="v1 is unauthenticated and cannot bind an AAD (design A3)",
        )
    )

    # --- AES-128 (design A10) --------------------------------------------------
    out.append(
        random_vector(
            "aes128-random-korean",
            NONCE_A,
            HONG,
            b"",
            "0x04: AES-128-GCM random, the key length selects the suite",
            key=KEY_128,
        )
    )
    out.append(
        det_vector(
            "aes128-det-korean",
            HONG,
            b"",
            "0x05: AES-128-GCM deterministic, same layout as 0x03",
            key=KEY_128,
        )
    )
    out.append(
        det_vector(
            "aes128-det-empty",
            b"",
            b"",
            "0x05 over an empty plaintext is still 29 bytes",
            key=KEY_128,
        )
    )
    out.append(
        det_vector(
            "aes128-det-with-aad",
            KIM,
            b"patients.name",
            "0x05 with an AAD; the AAD is not an input to the nonce (design §5.2)",
            key=KEY_128,
        )
    )

    # --- failure: key length ---------------------------------------------------
    # 16 is no longer here: it is a valid AES-128 key (design A10). 15 and 17
    # bracket it, and 24 pins that AES-192 is NOT implemented -- the suite table
    # has two rows, and a 24-byte key must not be folded into one of them.
    for n in (0, 15, 17, 24, 31, 33, 64):
        out.append(
            vec(
                id=f"bad-key-len-{n}",
                kind="det",
                key_hex=bytes(range(n)).hex(),
                aad_hex="",
                plaintext_hex=HONG.hex(),
                envelope_hex=good.hex(),
                expect="bad_key_len",
                note=f"{n}-byte key: error, never folded or padded to a suite length",
            )
        )

    # --- failure: the key length disagrees with the version byte (design A10) ---
    out.append(
        vec(
            id="bad-key-len-suite-mismatch-256-envelope-128-key",
            kind="det",
            key_hex=KEY_128.hex(),
            aad_hex="",
            plaintext_hex=HONG.hex(),
            envelope_hex=good.hex(),
            expect="bad_key_len",
            note="0x03 envelope read with a 16-byte key: bad_key_len, never bad_tag",
        )
    )
    out.append(
        vec(
            id="bad-key-len-suite-mismatch-128-envelope-256-key",
            kind="det",
            key_hex=KEY.hex(),
            aad_hex="",
            plaintext_hex=HONG.hex(),
            envelope_hex=(
                bytes([DET_VERSION[16]])
                + _hmac_sha256(_hmac_sha256(KEY_128, DET_NONCE_LABEL), HONG)[:12]
                + AESGCM(KEY_128).encrypt(
                    _hmac_sha256(_hmac_sha256(KEY_128, DET_NONCE_LABEL), HONG)[:12], HONG, b""
                )
            ).hex(),
            expect="bad_key_len",
            note="0x05 envelope read with a 32-byte key: bad_key_len, never bad_tag",
        )
    )
    return out


def nist_vectors(rsp_dir: Path | None, previous: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if rsp_dir is None:
        carried = [v for v in previous if v.get("kind") == "nist"]
        if not carried:
            print(
                "warning: no NIST vectors carried over and --rsp-dir not given",
                file=sys.stderr,
            )
        return carried
    sys.path.insert(0, str(ROOT / "scripts"))
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "import_nist", ROOT / "scripts" / "import-nist.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the NIST vector importer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses needs the module registered
    spec.loader.exec_module(module)
    return list(module.vectors(rsp_dir))


def _verify_failure(v: dict[str, Any]) -> None:
    """Check that a fixture which claims to fail actually does.

    Without this, a generator slip could emit a `bad_tag` fixture whose tag verifies
    cleanly and `--check` would still pass — the file would then assert the opposite
    of what the C++ suite reads from it. Kept narrow on purpose: these are assertions
    over the fixtures, not a general envelope parser or decrypt API (stack-python).
    """
    key = bytes.fromhex(str(v["key_hex"]))
    aad = bytes.fromhex(str(v["aad_hex"]))
    env = bytes.fromhex(str(v["envelope_hex"]))
    expect = str(v["expect"])

    if expect == "bad_key_len":
        # design A10: two ways to earn this. Either the key length is not one a
        # suite has, or it is -- and disagrees with the envelope's version byte.
        # The second is the case that must not collapse into bad_tag.
        version = env[0] if env else None
        no_such_suite = len(key) not in RANDOM_VERSION
        wrong_suite = version is not None and version not in (
            RANDOM_VERSION.get(len(key)),
            DET_VERSION.get(len(key)),
        )
        _require(
            no_such_suite or wrong_suite,
            f"{v['id']}: bad_key_len fixture has a key that matches its envelope",
        )
        return

    if expect == "bad_envelope":
        version = env[0] if env else None
        structural = (
            version not in (0x01, 0x02, 0x03, 0x04, 0x05)
            or (version in (0x02, 0x03, 0x04, 0x05) and len(env) < 29)
            or (version == 0x01 and (len(env) < 33 or (len(env) - 17) % 16 != 0))
            or (version == 0x01 and bool(aad))
        )
        _require(structural, f"{v['id']}: bad_envelope fixture is structurally valid")
        return

    if expect == "bad_tag":
        _require(len(env) >= 29, f"{v['id']}: bad_tag fixture is too short to reach the tag")
        _require(
            env[0] in (0x02, 0x03, 0x04, 0x05),
            f"{v['id']}: bad_tag fixture is not a GCM envelope",
        )
        authenticates = True
        try:
            AESGCM(key).decrypt(env[1:13], env[13:], aad)
        except InvalidTag:
            authenticates = False
        _require(not authenticates, f"{v['id']}: bad_tag fixture authenticates successfully")
        return

    _require(False, f"{v['id']}: unknown expect value {expect!r}")


def verify(vectors: list[dict[str, Any]]) -> None:
    """Check every fixture with cryptography before writing the file.

    The `ok` fixtures are decrypted (and re-sealed, for the deterministic ones); the
    failing fixtures are checked to actually fail, so the file cannot claim a failure
    it does not have. Malformed-input handling in the server is covered by the C++ and
    SQL suites; nothing here is exported as a reusable envelope API.
    """
    for v in vectors:
        if v["expect"] != "ok":
            _verify_failure(v)
            continue
        key = bytes.fromhex(str(v["key_hex"]))
        aad = bytes.fromhex(str(v["aad_hex"]))
        env = bytes.fromhex(str(v["envelope_hex"]))
        plaintext = bytes.fromhex(str(v["plaintext_hex"]))
        if v["kind"] == "legacy":
            _require(env[0] == 0x01 and not aad, f"{v['id']}: invalid legacy fixture")
            dec = Cipher(algorithms.AES(key), modes.CBC(env[1:17])).decryptor()
            padded = dec.update(env[17:]) + dec.finalize()
            unpadder = PKCS7(128).unpadder()
            actual = unpadder.update(padded) + unpadder.finalize()
        else:
            _require(env[0] in (0x02, 0x03, 0x04, 0x05), f"{v['id']}: wrong version byte")
            _require(
                env[0] in (RANDOM_VERSION[len(key)], DET_VERSION[len(key)]),
                f"{v['id']}: version byte does not match the key length",
            )
            actual = AESGCM(key).decrypt(env[1:13], env[13:], aad)
        _require(actual == plaintext, f"{v['id']}: decrypt mismatch")
        if v["kind"] == "det":
            nonce_key = _hmac_sha256(key, DET_NONCE_LABEL)
            nonce = _hmac_sha256(nonce_key, plaintext)[:12]
            expected = (
                bytes([DET_VERSION[len(key)]]) + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
            )
            _require(expected == env, f"{v['id']}: not deterministic")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rsp-dir", type=Path, help="unzipped NIST gcmtestvectors directory")
    ap.add_argument("--check", action="store_true", help="fail if the file would change")
    args = ap.parse_args()

    previous: list[dict[str, Any]] = []
    if SPEC.is_file():
        previous = json.loads(SPEC.read_text())["vectors"]

    vectors = nist_vectors(args.rsp_dir, previous) + project_vectors()
    verify(vectors)
    payload = {
        "version": SCHEMA_VERSION,
        "spec": "spec/envelope.md",
        "generated_by": "scripts/gen-vectors.py",
        "vectors": vectors,
    }
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        current = SPEC.read_text() if SPEC.is_file() else ""
        if current != text:
            print("spec/test-vectors.json is stale: run scripts/gen-vectors.py", file=sys.stderr)
            return 1
        print(f"{len(vectors)} vectors up to date", file=sys.stderr)
        return 0

    SPEC.write_text(text)
    kinds: dict[str, int] = {}
    for v in vectors:
        kinds[str(v["kind"])] = kinds.get(str(v["kind"]), 0) + 1
    print(f"{len(vectors)} vectors -> {SPEC} {kinds}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
