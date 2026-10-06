#!/usr/bin/env python3
"""Convert NIST CAVP GCM response files into mysql-gcm test vectors.

Only the ``[Keylen=256][IVlen=96][Taglen=128]`` blocks are relevant: the
component fixes AES-256, a 96-bit nonce and a 128-bit tag (crypto-safety rule),
so the other parameter blocks describe configurations we deliberately cannot
produce.

The CAVP archive is not vendored (9 MB, and NIST is the authoritative copy):

    curl -LO https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
    unzip gcmtestvectors.zip -d /tmp/gcmtestvectors
    scripts/import-nist.py --rsp-dir /tmp/gcmtestvectors

Output is sorted and stable so regenerating produces no spurious diff.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

# One entry per suite (design A10). The version byte is a function of the key
# length, so the importer carries it alongside the file names rather than
# hardcoding 0x02 the way the single-suite version did.
SUITES = (
    {
        "bits": "256",
        "encrypt": "gcmEncryptExtIV256.rsp",
        "decrypt": "gcmDecrypt256.rsp",
        "version": "02",
    },
    {
        "bits": "128",
        "encrypt": "gcmEncryptExtIV128.rsp",
        "decrypt": "gcmDecrypt128.rsp",
        "version": "04",
    },
)
WANTED_IV_TAG = {"IVlen": "96", "Taglen": "128"}


@dataclass(frozen=True)
class Case:
    header: dict[str, str]
    fields: dict[str, str]
    failed: bool


def parse_rsp(path: Path) -> list[Case]:
    """Parse a CAVP ``.rsp`` file into (parameter block, case) pairs."""
    header: dict[str, str] = {}
    fields: dict[str, str] = {}
    failed = False
    cases: list[Case] = []

    def flush() -> None:
        nonlocal fields, failed
        if fields:
            cases.append(Case(dict(header), dict(fields), failed))
        fields, failed = {}, False

    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line:
            flush()
            continue
        if line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            flush()
            key, value = line[1:-1].split("=", 1)
            header[key.strip()] = value.strip()
            continue
        if line == "FAIL":
            failed = True
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key.strip()] = value.strip()
    flush()
    return [c for c in cases if all(c.header.get(k) == v for k, v in WANTED_IV_TAG.items())]


def envelope_hex(iv: str, ct: str, tag: str, version: str) -> str:
    """Random-nonce envelope for a CAVP case: version || iv(12) || ct || tag(16)."""
    return f"{version}{iv}{ct}{tag}"


def vectors(rsp_dir: Path) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for suite in SUITES:
        bits, version = suite["bits"], suite["version"]
        for case in parse_rsp(rsp_dir / suite["encrypt"]):
            f, h = case.fields, case.header
            out.append(
                {
                    "id": f"nist{bits}-enc-pt{h['PTlen']}-aad{h['AADlen']}-{f['Count']}",
                    "kind": "nist",
                    "key_hex": f["Key"],
                    "nonce_hex": f["IV"],
                    "aad_hex": f["AAD"],
                    "plaintext_hex": f["PT"],
                    "envelope_hex": envelope_hex(f["IV"], f["CT"], f["Tag"], version),
                    "expect": "ok",
                    "note": f"CAVP {suite['encrypt']} Count={f['Count']}",
                }
            )
        for case in parse_rsp(rsp_dir / suite["decrypt"]):
            f, h = case.fields, case.header
            out.append(
                {
                    "id": f"nist{bits}-dec-pt{h['PTlen']}-aad{h['AADlen']}-{f['Count']}",
                    "kind": "nist",
                    "key_hex": f["Key"],
                    "nonce_hex": f["IV"],
                    "aad_hex": f["AAD"],
                    "plaintext_hex": "" if case.failed else f["PT"],
                    "envelope_hex": envelope_hex(f["IV"], f["CT"], f["Tag"], version),
                    "expect": "bad_tag" if case.failed else "ok",
                    "note": f"CAVP {suite['decrypt']} Count={f['Count']}",
                }
            )
    out.sort(key=lambda v: str(v["id"]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rsp-dir", type=Path, required=True, help="unzipped gcmtestvectors directory")
    ap.add_argument("--out", type=Path, help="write JSON here instead of stdout")
    args = ap.parse_args()

    for suite in SUITES:
        for key in ("encrypt", "decrypt"):
            if not (args.rsp_dir / suite[key]).is_file():
                print(f"missing {args.rsp_dir / suite[key]}", file=sys.stderr)
                return 2

    data = vectors(args.rsp_dir)
    text = json.dumps(data, indent=2, sort_keys=False) + "\n"
    if args.out:
        args.out.write_text(text)
        print(f"{len(data)} NIST vectors -> {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
