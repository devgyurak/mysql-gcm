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

ENCRYPT_RSP = "gcmEncryptExtIV256.rsp"
DECRYPT_RSP = "gcmDecrypt256.rsp"
WANTED = {"Keylen": "256", "IVlen": "96", "Taglen": "128"}


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
    return [c for c in cases if all(c.header.get(k) == v for k, v in WANTED.items())]


def envelope_hex(iv: str, ct: str, tag: str) -> str:
    """v2 envelope for a CAVP case: 0x02 || iv(12) || ct || tag(16)."""
    return f"02{iv}{ct}{tag}"


def vectors(rsp_dir: Path) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for case in parse_rsp(rsp_dir / ENCRYPT_RSP):
        f, h = case.fields, case.header
        out.append(
            {
                "id": f"nist-enc-pt{h['PTlen']}-aad{h['AADlen']}-{f['Count']}",
                "kind": "nist",
                "key_hex": f["Key"],
                "nonce_hex": f["IV"],
                "aad_hex": f["AAD"],
                "plaintext_hex": f["PT"],
                "envelope_hex": envelope_hex(f["IV"], f["CT"], f["Tag"]),
                "expect": "ok",
                "note": f"CAVP {ENCRYPT_RSP} Count={f['Count']}",
            }
        )
    for case in parse_rsp(rsp_dir / DECRYPT_RSP):
        f, h = case.fields, case.header
        out.append(
            {
                "id": f"nist-dec-pt{h['PTlen']}-aad{h['AADlen']}-{f['Count']}",
                "kind": "nist",
                "key_hex": f["Key"],
                "nonce_hex": f["IV"],
                "aad_hex": f["AAD"],
                "plaintext_hex": "" if case.failed else f["PT"],
                "envelope_hex": envelope_hex(f["IV"], f["CT"], f["Tag"]),
                "expect": "bad_tag" if case.failed else "ok",
                "note": f"CAVP {DECRYPT_RSP} Count={f['Count']}",
            }
        )
    out.sort(key=lambda v: str(v["id"]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rsp-dir", type=Path, required=True, help="unzipped gcmtestvectors directory")
    ap.add_argument("--out", type=Path, help="write JSON here instead of stdout")
    args = ap.parse_args()

    for name in (ENCRYPT_RSP, DECRYPT_RSP):
        if not (args.rsp_dir / name).is_file():
            print(f"missing {args.rsp_dir / name}", file=sys.stderr)
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
