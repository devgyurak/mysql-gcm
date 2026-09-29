#!/usr/bin/env python3
"""Every `uses:` in .github/workflows must name a commit SHA, with the tag in a comment.

A tag reference is mutable. `actions/checkout@v4` is whatever the owner last pointed v4
at, and an action runs inside this workflow with its token — in release.yml, alongside the
OIDC identity that signs the checksums consumers are told to verify. Pinning by SHA makes
an upgrade a commit somebody reviews rather than something that happens overnight.

The trailing `# <tag>` comment is required too: a bare 40-hex string tells a reader nothing
about which version it is or how far behind.

Refresh a pin with:
    gh api repos/<owner>/<action>/commits/<tag> -q .sha

This replaced a shell version that matched `uses:` only when it followed a `-` at the start
of a line, so `- { uses: actions/checkout@v4 }` passed the check unexamined. This repository
uses flow style throughout, so that was a real hole rather than a theoretical one.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

WORKFLOW_DIR = Path(__file__).resolve().parent.parent / ".github" / "workflows"
SHA_PINNED = re.compile(r"@[0-9a-f]{40}$")
DIGEST_PINNED = re.compile(r"@sha256:[0-9a-f]{64}$")


def workflow_files() -> list[Path]:
    """Both extensions: GitHub reads .yml and .yaml, and so does actionlint."""
    return sorted(p for p in WORKFLOW_DIR.iterdir() if p.suffix in {".yml", ".yaml"})


def uses_references(path: Path) -> list[tuple[int, str, str]]:
    """Every (line number, reference, rest of line) for a `uses:` on that line.

    Deliberately textual rather than a YAML parse: it needs the trailing comment, which a
    parser discards, and it must keep working without PyYAML installed so the lint job
    needs no dependency step.
    """
    found: list[tuple[int, str, str]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.lstrip().startswith("#") or "uses:" not in line:
            continue
        after = line.split("uses:", 1)[1]
        token = after.strip().split()[0] if after.strip() else ""
        reference = token.strip("'\"").rstrip(",}").strip("'\"")
        found.append((number, reference, after))
    return found


def main() -> int:
    if len(sys.argv) > 1:
        print(__doc__, file=sys.stderr)
        print("usage: scripts/check-action-pins.py", file=sys.stderr)
        return 2

    unpinned: list[str] = []
    uncommented: list[str] = []
    total = 0

    for path in workflow_files():
        for number, reference, after in uses_references(path):
            # A local action has no ref to pin.
            if reference.startswith("./"):
                continue
            total += 1
            where = f"{path.relative_to(WORKFLOW_DIR.parent.parent)}:{number}: {reference}"
            pinned = SHA_PINNED.search(reference) or DIGEST_PINNED.search(reference)
            if not pinned:
                unpinned.append(where)
            elif not re.search(r"#\s*\S", after.split(reference, 1)[-1]):
                uncommented.append(where)

    if total == 0:
        where = str(WORKFLOW_DIR)
        print(f"no 'uses:' found under {where} — is the path right?", file=sys.stderr)
        return 1

    if unpinned:
        print("these actions use a mutable tag or branch, not a commit SHA:", file=sys.stderr)
        print("\n".join(f"  {entry}" for entry in unpinned), file=sys.stderr)
    if uncommented:
        print("these actions are pinned but do not say which version the SHA is:", file=sys.stderr)
        print("\n".join(f"  {entry}" for entry in uncommented), file=sys.stderr)
    if unpinned or uncommented:
        return 1

    print(f"action pins: {total} references, all pinned to a commit SHA with a version comment")
    return 0


if __name__ == "__main__":
    sys.exit(main())
