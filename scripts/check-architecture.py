#!/usr/bin/env python3
"""Check explicit core dependencies and known test seams, not full C++ semantics."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE_HEADERS = {
    "gcm": {"gcm.h", "envelope.h", "nonce.h"},
    "nonce": {"nonce.h", "envelope.h"},
    "envelope": {"envelope.h"},
}
STANDARD_HEADERS = {"climits", "cstddef", "cstring", "memory"}
TEST_SEAMS = {"encrypt_with_nonce", "decrypt_session_has_key", "fault_inject_decrypt_init"}
TOKENS = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/')


def without_comments(text: str) -> str:
    # Keep strings and line numbers intact for include checks and diagnostics.
    return TOKENS.sub(lambda m: re.sub(r"[^\n]", " ", m[0]) if m[0].startswith("/") else m[0], text)


def check(root: Path) -> list[str]:
    problems: list[str] = []
    core_files = {
        root / "src" / f"{module}{suffix}" for module in CORE_HEADERS for suffix in (".cc", ".h")
    }
    for path in sorted(core_files):
        text = without_comments(path.read_text())
        for number, line in enumerate(text.splitlines(), 1):
            include = re.match(r"^\s*#\s*include\b\s*(.+)", line)
            if include:
                header = re.fullmatch(r'[<"]([^>"]+)[>"]\s*', include[1])
                name = header[1] if header else ""
                allowed = (
                    name in CORE_HEADERS[path.stem]
                    or name in STANDARD_HEADERS
                    or (path.stem != "envelope" and name.startswith("openssl/"))
                )
                if not allowed:
                    problems.append(
                        f"{path.relative_to(root)}:{number}: disallowed core include: {include[1]}"
                    )
            if re.search(r"\b(?:MYSQL_VERSION_ID|GCM_HAS_SESSION_SYSVAR)\b", line):
                problems.append(f"{path.relative_to(root)}:{number}: server version in core")

    for path in sorted((root / "src").rglob("*")):
        if path.suffix not in {".h", ".cc"} or path in core_files:
            continue
        for number, line in enumerate(without_comments(path.read_text()).splitlines(), 1):
            for seam in TEST_SEAMS:
                if re.search(rf"\b{re.escape(seam)}\b", line):
                    problems.append(
                        f"{path.relative_to(root)}:{number}: test seam in server adapter: {seam}"
                    )
    return problems


def main() -> int:
    problems = check(ROOT)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print("architecture: explicit core dependencies and known test seams OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
