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
    # Not cryptographic core, but held to the same server independence (amendment A14).
    "usage": {"usage.h"},
}
NO_OPENSSL = {"envelope", "usage"}
STANDARD_HEADERS = {"climits", "cstddef", "cstdint", "cstdlib", "cstring", "memory", "mutex"}
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
                    or (path.stem not in NO_OPENSSL and name.startswith("openssl/"))
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
    problems += fault_macro_problems(root)
    problems += probe_problems(root)
    return problems


FAULT_MACRO = "GCM_FAULT_INJECTION"
# The only uses a source file may make of the macro: testing whether it is defined.
FAULT_MACRO_TEST = re.compile(r"^\s*#\s*(?:if|ifdef|ifndef|elif|endif)\b")


def fault_macro_problems(root: Path) -> list[str]:
    """The fault seam must only ever be compiled into tests/unit.

    Defining GCM_FAULT_INJECTION anywhere the component is built from -- a #define in a
    header or source file, a compile definition in CMake, a flag in a docker script --
    would ship an injection point in the .so. Source files may *test* the macro
    (#ifdef / #if defined / #endif); every other mention under src/ and docker/ is
    refused, comments excepted. Judged per line, not per file type, so a #define in a
    header is caught as surely as one in CMakeLists.txt.
    """
    problems: list[str] = []
    for path in [*sorted((root / "src").rglob("*")), *sorted((root / "docker").rglob("*"))]:
        if not path.is_file() or path.suffix == ".png":
            continue
        text = path.read_text(errors="ignore")
        is_source = path.suffix in {".h", ".cc"}
        if is_source:
            text = without_comments(text)
        for number, line in enumerate(text.splitlines(), 1):
            if FAULT_MACRO not in line:
                continue
            if is_source and FAULT_MACRO_TEST.match(line):
                continue
            # CMake, shell and Dockerfile comments start with '#'; a source line starting
            # with '#' is a directive and is judged above, not skipped here.
            if not is_source and line.lstrip().startswith("#"):
                continue
            problems.append(
                f"{path.relative_to(root)}:{number}: {FAULT_MACRO} defined outside tests"
            )
    return problems


def probe_problems(root: Path) -> list[str]:
    """The probe component is scaffolding and must never reach a shipped artifact.

    `tests/probe` registers five throwaway UDFs to pin the nested-function server
    defect (issue #43). It is built only by `scripts/build-probe.sh`, from its own
    directory, into a throwaway server — never by the component build. The name
    `probe` is reserved for it, so any occurrence under `src/` (the component) or
    `docker/` (the build tree and the images) means the scaffolding would ship in
    the `.so`. Comments are not exempt: a copy in a CMake comment or a Dockerfile is
    exactly how it would get in.
    """
    problems: list[str] = []
    for tree in ("src", "docker"):
        for path in sorted((root / tree).rglob("*")):
            if not path.is_file() or path.suffix == ".png":
                continue
            for number, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
                if "probe" in line.lower():
                    problems.append(
                        f"{path.relative_to(root)}:{number}: 'probe' is reserved for the test-only "
                        f"component (tests/probe) and must not appear in a shipped tree"
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
