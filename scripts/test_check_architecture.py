"""Regression checks for scripts/check-architecture.py's fault-macro rule."""

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "check_architecture", ROOT / "scripts" / "check-architecture.py"
)
if _spec is None or _spec.loader is None:
    raise ImportError("cannot load scripts/check-architecture.py")
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)


def tree_with(relative: str, line: str) -> Path:
    """A copy of src/ and docker/ with one line appended to one file."""
    work = Path(tempfile.mkdtemp())
    shutil.copytree(ROOT / "src", work / "src")
    shutil.copytree(ROOT / "docker", work / "docker")
    target = work / relative
    target.write_text(target.read_text() + line + "\n")
    return work


class FaultMacro(unittest.TestCase):
    def test_given_the_repository_when_checked_then_the_ifdef_uses_pass(self) -> None:
        # Given: src/ as committed, which tests the macro with #ifdef only.
        root = ROOT
        # When
        problems = checker.fault_macro_problems(root)
        # Then
        self.assertEqual(problems, [])

    def test_given_a_define_in_a_header_when_checked_then_refused(self) -> None:
        # Given: the define the review slipped past the previous version of the check.
        root = tree_with("src/gcm.h", "#define GCM_FAULT_INJECTION 1")
        # When
        problems = checker.fault_macro_problems(root)
        # Then
        self.assertEqual(len(problems), 1)
        self.assertIn("src/gcm.h", problems[0])
        shutil.rmtree(root)

    def test_given_a_define_in_a_source_file_when_checked_then_refused(self) -> None:
        # Given
        root = tree_with("src/gcm.cc", "#  define GCM_FAULT_INJECTION")
        # When
        problems = checker.fault_macro_problems(root)
        # Then
        self.assertEqual(len(problems), 1)
        shutil.rmtree(root)

    def test_given_a_cmake_compile_definition_when_checked_then_refused(self) -> None:
        # Given
        root = tree_with("src/CMakeLists.txt", "add_compile_definitions(GCM_FAULT_INJECTION)")
        # When
        problems = checker.fault_macro_problems(root)
        # Then
        self.assertEqual(len(problems), 1)
        self.assertIn("src/CMakeLists.txt", problems[0])
        shutil.rmtree(root)

    def test_given_a_compiler_flag_in_a_docker_script_when_checked_then_refused(self) -> None:
        # Given
        root = tree_with("docker/build-component.sh", 'export CXXFLAGS="-DGCM_FAULT_INJECTION"')
        # When
        problems = checker.fault_macro_problems(root)
        # Then
        self.assertEqual(len(problems), 1)
        shutil.rmtree(root)

    def test_given_a_mention_in_a_comment_when_checked_then_allowed(self) -> None:
        # Given: a header comment and a CMake comment naming the macro.
        root = tree_with("src/gcm.h", "/* GCM_FAULT_INJECTION is defined by tests/unit only */")
        cmake = root / "src" / "CMakeLists.txt"
        cmake.write_text(cmake.read_text() + "# never define GCM_FAULT_INJECTION here\n")
        # When
        problems = checker.fault_macro_problems(root)
        # Then
        self.assertEqual(problems, [])
        shutil.rmtree(root)


if __name__ == "__main__":
    unittest.main()
