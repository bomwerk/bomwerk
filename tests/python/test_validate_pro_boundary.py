#!/usr/bin/env python3
"""Adversarial tests for the Community boundary validator."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = REPOSITORY_ROOT / "scripts" / "validate_pro_boundary.py"
MODULE_SPEC = importlib.util.spec_from_file_location("validate_pro_boundary", VALIDATOR_PATH)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise RuntimeError(f"cannot load boundary validator from {VALIDATOR_PATH}")
BOUNDARY = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(BOUNDARY)

# Modeled on the real CLI11 output, including the wrapped continuation lines
# trim's and binscan's long descriptions actually produce. A regex over this
# section previously mistook a wrapped line's first word ("actually",
# "components", "dynamic") for a fifth subcommand: this fixture is here so
# that regression stays caught.
PUBLIC_HELP = """A build-accurate SBOM scanner

SUBCOMMANDS:
  scan                        Scan a directory and report the components it
                               declares.
  observe                     Run a build under bomwerk's compiler shims and
                               record what it actually compiled and linked.
  trim                        Compare an SBOM against a recorded build trace
                               and report which components the build
                               actually compiled, linked, or included.
  binscan                     Read the binaries a recorded build produced and
                               report the dynamic dependencies, archive
                               contents and symbols they carry.
"""


def completed_process(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, "")


class SourceTreeValidationTest(unittest.TestCase):
    def make_public_tree(self, root: Path) -> None:
        for module in BOUNDARY.PUBLIC_SOURCE_MODULES:
            (root / "src" / module).mkdir(parents=True)

    def test_public_tree_is_accepted(self) -> None:
        # Given a tree holding only public modules, Then nothing is reported.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory)
            self.make_public_tree(repository_root)
            errors: list[str] = []
            with mock.patch.object(BOUNDARY, "list_tracked_paths", return_value=["src/core/a.cpp"]):
                BOUNDARY.validate_source_tree(repository_root, errors)
            self.assertEqual(errors, [])

    def test_unknown_source_module_is_rejected(self) -> None:
        # Given a paid module on disk, Then it is reported even without git.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory)
            self.make_public_tree(repository_root)
            (repository_root / "src" / "paid_addon").mkdir()
            errors: list[str] = []
            with mock.patch.object(BOUNDARY, "list_tracked_paths", return_value=None):
                BOUNDARY.validate_source_tree(repository_root, errors)
            self.assertTrue(any("paid_addon" in error for error in errors), errors)

    def test_tracked_path_outside_the_public_layout_is_rejected(self) -> None:
        # Given any tracked file the layout does not declare, Then git's own
        # listing catches it.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory)
            self.make_public_tree(repository_root)
            errors: list[str] = []
            with mock.patch.object(
                BOUNDARY, "list_tracked_paths", return_value=["src/core/a.cpp", "INTERNAL-NOTES.md"]
            ):
                BOUNDARY.validate_source_tree(repository_root, errors)
            self.assertTrue(any("INTERNAL-NOTES.md" in error for error in errors), errors)

    def test_missing_source_root_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            errors: list[str] = []
            with mock.patch.object(BOUNDARY, "list_tracked_paths", return_value=[]):
                BOUNDARY.validate_source_tree(Path(temporary_directory), errors)
            self.assertTrue(any("no src directory" in error for error in errors), errors)


class CompileCommandsValidationTest(unittest.TestCase):
    def write_compile_commands(self, build_directory: Path, entries: object) -> None:
        build_directory.mkdir(parents=True, exist_ok=True)
        (build_directory / "compile_commands.json").write_text(
            json.dumps(entries), encoding="utf-8"
        )

    def test_public_translation_units_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory) / "repository"
            build_directory = repository_root / "build"
            (repository_root / "src" / "core").mkdir(parents=True)
            self.write_compile_commands(
                build_directory, [{"file": str(repository_root / "src" / "core" / "result.cpp")}]
            )
            errors: list[str] = []
            BOUNDARY.validate_compile_commands(build_directory, repository_root, errors)
            self.assertEqual(errors, [])

    def test_composed_private_source_is_rejected(self) -> None:
        # Given a translation unit from a sibling private checkout,
        # Then the build is not a Community build.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory) / "repository"
            private_root = Path(temporary_directory) / "vendor-extension"
            build_directory = repository_root / "build"
            (repository_root / "src" / "core").mkdir(parents=True)
            self.write_compile_commands(
                build_directory, [{"file": str(private_root / "src" / "paid_addon" / "feature.cpp")}]
            )
            errors: list[str] = []
            BOUNDARY.validate_compile_commands(build_directory, repository_root, errors)
            self.assertTrue(any("outside this repository" in error for error in errors), errors)

    def test_non_public_module_inside_the_repository_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory) / "repository"
            build_directory = repository_root / "build"
            (repository_root / "src" / "paid_addon").mkdir(parents=True)
            self.write_compile_commands(
                build_directory, [{"file": str(repository_root / "src" / "paid_addon" / "gate.cpp")}]
            )
            errors: list[str] = []
            BOUNDARY.validate_compile_commands(build_directory, repository_root, errors)
            self.assertTrue(any("public layout" in error for error in errors), errors)

    def test_unreadable_compile_database_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory)
            errors: list[str] = []
            BOUNDARY.validate_compile_commands(
                repository_root / "absent-build", repository_root, errors
            )
            self.assertTrue(any("cannot read" in error for error in errors), errors)

    def test_non_array_compile_database_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory)
            build_directory = repository_root / "build"
            self.write_compile_commands(build_directory, {"file": "nope"})
            errors: list[str] = []
            BOUNDARY.validate_compile_commands(build_directory, repository_root, errors)
            self.assertTrue(any("JSON array" in error for error in errors), errors)


class CommandTreeValidationTest(unittest.TestCase):
    def test_public_command_tree_is_accepted(self) -> None:
        with mock.patch.object(
            BOUNDARY,
            "run",
            side_effect=[
                completed_process(PUBLIC_HELP),
                completed_process(PUBLIC_HELP),
                completed_process("", BOUNDARY.kIncompleteExitCode),
            ],
        ):
            errors: list[str] = []
            BOUNDARY.validate_cli(Path("bomwerk"), errors)
            self.assertEqual(errors, [])

    def test_extra_command_is_rejected(self) -> None:
        # Given any command beyond the public four, Then it is reported without
        # this test naming a paid command.
        paid_help = PUBLIC_HELP + "  extra-command              Not a Community command\n"
        with mock.patch.object(
            BOUNDARY,
            "run",
            side_effect=[
                completed_process(paid_help),
                completed_process(paid_help),
                completed_process("", BOUNDARY.kIncompleteExitCode),
            ],
        ):
            errors: list[str] = []
            BOUNDARY.validate_cli(Path("bomwerk"), errors)
            self.assertTrue(any("extra-command" in error for error in errors), errors)

    def test_missing_public_command_is_rejected(self) -> None:
        reduced_help = PUBLIC_HELP.replace(
            "  binscan                     Read the binaries a recorded build produced and\n"
            "                               report the dynamic dependencies, archive\n"
            "                               contents and symbols they carry.\n",
            "",
        )
        with mock.patch.object(
            BOUNDARY,
            "run",
            side_effect=[
                completed_process(reduced_help),
                completed_process(reduced_help),
                completed_process("", BOUNDARY.kIncompleteExitCode),
            ],
        ):
            errors: list[str] = []
            BOUNDARY.validate_cli(Path("bomwerk"), errors)
            self.assertTrue(any("missing public commands" in error for error in errors), errors)

    def test_runtime_flag_changing_the_tree_is_rejected(self) -> None:
        # Given a binary whose help changes when BOMWERK_PRO is set in the
        # environment, Then the build-time boundary is not a boundary.
        flagged_help = PUBLIC_HELP + "  extra-command              Appears only with the flag\n"
        with mock.patch.object(
            BOUNDARY,
            "run",
            side_effect=[
                completed_process(PUBLIC_HELP),
                completed_process(flagged_help),
                completed_process("", BOUNDARY.kIncompleteExitCode),
            ],
        ):
            errors: list[str] = []
            BOUNDARY.validate_cli(Path("bomwerk"), errors)
            self.assertTrue(
                any("runtime BOMWERK_PRO" in error for error in errors), errors
            )

    def test_unknown_command_must_exit_two(self) -> None:
        with mock.patch.object(
            BOUNDARY,
            "run",
            side_effect=[
                completed_process(PUBLIC_HELP),
                completed_process(PUBLIC_HELP),
                completed_process("", 0),
            ],
        ):
            errors: list[str] = []
            BOUNDARY.validate_cli(Path("bomwerk"), errors)
            self.assertTrue(any("unknown command" in error for error in errors), errors)

    def test_help_without_a_subcommand_section_is_reported(self) -> None:
        with mock.patch.object(
            BOUNDARY, "run", side_effect=[completed_process("no sections here\n")]
        ):
            errors: list[str] = []
            BOUNDARY.validate_cli(Path("bomwerk"), errors)
            self.assertTrue(any("SUBCOMMANDS" in error for error in errors), errors)


class BinaryValidationTest(unittest.TestCase):
    def inspect_with(self, symbol_text: str) -> list[str]:
        errors: list[str] = []
        with mock.patch.object(
            BOUNDARY, "run", side_effect=[completed_process(symbol_text), completed_process("")]
        ):
            BOUNDARY.validate_binary(Path("bomwerk"), errors)
        return errors

    def test_public_namespaces_are_accepted(self) -> None:
        symbols = "\n".join(
            f"0000000000401000 T bomwerk::{module}::do_work()"
            for module in sorted(BOUNDARY.PUBLIC_SOURCE_MODULES)
        )
        self.assertEqual(self.inspect_with(symbols), [])

    def test_non_public_namespace_is_rejected(self) -> None:
        # Given a paid namespace linked into the Community artifact,
        # Then it is reported by name found in the binary, not from a list here.
        errors = self.inspect_with("0000000000401000 T bomwerk::entitlements::verify()")
        self.assertTrue(any("bomwerk::entitlements" in error for error in errors), errors)

    def test_missing_inspector_is_reported(self) -> None:
        with mock.patch.object(BOUNDARY.shutil, "which", return_value=None):
            errors: list[str] = []
            BOUNDARY.validate_binary(Path("bomwerk"), errors)
            self.assertTrue(any("artifact inspector" in error for error in errors), errors)


class PublicLayoutTest(unittest.TestCase):
    def test_repository_itself_matches_the_public_layout(self) -> None:
        # Given this very checkout, When its tracked paths are classified,
        # Then every one of them belongs to the public layout.
        tracked_paths = BOUNDARY.list_tracked_paths(REPOSITORY_ROOT)
        if tracked_paths is None:
            self.skipTest("not a git checkout")
        offending_paths = [path for path in tracked_paths if not BOUNDARY.path_is_public(path)]
        self.assertEqual(offending_paths, [])


if __name__ == "__main__":
    unittest.main()
