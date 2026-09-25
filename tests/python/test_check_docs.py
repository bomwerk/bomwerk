#!/usr/bin/env python3
"""Tests for the documentation contract checker (scripts/check_docs.py)."""

from __future__ import annotations

import importlib.util
import shlex
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPOSITORY_ROOT / "scripts" / "check_docs.py"
MODULE_SPEC = importlib.util.spec_from_file_location("check_docs", CHECKER_PATH)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise RuntimeError(f"cannot load docs checker from {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = CHECKER  # dataclasses resolve annotations through it
MODULE_SPEC.loader.exec_module(CHECKER)

# Modeled on real CLI11 output: a flag whose description starts with a capital
# letter must not be read as taking a value, a negatable pair shares one line,
# and "Excludes:" names another option without being one of its aliases.
ROOT_HELP = """A scanner


bomwerk [OPTIONS] SUBCOMMAND


OPTIONS:
  -h,     --help              Print this help message and exit
  -V,     --version           Display program version information and exit

SUBCOMMANDS:
  scan                        Scan a directory and report the components it
                              declares.
  observe                     Run a build under shims and record what it
                              actually compiled.
"""

SCAN_HELP = """Scan a directory.


bomwerk scan [OPTIONS] [dir]


POSITIONALS:
  dir TEXT:DIR [.]            Directory to scan

OPTIONS:
  -h,     --help              Print this help message and exit
  -o,     --output TEXT [sbom.cdx.json]
                              Where to write the SBOM
  -f,     --format {cyclonedx,spdx} [cyclonedx]
                              SBOM format
  -A,     --all               Scan every directory
          --max-files UINT:POSITIVE [10000]
                              Maximum manifest files
          --vuln, --no-vuln{false}
                              Match components against OSV vulnerability data
          --config TEXT:FILE Excludes: --no-config
                              Scan config file
          --no-config Excludes: --config
                              Ignore any bomwerk.toml

Examples:
  bomwerk scan .              scan the current directory
"""

OBSERVE_HELP = """Run a build.


bomwerk observe [OPTIONS] command...


OPTIONS:
  -h,     --help              Print this help message and exit
          --clean-shims       Delete the shim directory when the build finishes
"""


def fixture_helps():
    return {
        (): CHECKER.parse_help((), ROOT_HELP),
        ("scan",): CHECKER.parse_help(("scan",), SCAN_HELP),
        ("observe",): CHECKER.parse_help(("observe",), OBSERVE_HELP),
    }


def problems(command: str) -> list[str]:
    return CHECKER.validate_command_line(shlex.split(command), fixture_helps())


class ParseHelpTest(unittest.TestCase):
    def test_options_are_read_with_value_types_enums_and_aliases(self) -> None:
        scan = fixture_helps()[("scan",)]
        self.assertTrue(scan.options["--output"].takes_value)
        self.assertEqual(scan.options["-f"].choices, ("cyclonedx", "spdx"))
        self.assertTrue(scan.options["--max-files"].takes_value)
        self.assertFalse(scan.options["-A"].takes_value)
        self.assertFalse(scan.options["--no-vuln"].takes_value)
        self.assertTrue(scan.options["--config"].takes_value)
        self.assertFalse(scan.options["--no-config"].takes_value)

    def test_a_capitalized_description_is_not_a_value_type(self) -> None:
        self.assertFalse(fixture_helps()[()].options["--version"].takes_value)

    def test_wrapped_description_words_are_not_subcommands(self) -> None:
        self.assertEqual(fixture_helps()[()].subcommands, ["scan", "observe"])


class ValidateCommandLineTest(unittest.TestCase):
    def test_valid_invocations_pass(self) -> None:
        for command in (
            "bomwerk --version",
            "bomwerk scan .",
            "bomwerk scan . --format spdx -o sbom.spdx.json",
            "bomwerk scan --output=x.json --no-vuln -A",
            "bomwerk observe -- make -j8 --anything-the-build-takes",
        ):
            with self.subTest(command=command):
                self.assertEqual(problems(command), [])

    def test_unknown_option_is_reported(self) -> None:
        self.assertEqual(problems("bomwerk scan . --stats"), ["`bomwerk scan` has no option --stats"])

    def test_invalid_enum_value_is_reported(self) -> None:
        self.assertEqual(len(problems("bomwerk scan . --format all")), 1)

    def test_unknown_command_is_reported(self) -> None:
        self.assertEqual(problems("bomwerk monitor --once"), ["unknown command `bomwerk monitor`"])

    def test_missing_value_is_reported_only_for_runnable_examples(self) -> None:
        self.assertEqual(problems("bomwerk scan --format"), ["--format needs a value"])
        self.assertEqual(
            CHECKER.validate_command_line(
                ["bomwerk", "scan", "--format"], fixture_helps(), values_required=False
            ),
            [],
        )


class MarkdownTest(unittest.TestCase):
    def test_fenced_commands_respect_language_prompt_and_skip_marker(self) -> None:
        text = "\n".join(
            [
                "```bash",
                "bomwerk scan .   # comment",
                "```",
                "```console",
                "$ bomwerk scan . --html r.html",
                "output line mentioning bomwerk --bogus",
                "```",
                "<!-- docs-check: skip -->",
                "```bash",
                "bomwerk scan --bogus",
                "```",
                "```toml",
                "bomwerk = 1",
                "```",
            ]
        )
        commands = [command for _, command in CHECKER.iter_fenced_commands(text)]
        self.assertEqual(commands, ["bomwerk scan .   # comment", "bomwerk scan . --html r.html"])

    def test_command_chains_are_split(self) -> None:
        tokens = CHECKER.split_command("bomwerk scan . -o a.json && bomwerk scan . -o b.json # x")
        self.assertEqual(
            CHECKER.split_chain(tokens),
            [["bomwerk", "scan", ".", "-o", "a.json"], ["bomwerk", "scan", ".", "-o", "b.json"]],
        )

    def test_github_slugs_match_headings_with_code_and_duplicates(self) -> None:
        seen: dict[str, int] = {}
        self.assertEqual(CHECKER.github_slug("`scan`", seen), "scan")
        self.assertEqual(CHECKER.github_slug("Exit codes", seen), "exit-codes")
        self.assertEqual(CHECKER.github_slug("Exit codes", seen), "exit-codes-1")

    def test_broken_links_and_anchors_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs" / "a.md").write_text("# Title\n\n## Real section\n", encoding="utf-8")
            (root / "README.md").write_text(
                "[ok](docs/a.md#real-section) [gone](docs/missing.md) "
                "[bad](docs/a.md#nope) [web](https://example.com)\n"
                "```bash\n[not a link](nowhere.md)\n```\n",
                encoding="utf-8",
            )
            errors: list[str] = []
            CHECKER.check_links(CHECKER.checked_markdown_files(root, []), root, errors)
        self.assertEqual(
            errors,
            [
                "README.md:1: broken link docs/missing.md",
                "README.md:1: docs/a.md#nope names a missing anchor",
            ],
        )


class PathReferenceTest(unittest.TestCase):
    def test_backticked_document_paths_must_exist_under_a_base(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs" / "RULES.md").write_text("rules\n", encoding="utf-8")
            prose = root / "NOTES.md"
            prose.write_text(
                "Read `docs/RULES.md`, not `docs/GONE.md`; `scan --html` and `out/` are not documents.\n"
                "```sh\ncat `docs/ALSO-GONE.md`\n```\n",
                encoding="utf-8",
            )
            errors: list[str] = []
            CHECKER.check_path_references([prose], [root], errors)
        self.assertEqual(errors, ["NOTES.md:1: names docs/GONE.md, which does not exist"])


class LedgerTest(unittest.TestCase):
    def write_ledger(self, root: Path, rows: list[str]) -> None:
        (root / "docs").mkdir(exist_ok=True)
        (root / "docs" / "capabilities.md").write_text(
            "| Capability | Status | Since | Evidence |\n| --- | --- | --- | --- |\n"
            + "\n".join(rows)
            + "\n",
            encoding="utf-8",
        )

    def ledger_errors(self, rows: list[str], tests: list[str] | None = None) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_ledger(root, rows)
            errors: list[str] = []
            CHECKER.check_ledger(root, fixture_helps(), tests, errors)
            return errors

    def test_complete_ledger_passes(self) -> None:
        rows = [
            "| `scan` | preview | 0.1.0 | `golden_*` |",
            "| `observe` (build tracing) | preview | 0.1.0 | `observe_cmake_build` |",
            "| `scan --format spdx` | preview | 0.1.0 | `golden_*` |",
            "| `scan --stats` | planned | | Not built yet |",
        ]
        self.assertEqual(self.ledger_errors(rows, ["golden_npm", "observe_cmake_build"]), [])

    def test_command_without_a_row_is_reported(self) -> None:
        errors = self.ledger_errors(["| `scan` | preview | 0.1.0 | tests |"])
        self.assertEqual(len(errors), 1)
        self.assertIn("`observe` is in the binary", errors[0])

    def test_planned_row_the_binary_already_has_is_reported(self) -> None:
        rows = [
            "| `scan` | preview | 0.1.0 | t |",
            "| `observe` | planned | | soon |",
            "| `scan --format spdx` | planned | | soon |",
        ]
        errors = self.ledger_errors(rows)
        self.assertEqual(len(errors), 3)  # two planned-but-present, plus observe uncovered

    def test_evidence_must_name_a_registered_test(self) -> None:
        rows = ["| `scan` | preview | 0.1.0 | `no_such_test` |", "| `observe` | preview | 0.1.0 | `o` |"]
        errors = self.ledger_errors(rows, ["o"])
        self.assertEqual(len(errors), 1)
        self.assertIn("no_such_test", errors[0])

    def test_unknown_status_and_missing_evidence_are_reported(self) -> None:
        rows = ["| `scan` | beta | 0.1.0 | t |", "| `observe` | preview | 0.1.0 | |"]
        errors = self.ledger_errors(rows)
        self.assertTrue(any("'beta'" in error for error in errors))
        self.assertTrue(any("no evidence" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
