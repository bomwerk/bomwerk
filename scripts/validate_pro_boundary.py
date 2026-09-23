#!/usr/bin/env python3
"""Fail when a Community build is not exactly the Community build.

The check is a positive allowlist, not a list of paid module names. A
source file, a compiled translation unit, a CLI command or a binary symbol is
acceptable because the public repository is known to contain it. Anything else
is a finding, whether it came from a composed private source tree, a
half-merged branch, or a module nobody has reviewed yet.

That is both stricter and quieter than naming the paid modules: it catches a
private module this script has never heard of, and it publishes no map of the
private repository. The concrete private names live in the private extension's
`release/public-audit-policy.json`, which the history auditor reads.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from public_layout import (  # noqa: E402  (same-directory module)
    PUBLIC_COMMANDS,
    PUBLIC_SOURCE_MODULES,
    path_is_public,
)


# `nm -C` prints demangled names; anything in our own namespace has to belong to
# a module the public repository declares.
BOMWERK_NAMESPACE_PATTERN = re.compile(r"bomwerk::([A-Za-z_][A-Za-z0-9_]*)::")

# CLI11 lists the registered commands under a SUBCOMMANDS heading, one entry
# per command indented exactly two spaces. A command's own description can be
# long enough to wrap (trim's and binscan's both do), and CLI11 indents that
# continuation text further, aligned under the description column rather than
# under the name. Requiring exactly two leading spaces: the lookahead rejects
# a third: is what tells an actual subcommand line apart from the first word
# of a wrapped description line such as "actually" or "dynamic".
HELP_SUBCOMMAND_SECTION_PATTERN = re.compile(
    r"^SUBCOMMANDS:\n(.*?)(?:\n\S|\Z)", re.MULTILINE | re.DOTALL
)
HELP_SUBCOMMAND_PATTERN = re.compile(r"^ {2}(?! )([a-z][a-z0-9-]*)", re.MULTILINE)

kUnknownCommandProbe = "definitely-not-a-bomwerk-command"
kIncompleteExitCode = 2


def run(
    command: list[str], environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
    )


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def list_tracked_paths(repository_root: Path) -> list[str] | None:
    """Paths git would publish, or None when this is not a git checkout."""
    completed = subprocess.run(
        ["git", "-C", str(repository_root), "ls-files", "-z"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return [path for path in completed.stdout.split("\0") if path]


def validate_source_tree(repository_root: Path, errors: list[str]) -> None:
    """Everything this repository would publish belongs to the public layout."""
    tracked_paths = list_tracked_paths(repository_root)
    if tracked_paths is not None:
        for tracked_path in tracked_paths:
            require(
                path_is_public(tracked_path),
                f"community source tree tracks a path outside the public layout: {tracked_path}",
                errors,
            )

    # A source archive has no git metadata, so at least check the module list,
    # which is where a composed private tree would show up.
    source_root = repository_root / "src"
    if not source_root.is_dir():
        errors.append(f"community source tree has no src directory: {source_root}")
        return
    for module in sorted(source_root.iterdir()):
        require(
            module.name in PUBLIC_SOURCE_MODULES,
            f"community source tree contains an unknown src module: {module.name}",
            errors,
        )


def validate_compile_commands(
    build_directory: Path, repository_root: Path, errors: list[str]
) -> None:
    """Every compiled translation unit comes from this repository."""
    compile_commands_path = build_directory / "compile_commands.json"
    try:
        compile_commands = json.loads(compile_commands_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"cannot read {compile_commands_path}: {error}")
        return

    if not isinstance(compile_commands, list):
        errors.append(f"{compile_commands_path} must contain a JSON array")
        return

    allowed_roots = (repository_root.resolve(), build_directory.resolve())
    for entry_index, entry in enumerate(compile_commands):
        if not isinstance(entry, dict):
            errors.append(f"{compile_commands_path} entry {entry_index} must be a JSON object")
            continue
        compiled_file = entry.get("file", "")
        try:
            resolved_file = Path(compiled_file).resolve()
        except OSError:
            errors.append(f"community build compiles an unreadable path: {compiled_file!r}")
            continue
        inside_repository = any(
            resolved_file == allowed_root or allowed_root in resolved_file.parents
            for allowed_root in allowed_roots
        )
        require(
            inside_repository,
            f"community build compiles a source outside this repository: {compiled_file}",
            errors,
        )
        if inside_repository and resolved_file.is_relative_to(allowed_roots[0]):
            relative_path = resolved_file.relative_to(allowed_roots[0]).as_posix()
            require(
                path_is_public(relative_path),
                f"community build compiles a source outside the public layout: {relative_path}",
                errors,
            )


def validate_cli(binary_path: Path, errors: list[str]) -> None:
    """The command tree is exactly the public one, whatever the environment says."""
    normal_help = run([str(binary_path), "--help"])
    require(normal_help.returncode == 0, "community --help did not exit cleanly", errors)

    subcommand_section = HELP_SUBCOMMAND_SECTION_PATTERN.search(normal_help.stdout)
    if subcommand_section is None:
        errors.append("community --help has no SUBCOMMANDS section to check")
        return
    advertised_commands = set(HELP_SUBCOMMAND_PATTERN.findall(subcommand_section.group(1)))
    unexpected_commands = sorted(advertised_commands - set(PUBLIC_COMMANDS))
    require(
        not unexpected_commands,
        f"community --help advertises commands outside the public set: {unexpected_commands}",
        errors,
    )
    missing_commands = sorted(set(PUBLIC_COMMANDS) - advertised_commands)
    require(
        not missing_commands,
        f"community --help is missing public commands: {missing_commands}",
        errors,
    )

    runtime_environment = os.environ.copy()
    runtime_environment["BOMWERK_PRO"] = "ON"
    flagged_help = run([str(binary_path), "--help"], runtime_environment)
    require(
        flagged_help.stdout == normal_help.stdout,
        "runtime BOMWERK_PRO changed the community command tree",
        errors,
    )

    unknown_command = run([str(binary_path), kUnknownCommandProbe])
    require(
        unknown_command.returncode == kIncompleteExitCode,
        "community binary did not reject an unknown command with exit 2",
        errors,
    )


def validate_binary(binary_path: Path, errors: list[str]) -> None:
    """Every bomwerk namespace in the artifact is a public module."""
    tools = {name: shutil.which(name) for name in ("nm", "strings")}
    missing_tools = sorted(name for name, executable in tools.items() if executable is None)
    if missing_tools:
        for name in missing_tools:
            errors.append(f"required artifact inspector {name!r} is unavailable")
        return

    nm_result = run([tools["nm"], "-C", str(binary_path)])
    strings_result = run([tools["strings"], str(binary_path)])
    require(nm_result.returncode == 0, "nm could not inspect the community binary", errors)
    require(
        strings_result.returncode == 0, "strings could not inspect the community binary", errors
    )

    artifact_text = f"{nm_result.stdout}\n{strings_result.stdout}"
    for module in sorted(set(BOMWERK_NAMESPACE_PATTERN.findall(artifact_text))):
        require(
            module in PUBLIC_SOURCE_MODULES,
            f"community binary contains the non-public namespace bomwerk::{module}",
            errors,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository_root", type=Path)
    parser.add_argument("build_directory", type=Path)
    parser.add_argument("binary", type=Path)
    arguments = parser.parse_args()

    errors: list[str] = []
    repository_root = arguments.repository_root.resolve()
    validate_source_tree(repository_root, errors)
    validate_compile_commands(arguments.build_directory.resolve(), repository_root, errors)
    validate_cli(arguments.binary.resolve(), errors)
    validate_binary(arguments.binary.resolve(), errors)

    if errors:
        for error in sorted(set(errors)):
            print(f"boundary error: {error}", file=sys.stderr)
        return 1
    print("community source/build boundary: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
