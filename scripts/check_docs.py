#!/usr/bin/env python3
"""Fail when the documentation promises a CLI the binary does not have.

The binary's own `--help` is the command-syntax contract. This script pins it
and holds every other description to it:

1. `docs/cli-help/*.txt` is a byte-exact copy of each command's `--help`, so a
   flag cannot be added, renamed or removed without the change being visible
   in review (`--update` regenerates them).
2. `docs/capabilities.md` is the capability ledger: every command the binary
   exposes has a row with a status (shipped, preview or planned) and the
   evidence behind it. A shipped or preview row names a registered test; a
   planned row must not be a command the binary already has, and a command row
   must not be missing from the binary.
3. Every `bomwerk ...` line inside a bash/sh/console code block names a real
   command and only flags, and enum values, that its help lists. A fence
   preceded by `<!-- docs-check: skip -->` is exempt (sample console output).
4. Every relative link and `#anchor` in the checked markdown resolves.
5. Optionally (`--path-refs`), every backticked `*.md` path in a prose file
   exists under one of the `--path-base` directories, for files that name
   documents in running text rather than linking them.

Standard library only: this runs as a ctest and in CI with no pip install.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

HELP_DIRECTORY = Path("docs") / "cli-help"
LEDGER_PATH = Path("docs") / "capabilities.md"
ROOT_SNAPSHOT_NAME = "bomwerk"
VALID_STATUSES = ("shipped", "preview", "planned")
CHECKED_FENCE_LANGUAGES = frozenset({"bash", "sh", "shell", "console"})
SKIP_MARKER = "<!-- docs-check: skip -->"

# CLI11 section headings are flush left and end with a colon.
HELP_SECTION_PATTERN = re.compile(r"^([A-Z][A-Z ]+):\n(.*?)(?=^\S|\Z)", re.MULTILINE | re.DOTALL)
# A subcommand entry is indented exactly two spaces; wrapped description text
# is indented further (see scripts/validate_pro_boundary.py).
HELP_SUBCOMMAND_PATTERN = re.compile(r"^ {2}(?! )([a-z][a-z0-9-]*)", re.MULTILINE)
# `  -o,     --output TEXT [x]` / `          --vuln, --no-vuln{false}`
HELP_OPTION_PATTERN = re.compile(
    r"^ {2}(?:(-[A-Za-z]),)?\s+(--[a-z0-9][a-z0-9-]*(?:\{[^}]*\})?(?:, --[a-z0-9][a-z0-9-]*(?:\{[^}]*\})?)*)(.*)$",
    re.MULTILINE,
)
# CLI11 prints a value type (`TEXT`, `UINT:POSITIVE`) or an enum one space after
# the option name; the description column starts after several spaces, so a
# flag's description ("Display program ...") is never mistaken for a type.
HELP_ENUM_PATTERN = re.compile(r"^ \{([^}]*)\}")
HELP_VALUE_TYPE_PATTERN = re.compile(r"^ [A-Z][A-Z0-9_]*(?::[A-Z0-9_]+)*(?![A-Za-z0-9_])")

FENCE_PATTERN = re.compile(r"^(\s*)(```+|~~~+)\s*([A-Za-z0-9_-]*)")
MARKDOWN_LINK_PATTERN = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HTML_HREF_PATTERN = re.compile(r"""href=["']([^"']+)["']""")
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
HTML_ANCHOR_PATTERN = re.compile(r"""<a\s+(?:name|id)=["']([^"']+)["']""")
LEDGER_ROW_PATTERN = re.compile(r"^\|(.+)\|\s*$")
BACKTICK_PATTERN = re.compile(r"`([^`]+)`")
DOCUMENT_PATH_PATTERN = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]*\.md$")


@dataclass
class OptionSpec:
    takes_value: bool
    choices: tuple[str, ...] = ()


@dataclass
class CommandHelp:
    path: tuple[str, ...]
    text: str
    options: dict[str, OptionSpec] = field(default_factory=dict)
    subcommands: list[str] = field(default_factory=list)


@dataclass
class LedgerRow:
    line_number: int
    capability: str
    status: str
    since: str
    evidence: str


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )


# ---------------------------------------------------------------------------
# --help parsing


def parse_help(path: tuple[str, ...], text: str) -> CommandHelp:
    command_help = CommandHelp(path=path, text=text)
    for section_match in HELP_SECTION_PATTERN.finditer(text):
        heading, body = section_match.group(1), section_match.group(2)
        if heading == "SUBCOMMANDS":
            command_help.subcommands = HELP_SUBCOMMAND_PATTERN.findall(body)
        elif heading == "OPTIONS":
            for option_match in HELP_OPTION_PATTERN.finditer(body):
                short_name, long_names, remainder = option_match.groups()
                choices_match = HELP_ENUM_PATTERN.match(remainder)
                choices = tuple(choices_match.group(1).split(",")) if choices_match else ()
                takes_value = bool(choices) or bool(HELP_VALUE_TYPE_PATTERN.match(remainder))
                spec = OptionSpec(takes_value=takes_value, choices=choices)
                names = [re.sub(r"\{[^}]*\}$", "", name) for name in long_names.split(", ")]
                if short_name:
                    names.append(short_name)
                for name in names:
                    command_help.options[name] = spec
    return command_help


def snapshot_name(path: tuple[str, ...]) -> str:
    return "-".join(path) if path else ROOT_SNAPSHOT_NAME


def collect_live_help(binary: Path, top_level: list[str] | None) -> dict[tuple[str, ...], CommandHelp]:
    """--help for the root and every (nested) subcommand, keyed by command path."""
    helps: dict[tuple[str, ...], CommandHelp] = {}
    pending: list[tuple[str, ...]] = [()]
    while pending:
        path = pending.pop(0)
        completed = run([str(binary), *path, "--help"])
        if completed.returncode != 0:
            raise RuntimeError(f"`bomwerk {' '.join(path)} --help` exited {completed.returncode}")
        command_help = parse_help(path, completed.stdout)
        helps[path] = command_help
        for subcommand in command_help.subcommands:
            if not path and top_level is not None and subcommand not in top_level:
                continue
            pending.append((*path, subcommand))
    return helps


def load_snapshots(docs_root: Path) -> dict[tuple[str, ...], CommandHelp]:
    helps: dict[tuple[str, ...], CommandHelp] = {}
    help_directory = docs_root / HELP_DIRECTORY
    if not help_directory.is_dir():
        return helps
    for snapshot in sorted(help_directory.glob("*.txt")):
        path = () if snapshot.stem == ROOT_SNAPSHOT_NAME else tuple(snapshot.stem.split("-"))
        helps[path] = parse_help(path, snapshot.read_text(encoding="utf-8"))
    return helps


def write_snapshots(docs_root: Path, helps: dict[tuple[str, ...], CommandHelp]) -> None:
    help_directory = docs_root / HELP_DIRECTORY
    help_directory.mkdir(parents=True, exist_ok=True)
    wanted = {f"{snapshot_name(path)}.txt" for path in helps}
    for stale in help_directory.glob("*.txt"):
        if stale.name not in wanted:
            stale.unlink()
    for path, command_help in helps.items():
        (help_directory / f"{snapshot_name(path)}.txt").write_text(command_help.text, encoding="utf-8")


def check_snapshots(
    live: dict[tuple[str, ...], CommandHelp], pinned: dict[tuple[str, ...], CommandHelp], errors: list[str]
) -> None:
    for path, command_help in live.items():
        name = f"{HELP_DIRECTORY}/{snapshot_name(path)}.txt"
        if path not in pinned:
            errors.append(f"{name}: missing; run check_docs.py --update")
        elif pinned[path].text != command_help.text:
            errors.append(f"{name}: differs from the binary's --help; run check_docs.py --update and review")
    for path in pinned.keys() - live.keys():
        errors.append(f"{HELP_DIRECTORY}/{snapshot_name(path)}.txt: the binary has no such command")


# ---------------------------------------------------------------------------
# Command-line snippets


def validate_command_line(
    tokens: list[str], helps: dict[tuple[str, ...], CommandHelp], values_required: bool = True
) -> list[str]:
    """Problems with one `bomwerk ...` invocation, judged against the help texts.

    A ledger row names an option without its value (`scan --fail-on`), so it
    passes `values_required=False`; a runnable example must supply one.
    """
    problems: list[str] = []
    path: tuple[str, ...] = ()
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            break  # everything after is the wrapped build command (observe)
        command_help = helps[path]
        if token.startswith("-") and token != "-":
            name, _, inline_value = token.partition("=") if token.startswith("--") else (token, "", "")
            spec = command_help.options.get(name)
            if spec is None:
                problems.append(f"`{' '.join(('bomwerk', *path))}` has no option {name}")
                index += 1
                continue
            if spec.takes_value and not inline_value:
                next_token = tokens[index + 1] if index + 1 < len(tokens) else ""
                if next_token and not (next_token.startswith("-") and not values_required):
                    index += 1
                    inline_value = next_token
                elif values_required:
                    problems.append(f"{name} needs a value")
            if spec.choices and inline_value and inline_value not in spec.choices:
                problems.append(f"{name} {inline_value!r} is not one of {{{','.join(spec.choices)}}}")
        elif not path or command_help.subcommands:
            candidate = (*path, token)
            if candidate in helps:
                path = candidate
            elif command_help.subcommands:
                problems.append(f"unknown command `bomwerk {' '.join(candidate)}`")
                break
        index += 1
    return problems


def is_bomwerk_invocation(tokens: list[str]) -> bool:
    return bool(tokens) and Path(tokens[0]).name == "bomwerk"


def iter_fenced_commands(text: str):
    """(line number, command text) for each checked shell line in a markdown file."""
    lines = text.splitlines()
    in_fence = False
    fence_marker = ""
    checked = False
    for line_number, line in enumerate(lines, start=1):
        fence_match = FENCE_PATTERN.match(line)
        if not in_fence and fence_match:
            in_fence, fence_marker = True, fence_match.group(2)
            previous = next((l for l in reversed(lines[: line_number - 1]) if l.strip()), "")
            checked = fence_match.group(3).lower() in CHECKED_FENCE_LANGUAGES and previous.strip() != SKIP_MARKER
            console = fence_match.group(3).lower() == "console"
            continue
        if in_fence and line.strip().startswith(fence_marker):
            in_fence = False
            continue
        if not (in_fence and checked):
            continue
        command = line.strip()
        if console:
            if not command.startswith("$ "):
                continue
            command = command[2:]
        elif command.startswith("$ "):
            command = command[2:]
        yield line_number, command


def split_command(command: str) -> list[str] | None:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        return None


def split_chain(tokens: list[str]) -> list[list[str]]:
    chains: list[list[str]] = [[]]
    for token in tokens:
        if token in {"&&", "||", ";", "|", "&"}:
            chains.append([])
        else:
            chains[-1].append(token)
    return [chain for chain in chains if chain]


def check_snippets(
    markdown_files: list[Path], docs_root: Path, helps: dict[tuple[str, ...], CommandHelp], errors: list[str]
) -> int:
    checked_count = 0
    for markdown_file in markdown_files:
        relative = markdown_file.relative_to(docs_root)
        for line_number, command in iter_fenced_commands(markdown_file.read_text(encoding="utf-8")):
            tokens = split_command(command)
            if tokens is None:
                continue
            for invocation in split_chain(tokens):
                if not is_bomwerk_invocation(invocation):
                    continue
                checked_count += 1
                for problem in validate_command_line(invocation, helps):
                    errors.append(f"{relative}:{line_number}: {problem}")
    return checked_count


# ---------------------------------------------------------------------------
# Capability ledger


def parse_ledger(text: str) -> list[LedgerRow]:
    rows: list[LedgerRow] = []
    header: list[str] | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        row_match = LEDGER_ROW_PATTERN.match(line.strip())
        if not row_match:
            header = None
            continue
        cells = [cell.strip() for cell in row_match.group(1).split("|")]
        if header is None:
            lowered = [cell.lower() for cell in cells]
            header = lowered if {"capability", "status", "evidence"} <= set(lowered) else None
            continue
        if all(set(cell) <= set("-: ") for cell in cells):
            continue
        record = dict(zip(header, cells))
        rows.append(
            LedgerRow(
                line_number=line_number,
                capability=record.get("capability", ""),
                status=record.get("status", "").strip("*").lower(),
                since=record.get("since", ""),
                evidence=record.get("evidence", ""),
            )
        )
    return rows


def ledger_command_path(capability: str) -> tuple[str, ...] | None:
    """`scan` / `registry add` (plus any trailing prose) -> command path.

    A cell that starts with an option (`scan --html`) or with prose -> None.
    """
    match = re.match(r"`([a-z][a-z0-9 -]*)`", capability.strip())
    if not match or " -" in f" {match.group(1)}":
        return None
    return tuple(match.group(1).split())


def check_ledger(
    docs_root: Path,
    helps: dict[tuple[str, ...], CommandHelp],
    registered_tests: list[str] | None,
    errors: list[str],
) -> None:
    ledger_file = docs_root / LEDGER_PATH
    if not ledger_file.is_file():
        errors.append(f"{LEDGER_PATH}: missing")
        return
    rows = parse_ledger(ledger_file.read_text(encoding="utf-8"))
    if not rows:
        errors.append(f"{LEDGER_PATH}: no table with Capability/Status/Evidence columns")
        return

    available_commands: set[tuple[str, ...]] = set()
    for row in rows:
        where = f"{LEDGER_PATH}:{row.line_number}"
        if row.status not in VALID_STATUSES:
            errors.append(f"{where}: status {row.status!r} is not one of {', '.join(VALID_STATUSES)}")
            continue
        if not row.evidence.strip():
            errors.append(f"{where}: {row.capability} has no evidence")
        command_path = ledger_command_path(row.capability)
        flag_snippets = [s for s in BACKTICK_PATTERN.findall(row.capability) if " -" in f" {s}"]

        if row.status == "planned":
            if command_path is not None and command_path in helps:
                errors.append(f"{where}: {row.capability} is marked planned but the binary has it")
            for snippet in flag_snippets:
                if not validate_command_line(["bomwerk", *snippet.split()], helps, values_required=False):
                    errors.append(f"{where}: {row.capability} is marked planned but the binary accepts it")
            continue

        if command_path is not None:
            if command_path not in helps:
                errors.append(f"{where}: {row.capability} is marked {row.status} but the binary has no such command")
            available_commands.add(command_path)
        for snippet in flag_snippets:
            for problem in validate_command_line(["bomwerk", *snippet.split()], helps, values_required=False):
                errors.append(f"{where}: {problem}")
        if registered_tests is not None:
            for test_pattern in BACKTICK_PATTERN.findall(row.evidence):
                if not fnmatch.filter(registered_tests, test_pattern):
                    errors.append(f"{where}: evidence `{test_pattern}` matches no registered test")

    # A nested command (`registry add`) is covered by its own row or its parent's.
    for path in helps:
        if path and not any(path[:depth] in available_commands for depth in range(1, len(path) + 1)):
            errors.append(f"{LEDGER_PATH}: `{' '.join(path)}` is in the binary but has no shipped/preview row")


# ---------------------------------------------------------------------------
# Links


def github_slug(heading: str, seen: dict[str, int]) -> str:
    text = re.sub(r"<[^>]+>", "", heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.replace("`", "").strip().lower()
    slug = re.sub(r"[^\w\- ]", "", text).replace(" ", "-")
    count = seen.get(slug, 0)
    seen[slug] = count + 1
    return slug if count == 0 else f"{slug}-{count}"


def anchors_of(markdown_file: Path) -> set[str]:
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    in_fence = False
    for line in markdown_file.read_text(encoding="utf-8").splitlines():
        if FENCE_PATTERN.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        heading_match = HEADING_PATTERN.match(line)
        if heading_match:
            anchors.add(github_slug(heading_match.group(2), seen))
        anchors.update(HTML_ANCHOR_PATTERN.findall(line))
    return anchors


def iter_links(text: str):
    in_fence = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        if FENCE_PATTERN.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        without_code = re.sub(r"`[^`]*`", "", line)
        for target in MARKDOWN_LINK_PATTERN.findall(without_code) + HTML_HREF_PATTERN.findall(without_code):
            yield line_number, target


def check_links(markdown_files: list[Path], docs_root: Path, errors: list[str]) -> None:
    anchor_cache: dict[Path, set[str]] = {}
    for markdown_file in markdown_files:
        relative = markdown_file.relative_to(docs_root)
        for line_number, target in iter_links(markdown_file.read_text(encoding="utf-8")):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE):
                continue  # http:, https:, mailto: ... are external
            path_part, _, anchor = target.partition("#")
            destination = (markdown_file.parent / path_part).resolve() if path_part else markdown_file
            if path_part and not destination.exists():
                errors.append(f"{relative}:{line_number}: broken link {target}")
                continue
            if anchor and destination.suffix == ".md":
                anchors = anchor_cache.setdefault(destination, anchors_of(destination))
                if anchor.lower() not in anchors:
                    errors.append(f"{relative}:{line_number}: {target} names a missing anchor")


def check_path_references(files: list[Path], bases: list[Path], errors: list[str]) -> None:
    for prose_file in files:
        in_fence = False
        for line_number, line in enumerate(prose_file.read_text(encoding="utf-8").splitlines(), start=1):
            if FENCE_PATTERN.match(line):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for reference in BACKTICK_PATTERN.findall(line):
                if not DOCUMENT_PATH_PATTERN.match(reference):
                    continue
                if not any((base / reference).exists() for base in bases):
                    errors.append(f"{prose_file.name}:{line_number}: names {reference}, which does not exist")


# ---------------------------------------------------------------------------


def checked_markdown_files(docs_root: Path, extra: list[str]) -> list[Path]:
    files = [docs_root / "README.md"] if (docs_root / "README.md").is_file() else []
    files += sorted((docs_root / "docs").rglob("*.md")) if (docs_root / "docs").is_dir() else []
    files += [docs_root / pattern for pattern in extra]
    return [f for f in dict.fromkeys(files) if f.is_file()]


def registered_test_names(ctest: str | None, build_directory: str | None) -> list[str] | None:
    if not ctest or not build_directory:
        return None
    completed = run([ctest, "--test-dir", build_directory, "-N"])
    if completed.returncode != 0:
        raise RuntimeError(f"ctest -N failed: {completed.stderr.strip()}")
    return re.findall(r"^\s*Test\s+#\d+: (\S+)", completed.stdout, re.MULTILINE)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bomwerk", type=Path, required=True, help="the built bomwerk binary")
    parser.add_argument("--docs-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--commands", help="comma-separated top-level commands this ledger owns (default: all)")
    parser.add_argument("--extra", action="append", default=[], help="another markdown file to check")
    parser.add_argument("--ctest", help="ctest executable, to verify ledger evidence names")
    parser.add_argument("--build-dir", help="build directory ctest reads the registered tests from")
    parser.add_argument("--update", action="store_true", help="rewrite docs/cli-help from the binary")
    parser.add_argument("--path-refs", type=Path, action="append", default=[],
                        help="a prose file whose backticked *.md paths must exist")
    parser.add_argument("--path-base", type=Path, action="append", default=[],
                        help="a directory --path-refs paths may be relative to")
    arguments = parser.parse_args()

    docs_root = arguments.docs_root.resolve()
    top_level = arguments.commands.split(",") if arguments.commands else None
    errors: list[str] = []

    live = collect_live_help(arguments.bomwerk, top_level)
    if arguments.update:
        write_snapshots(docs_root, live)
        print(f"wrote {len(live)} help snapshot(s) to {docs_root / HELP_DIRECTORY}")
    check_snapshots(live, load_snapshots(docs_root), errors)

    # Snippets may use any command the binary has, including ones another
    # ledger owns (a Pro doc may show `bomwerk scan`), so judge them against
    # the full tree, not only the owned subset.
    all_helps = collect_live_help(arguments.bomwerk, None) if top_level is not None else live
    check_ledger(docs_root, live, registered_test_names(arguments.ctest, arguments.build_dir), errors)

    markdown_files = checked_markdown_files(docs_root, arguments.extra)
    snippet_count = check_snippets(markdown_files, docs_root, all_helps, errors)
    check_links(markdown_files, docs_root, errors)
    check_path_references(arguments.path_refs, arguments.path_base or [docs_root], errors)

    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    print(
        f"checked {len(live)} help text(s), {snippet_count} command line(s), "
        f"{len(markdown_files)} markdown file(s): {len(errors)} error(s)"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
