#!/usr/bin/env python3
"""Scan one golden fixture tree and diff the SBOM against its checked-in snapshot.

Usage: run_golden_case.py <bomwerk-binary> <case-dir> [--update]

A case directory holds three things:

    case.json          {"description": ..., "args": [...], "expect_exit": 0,
                        optional "format": "cyclonedx"|"spdx" (default cyclonedx),
                        optional "spdx_version": "2.3"|"3.0" (default 3.0),
                        optional "coverage": true|false (default false)}
    expected.<fmt>     the snapshot (expected.cdx.json for CycloneDX,
                       expected.spdx.json for SPDX); the tool version is held as
                       @BOMWERK_VERSION@
    expected.coverage.json  the match-coverage snapshot, present only when
                       case.json sets "coverage": true -- `--coverage` is then
                       passed and this file is diffed exactly like the SBOM
                       snapshot above (same @BOMWERK_VERSION@ token; the
                       coverage document's "version" field is always a plain
                       quoted string, so it always uses the CycloneDX-shaped
                       marker regardless of this case's own SBOM `format`)
    tree/              the repo to scan, copied to a temp dir before scanning

Unit tests cover each producer alone. This harness covers what they cannot: the
composition in cli/scan_command.cpp, where five producers, the shared file walk,
the purl-keyed merge and the selected SBOM writer meet. It runs the real binary,
so the exit code (hard rule 2) is part of what each case asserts.

Why the tree is copied rather than scanned in place: git refuses to track a path
containing a ".git" component, so a fixture that exercises commit resolution --
the submodules producer resolves a pinned commit by reading git's own files,
never by running git (rule 9) -- cannot be committed with real plumbing in
place. Fixtures carry "_git" instead, and this script renames it in the copy.

Why the tool version is a token: it is the one field in the document that is
neither pinned by SOURCE_DATE_EPOCH nor derived from the scanned tree, so
snapshotting it literally would rewrite every golden on an unrelated version
bump. The substitution runs on the EXPECTED text and never on the scanner's
output -- parsing and re-serializing the actual document would silently mask the
canonical-key-order and formatting regressions these snapshots exist to catch
(rule 3). What the binary wrote is compared byte for byte.
"""
import argparse
import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Fixed generation time for every golden run: 2025-01-01T00:00:00Z. The writer
# honors SOURCE_DATE_EPOCH (rule 3), so pinning it makes metadata.timestamp
# byte-stable and exercises that mechanism at the same time.
GOLDEN_SOURCE_DATE_EPOCH = "1735689600"

# Stand-in for bomwerk's own version in a snapshot (see module docstring).
VERSION_TOKEN = "@BOMWERK_VERSION@"

# Checked-in name for a fixture's git plumbing, renamed to ".git" in the copy.
GIT_DIR_STAND_IN = "_git"

# The SBOM format a case exercises, from case.json's optional "format" field.
# The default keeps every pre-existing case on CycloneDX with byte-identical
# behavior (no --format is passed, the snapshot stays expected.cdx.json). The
# format fixes three things: the snapshot/scan-output filename suffix, whether
# --format/--spdx-version are passed, and where the tool version appears in the
# document -- so the version token below can anchor on it. SPDX additionally
# reads an optional "spdx_version" (default 3.0).
DEFAULT_FORMAT = "cyclonedx"
DEFAULT_SPDX_VERSION = "3.0"
SUPPORTED_SPDX_VERSIONS = ("2.3", "3.0")
# format -> the "<name>.json" suffix of expected.<...>/actual.<...>.
_OUTPUT_SUFFIX_BY_FORMAT = {"cyclonedx": "cdx.json", "spdx": "spdx.json"}

# Vulnerability matching is off for every case, and deliberately not something a
# case.json can turn back on: OSV findings never enter the SBOM (feed data
# changes daily, SBOM bytes must not), so matching would add nothing to a
# snapshot while making the suite depend on the network and on a live feed's
# mood. Network trouble also degrades a run to exit 1, which would fight the
# per-case exit-code assertion below.
BASE_SCAN_ARGS = ["--no-vuln"]

# Flags the harness itself already supplies. CLI11 either crashes on a second
# occurrence of a plain option (-o/--output is Throw-policy: ArgumentMismatch)
# or silently takes the last occurrence of a negatable flag pair (--vuln/
# --no-vuln is TakeLast) -- neither is a case author's likely intent, and both
# would otherwise go unnoticed until a case tried it.
_RESERVED_CASE_ARGS = frozenset(
    {"-o", "--output", "--vuln", "--no-vuln", "-f", "--format", "--spdx-version", "--coverage"}
)


def validate_case_args(case_args) -> None:
    """Reject a case's own `args` if they collide with harness-controlled flags."""
    for argument in case_args:
        if argument in _RESERVED_CASE_ARGS:
            raise RuntimeError(
                f"case.json 'args' contains {argument!r}, which the harness already "
                f"controls (-o/--output is the snapshot path; --vuln/--no-vuln stays "
                f"fixed off so golden runs stay network-free and deterministic; "
                f"-f/--format and --spdx-version come from the case's own 'format'/"
                f"'spdx_version' fields; --coverage comes from the case's own "
                f"'coverage' field) -- remove it from this case's args"
            )


def read_tool_version(binary_path: Path) -> str:
    """The version the binary reports, parsed from `bomwerk --version`."""
    completed = subprocess.run(
        [str(binary_path), "--version"], capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise RuntimeError(f"`{binary_path} --version` failed: {completed.stderr.strip()}")
    # CLI11 prints the version flag's message verbatim: "bomwerk <version>".
    reported = completed.stdout.strip().split()
    if len(reported) != 2 or reported[0] != "bomwerk":
        raise RuntimeError(f"unexpected --version output: {completed.stdout!r}")
    return reported[1]


def materialize_tree(case_tree: Path, destination: Path) -> None:
    """Copy `case_tree` to `destination`, renaming every `_git` to `.git`.

    Deepest-first, so renaming a parent never invalidates a path still queued
    for a nested submodule's plumbing.
    """
    shutil.copytree(case_tree, destination)
    stand_ins = sorted(
        destination.rglob(GIT_DIR_STAND_IN), key=lambda path: len(path.parts), reverse=True
    )
    for stand_in in stand_ins:
        stand_in.rename(stand_in.with_name(".git"))


def _version_value_marker(sbom_format: str, version: str) -> bytes:
    """The exact bytes that stand for bomwerk's own version in a document.

    CycloneDX writes the version as a standalone JSON string (metadata.tools);
    SPDX embeds it in the tool identity "bomwerk-<version>" (2.3 creators / 3.0
    Tool name). Anchoring on those surrounding bytes -- the quotes, or the
    "bomwerk-" prefix -- keeps a component version like "10.1.0" from ever being
    hit by a bare "0.1.0" substring, for either format.
    """
    if sbom_format == "spdx":
        return f"bomwerk-{version}".encode()
    return f'"{version}"'.encode()


def resolve_version_token(expected_bytes: bytes, tool_version: str, sbom_format: str) -> bytes:
    """Expected snapshot with the version token replaced by the real version.

    Requires the token to be present: a snapshot that lost it to a bad manual
    edit or merge resolution must not silently compare as a no-op (which would
    surface downstream as a misleading full-document diff with no indication
    the actual cause is a missing token).
    """
    token = _version_value_marker(sbom_format, VERSION_TOKEN)
    if token not in expected_bytes:
        raise RuntimeError(
            f"snapshot has no {VERSION_TOKEN} token -- was it hand-edited or "
            f"merged incorrectly? Re-bless with --update to restore it."
        )
    return expected_bytes.replace(token, _version_value_marker(sbom_format, tool_version))


def apply_version_token(actual_bytes: bytes, tool_version: str, sbom_format: str) -> bytes:
    """Scanner output with the tool version replaced by the token, for blessing.

    The version is matched with its surrounding bytes (quotes for CycloneDX, the
    "bomwerk-" tool-name prefix for SPDX) so a component version like "10.1.0"
    can never be hit by a bare "0.1.0" substring. It must occur exactly once: a
    second occurrence means a fixture declares a component at bomwerk's own
    version, which would make the token ambiguous and silently corrupt the
    snapshot.
    """
    marker = _version_value_marker(sbom_format, tool_version)
    occurrences = actual_bytes.count(marker)
    if occurrences != 1:
        raise RuntimeError(
            f'the tool version "{tool_version}" occurs {occurrences} times in the document, '
            f"expected exactly once (as the tool identity). A fixture component almost "
            f"certainly declares that same version -- give it a different one so the "
            f"snapshot's version token stays unambiguous."
        )
    return actual_bytes.replace(marker, _version_value_marker(sbom_format, VERSION_TOKEN))


def report_difference(expected_bytes: bytes, actual_bytes: bytes, expected_path: Path) -> None:
    """Print a unified diff of the snapshot against what the scan produced."""
    diff_lines = difflib.unified_diff(
        expected_bytes.decode("utf-8", errors="replace").splitlines(),
        actual_bytes.decode("utf-8", errors="replace").splitlines(),
        fromfile=f"{expected_path.name} (snapshot)",
        tofile="actual scan output",
        lineterm="",
    )
    for line in diff_lines:
        print(line, file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binary", type=Path, help="the bomwerk executable to run")
    parser.add_argument("case_dir", type=Path, help="a directory under fixtures/golden/")
    parser.add_argument(
        "--update",
        action="store_true",
        help="rewrite the snapshot from this run instead of comparing against it",
    )
    arguments = parser.parse_args()
    # Resolved eagerly: the scan subprocess below runs with cwd=case_dir, and a
    # relative `binary` (the documented `./build/bomwerk` form, per SOURCES.md)
    # would otherwise be looked up relative to THAT directory instead of the
    # invoker's, since a relative argv[0] is resolved against the child's cwd.
    arguments.binary = arguments.binary.resolve()

    case_config_path = arguments.case_dir / "case.json"
    case_tree = arguments.case_dir / "tree"
    for required in (case_config_path, case_tree):
        if not required.exists():
            print(f"malformed golden case: {required} is missing", file=sys.stderr)
            return 2

    try:
        case_config = json.loads(case_config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as parse_error:
        print(f"malformed golden case: {case_config_path} is not valid JSON: {parse_error}",
              file=sys.stderr)
        return 2

    case_args = case_config.get("args", [])
    if not isinstance(case_args, list):
        print(
            f"malformed golden case: {case_config_path}'s 'args' must be a list, "
            f"got {case_args!r}",
            file=sys.stderr,
        )
        return 2
    validate_case_args(case_args)

    expected_exit = case_config.get("expect_exit", 0)
    if not isinstance(expected_exit, int) or isinstance(expected_exit, bool):
        print(
            f"malformed golden case: {case_config_path}'s 'expect_exit' must be an "
            f"integer, got {expected_exit!r}",
            file=sys.stderr,
        )
        return 2

    sbom_format = case_config.get("format", DEFAULT_FORMAT)
    if sbom_format not in _OUTPUT_SUFFIX_BY_FORMAT:
        print(
            f"malformed golden case: {case_config_path}'s 'format' must be one of "
            f"{sorted(_OUTPUT_SUFFIX_BY_FORMAT)}, got {sbom_format!r}",
            file=sys.stderr,
        )
        return 2
    spdx_version = case_config.get("spdx_version", DEFAULT_SPDX_VERSION)
    if sbom_format == "spdx" and spdx_version not in SUPPORTED_SPDX_VERSIONS:
        print(
            f"malformed golden case: {case_config_path}'s 'spdx_version' must be one of "
            f"{list(SUPPORTED_SPDX_VERSIONS)}, got {spdx_version!r}",
            file=sys.stderr,
        )
        return 2

    # Opt-in second snapshot. False for every pre-existing case, so their
    # command line and comparison are byte-for-byte unchanged by this feature.
    wants_coverage = case_config.get("coverage", False)
    if not isinstance(wants_coverage, bool):
        print(
            f"malformed golden case: {case_config_path}'s 'coverage' must be a boolean, "
            f"got {wants_coverage!r}",
            file=sys.stderr,
        )
        return 2

    # Snapshot/scan-output names follow the format (expected.cdx.json for
    # CycloneDX, expected.spdx.json for SPDX), so one case dir maps to one file.
    output_suffix = _OUTPUT_SUFFIX_BY_FORMAT[sbom_format]
    expected_path = arguments.case_dir / f"expected.{output_suffix}"
    expected_coverage_path = arguments.case_dir / "expected.coverage.json"

    tool_version = read_tool_version(arguments.binary)

    with tempfile.TemporaryDirectory(prefix="bomwerk_golden_") as temp_root:
        scan_root = Path(temp_root) / "tree"
        # Outside the scanned tree on purpose: an SBOM written into the root
        # being walked is a file the next producer would have to ignore.
        actual_path = Path(temp_root) / f"actual.{output_suffix}"
        actual_coverage_path = Path(temp_root) / "actual.coverage.json"
        materialize_tree(case_tree, scan_root)

        # The default (CycloneDX) adds nothing, so an existing case's command --
        # and therefore its bytes -- is unchanged. Only a non-default format
        # selects a writer explicitly; --spdx-version is meaningful for SPDX.
        format_args = []
        if sbom_format != DEFAULT_FORMAT:
            format_args += ["--format", sbom_format]
        if sbom_format == "spdx":
            format_args += ["--spdx-version", spdx_version]
        coverage_args = ["--coverage", str(actual_coverage_path)] if wants_coverage else []

        command = [
            str(arguments.binary),
            "scan",
            str(scan_root),
            "-o",
            str(actual_path),
            *BASE_SCAN_ARGS,
            *format_args,
            *coverage_args,
            *case_args,
        ]
        # The environment is inherited, not scrubbed: the loader vars a
        # sanitizer or dynamically-linked build needs must survive. Overriding
        # SOURCE_DATE_EPOCH is enough for byte-stability -- it is the only
        # environment input that reaches the document (spdlog's SPDLOG_LEVEL
        # only moves stderr, which no case compares).
        scan_environment = dict(os.environ, SOURCE_DATE_EPOCH=GOLDEN_SOURCE_DATE_EPOCH)
        # Pinned rather than inherited: ctest's default cwd (the build tree) and
        # a human re-blessing by hand from the repo root (per SOURCES.md) would
        # otherwise resolve a case's own relative-path args (e.g. a future
        # --report-config file) two different ways. The case directory is the
        # one location every part of a case (case.json, expected.<fmt>,
        # tree/) already shares.
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env=scan_environment,
            cwd=arguments.case_dir,
        )

        if completed.returncode != expected_exit:
            print(
                f"exit code {completed.returncode}, expected {expected_exit} "
                f"(case: {case_config.get('description', arguments.case_dir.name)})",
                file=sys.stderr,
            )
            print(f"--- stdout ---\n{completed.stdout}", file=sys.stderr)
            print(f"--- stderr ---\n{completed.stderr}", file=sys.stderr)
            return 1

        if not actual_path.exists():
            print(f"scan exited {completed.returncode} but wrote no SBOM", file=sys.stderr)
            print(f"--- stderr ---\n{completed.stderr}", file=sys.stderr)
            return 1
        actual_bytes = actual_path.read_bytes()

        actual_coverage_bytes = None
        if wants_coverage:
            if not actual_coverage_path.exists():
                print(f"scan exited {completed.returncode} but wrote no coverage file",
                      file=sys.stderr)
                print(f"--- stderr ---\n{completed.stderr}", file=sys.stderr)
                return 1
            actual_coverage_bytes = actual_coverage_path.read_bytes()

    if arguments.update:
        expected_path.write_bytes(apply_version_token(actual_bytes, tool_version, sbom_format))
        print(f"blessed {expected_path}")
        if wants_coverage:
            # The coverage document's "version" field is always a plain quoted
            # string (see module docstring) -- DEFAULT_FORMAT, not this case's
            # own sbom_format, picks the right marker shape.
            expected_coverage_path.write_bytes(
                apply_version_token(actual_coverage_bytes, tool_version, DEFAULT_FORMAT)
            )
            print(f"blessed {expected_coverage_path}")
        return 0

    if not expected_path.exists():
        print(
            f"no snapshot at {expected_path} -- create it with --update, then read it "
            f"before committing",
            file=sys.stderr,
        )
        return 2
    if wants_coverage and not expected_coverage_path.exists():
        print(
            f"no coverage snapshot at {expected_coverage_path} -- create it with --update, "
            f"then read it before committing",
            file=sys.stderr,
        )
        return 2

    expected_bytes = resolve_version_token(expected_path.read_bytes(), tool_version, sbom_format)
    sbom_matches = actual_bytes == expected_bytes

    expected_coverage_bytes = None
    coverage_matches = True
    if wants_coverage:
        expected_coverage_bytes = resolve_version_token(
            expected_coverage_path.read_bytes(), tool_version, DEFAULT_FORMAT
        )
        coverage_matches = actual_coverage_bytes == expected_coverage_bytes

    if sbom_matches and coverage_matches:
        return 0

    print(
        f"golden mismatch: {case_config.get('description', arguments.case_dir.name)}",
        file=sys.stderr,
    )
    if not sbom_matches:
        report_difference(expected_bytes, actual_bytes, expected_path)
    if not coverage_matches:
        report_difference(expected_coverage_bytes, actual_coverage_bytes, expected_coverage_path)
    print(
        f"\nIf this change is intended, re-bless with:\n"
        f"  python3 scripts/run_golden_case.py {arguments.binary} {arguments.case_dir} --update",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as failure:
        # Borrowing bomwerk's own exit-code meanings for this script: 1 is a
        # golden that legitimately disagrees with its snapshot (the finding the
        # harness exists to report), 2 is the harness itself being unable to
        # reach a verdict. A red ctest should say which of the two it hit.
        print(f"golden harness could not run: {failure}", file=sys.stderr)
        sys.exit(2)
