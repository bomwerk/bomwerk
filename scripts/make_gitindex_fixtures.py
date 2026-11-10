#!/usr/bin/env python3
"""Build the git index fixtures with real git, or check the committed ones still match.

Usage:
    make_gitindex_fixtures.py            write fixtures/gitindex/*.index and the
                                         nightmare-shallow-clone golden index
    make_gitindex_fixtures.py --check    rebuild into a temp dir and compare
                                         byte for byte; exit 1 on a difference,
                                         77 (ctest "skipped") when git is absent

Why these binary files are committed when fixtures/binscan/SOURCES.md keeps ELF
and `ar` blobs out: see fixtures/gitindex/SOURCES.md. In short, an index is the
same bytes on every platform, the reader's whole point is to agree with what
real git writes (a hand-built index would only prove the reader agrees with its
own author), and this script is the reviewable recipe, which `--check` proves
the blobs still match.

Every entry goes in through `git update-index --cacheinfo` or `--index-info`,
never `git add`: those record no stat data (all zeros), so the bytes depend on
the recipe alone, not on the machine, the clock or the inode numbers. No object
has to exist for that, so every commit id here is synthetic, as in
fixtures/golden/SOURCES.md. Global and system git config are ignored so a
contributor's `feature.manyFiles` or `index.skipHash` cannot change the output.

Running git here is fine: hard rule 9 forbids PRODUCERS from shelling out, and
this is a fixture builder that never runs during a scan.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GITINDEX_DIRECTORY = Path("fixtures/gitindex")
SHALLOW_CLONE_INDEX = Path("fixtures/golden/nightmare-shallow-clone/tree/_git/index")

SKIPPED_EXIT_CODE = 77

# Synthetic, deliberately patterned object ids (fixtures/golden/SOURCES.md).
# The openssl pin is the one nightmare-submodule-pinned checks out, so the
# shallow-clone golden case and that one must produce the same SBOM.
OPENSSL_COMMIT = "fedcba9876543210fedcba9876543210fedcba98"
ZLIB_COMMIT = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c"
MBEDTLS_COMMIT = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"
BLOB_ID = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"  # git's empty blob

OPENSSL_COMMIT_SHA256 = "fedcba9876543210" * 4
ZLIB_COMMIT_SHA256 = "0f1e2d3c4b5a6978" * 4
MBEDTLS_COMMIT_SHA256 = "1a2b3c4d5e6f7081" * 4
BLOB_ID_SHA256 = "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"

GITLINK_MODE = "160000"
REGULAR_FILE_MODE = "100644"

# One path of exactly 0xFFF bytes saturates the 12-bit name-length field, the
# boundary where the reader must stop trusting the field and use the NUL.
SATURATED_NAME_LENGTH = 0xFFF
# One byte longer than the reader's cap (core::kMaxGitIndexPathBytes = 4096)
# plus a margin: a legal git index the reader must refuse rather than misread.
OVER_LIMIT_NAME_LENGTH = 4200


def long_path(length: int) -> str:
    """A '/'-separated path of exactly `length` bytes, no segment over 199."""
    segment = "d" * 199
    parts: list[str] = []
    remaining = length
    while remaining > len(segment) + 1:
        parts.append(segment)
        remaining -= len(segment) + 1
    parts.append("x" * remaining)
    path = "/".join(parts)
    assert len(path) == length, (len(path), length)
    return path


@dataclass
class IndexRecipe:
    """One index: the entries, then optional git commands run after them."""

    output: Path
    entries: list[tuple[str, str, str]]  # (mode, object id, path), stage 0
    object_format: str = "sha1"
    index_info_lines: list[str] = field(default_factory=list)  # staged entries
    after: list[list[str]] = field(default_factory=list)


def standard_entries(openssl: str, zlib: str, mbedtls: str, blob: str) -> list[tuple[str, str, str]]:
    return [
        (REGULAR_FILE_MODE, blob, ".gitmodules"),
        (GITLINK_MODE, mbedtls, "libs/mbedtls"),
        (GITLINK_MODE, zlib, "libs/zlib"),
        (REGULAR_FILE_MODE, blob, "src/main.c"),
        (GITLINK_MODE, openssl, "third_party/openssl"),
    ]


def recipes() -> list[IndexRecipe]:
    standard = standard_entries(OPENSSL_COMMIT, ZLIB_COMMIT, MBEDTLS_COMMIT, BLOB_ID)
    return [
        IndexRecipe(GITINDEX_DIRECTORY / "v2-sha1.index", standard),
        # skip-worktree is an extended flag, so git upgrades the file to v3.
        IndexRecipe(
            GITINDEX_DIRECTORY / "v3-skip-worktree.index",
            standard,
            after=[["update-index", "--skip-worktree", "src/main.c"]],
        ),
        # v4 compresses each path against the previous one: libs/mbedtls ->
        # libs/zlib strips "mbedtls" and appends "zlib".
        IndexRecipe(
            GITINDEX_DIRECTORY / "v4-sha1.index",
            standard,
            after=[["update-index", "--index-version", "4"]],
        ),
        IndexRecipe(
            GITINDEX_DIRECTORY / "v2-sha256.index",
            standard_entries(
                OPENSSL_COMMIT_SHA256, ZLIB_COMMIT_SHA256, MBEDTLS_COMMIT_SHA256, BLOB_ID_SHA256
            ),
            object_format="sha256",
        ),
        # A split index holds only a delta against sharedindex.<id>: refused.
        IndexRecipe(
            GITINDEX_DIRECTORY / "split.index",
            standard,
            after=[["update-index", "--split-index"]],
        ),
        # libs/zlib only at merge-conflict stages 1 to 3: no single pin.
        IndexRecipe(
            GITINDEX_DIRECTORY / "conflict.index",
            [(GITLINK_MODE, OPENSSL_COMMIT, "third_party/openssl")],
            index_info_lines=[
                f"{GITLINK_MODE} {ZLIB_COMMIT} {stage}\tlibs/zlib" for stage in (1, 2, 3)
            ],
        ),
        IndexRecipe(
            GITINDEX_DIRECTORY / "long-path.index",
            [(GITLINK_MODE, ZLIB_COMMIT, long_path(SATURATED_NAME_LENGTH))],
        ),
        IndexRecipe(
            GITINDEX_DIRECTORY / "path-over-limit.index",
            [(GITLINK_MODE, ZLIB_COMMIT, long_path(OVER_LIMIT_NAME_LENGTH))],
        ),
        # The golden case: what a default `actions/checkout` of the nightmare
        # corpus has on disk for its one submodule.
        IndexRecipe(
            SHALLOW_CLONE_INDEX,
            [
                (REGULAR_FILE_MODE, BLOB_ID, ".gitmodules"),
                (GITLINK_MODE, OPENSSL_COMMIT, "third_party/openssl"),
            ],
        ),
    ]


def isolated_git_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_SYSTEM"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment.pop("GIT_INDEX_FILE", None)
    environment.pop("GIT_DIR", None)
    return environment


def run_git(repository: Path, arguments: list[str], stdin: str | None = None) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=repository,
        env=isolated_git_environment(),
        input=stdin,
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )


def build_index(recipe: IndexRecipe, scratch: Path, output_root: Path) -> None:
    repository = scratch / recipe.output.name.replace(".", "-")
    run_git(
        scratch,
        ["init", "--quiet", f"--object-format={recipe.object_format}", str(repository)],
    )
    for mode, object_id, path in recipe.entries:
        run_git(repository, ["update-index", "--add", "--cacheinfo", f"{mode},{object_id},{path}"])
    if recipe.index_info_lines:
        run_git(repository, ["update-index", "--index-info"], "\n".join(recipe.index_info_lines) + "\n")
    for command in recipe.after:
        run_git(repository, command)
    destination = output_root / recipe.output
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(repository / ".git" / "index", destination)


def build_all(output_root: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="gitindex-") as scratch_name:
        scratch = Path(scratch_name)
        for recipe in recipes():
            build_index(recipe, scratch, output_root)


def check() -> int:
    with tempfile.TemporaryDirectory(prefix="gitindex-check-") as rebuilt_name:
        rebuilt_root = Path(rebuilt_name)
        build_all(rebuilt_root)
        mismatches = []
        for recipe in recipes():
            committed = REPOSITORY_ROOT / recipe.output
            rebuilt = rebuilt_root / recipe.output
            if not committed.is_file() or committed.read_bytes() != rebuilt.read_bytes():
                mismatches.append(str(recipe.output))
    if mismatches:
        print("git index fixtures differ from their recipe (rerun make_gitindex_fixtures.py):")
        for mismatch in mismatches:
            print(f"  {mismatch}")
        return 1
    print(f"git index fixtures: {len(recipes())} match their recipe")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    arguments = parser.parse_args()
    if shutil.which("git") is None:
        print("git not found; skipping", file=sys.stderr)
        return SKIPPED_EXIT_CODE if arguments.check else 1
    if arguments.check:
        return check()
    build_all(REPOSITORY_ROOT)
    print(f"wrote {len(recipes())} git index fixtures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
