#!/usr/bin/env python3
"""The shape of the public repository, as a positive allowlist.

Both the build-boundary validator and the history auditor answer the same
question: "does this belong in the Community repository?": and both answer it
by listing what does, never by listing what does not. A negative list only ever
catches the leaks someone remembered to name, and writing those names into a
public repository publishes the map of the private one.
"""

from __future__ import annotations


PUBLIC_TOP_LEVEL_ENTRIES = frozenset(
    {
        ".clang-format",
        ".clang-tidy",
        ".dockerignore",
        ".github",
        ".gitignore",
        ".gitmodules",
        "CHANGELOG.md",
        "CMakeLists.txt",
        "LICENSE",
        "README.md",
        "docker",
        "docs",
        "fixtures",
        "scripts",
        "src",
        "tests",
        "vcpkg",
        "vcpkg.json",
    }
)

PUBLIC_SOURCE_MODULES = frozenset(
    {
        "binscan",
        "cli",
        "core",
        "heuristics",
        "observe",
        "output",
        "parsers",
        "sbom",
        "vuln",
    }
)

PUBLIC_COMMANDS = ("binscan", "observe", "scan", "trim")


def path_is_public(path: str) -> bool:
    """True when `path`, relative to the repository root, belongs here."""
    segments = path.split("/")
    if segments[0] not in PUBLIC_TOP_LEVEL_ENTRIES:
        return False
    if segments[0] == "src" and len(segments) > 1:
        return segments[1] in PUBLIC_SOURCE_MODULES
    return True
