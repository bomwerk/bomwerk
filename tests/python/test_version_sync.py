#!/usr/bin/env python3
"""Fails when vcpkg.json's version drifts from the version CMake builds into bomwerk.

`CMakeLists.txt` is the source of truth: `project(bomwerk VERSION x.y.z)` plus the
`bomwerk_version_prerelease` label. vcpkg cannot read that file, so vcpkg.json carries
a copy in `version-string`. The two must agree exactly: a manifest naming another
version misstates what is being built.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CMAKE_PATH = REPOSITORY_ROOT / "CMakeLists.txt"
VCPKG_MANIFEST_PATH = REPOSITORY_ROOT / "vcpkg.json"

PROJECT_VERSION_PATTERN = re.compile(r"^project\(bomwerk VERSION (\d+\.\d+\.\d+)\b", re.MULTILINE)
PRERELEASE_PATTERN = re.compile(r'^set\(bomwerk_version_prerelease "([^"]*)"\)$', re.MULTILINE)
# SemVer 2.0.0 section 9: dot-separated identifiers of [0-9A-Za-z-], numeric ones
# without leading zeros.
SEMVER_PRERELEASE_IDENTIFIER_PATTERN = re.compile(r"^(0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)$")


def read_cmake_version_parts() -> tuple[str, str]:
    cmake_text = CMAKE_PATH.read_text(encoding="utf-8")
    project_matches = PROJECT_VERSION_PATTERN.findall(cmake_text)
    prerelease_matches = PRERELEASE_PATTERN.findall(cmake_text)
    if len(project_matches) != 1 or len(prerelease_matches) != 1:
        raise AssertionError(
            f"expected exactly one project() version and one bomwerk_version_prerelease "
            f"in {CMAKE_PATH}, found {len(project_matches)} and {len(prerelease_matches)}"
        )
    return project_matches[0], prerelease_matches[0]


def compose_version(project_version: str, prerelease: str) -> str:
    return f"{project_version}-{prerelease}" if prerelease else project_version


class VersionSyncTest(unittest.TestCase):
    def test_vcpkg_manifest_carries_the_version_cmake_builds(self) -> None:
        # Given the project() version and pre-release label in CMakeLists.txt,
        # When vcpkg.json's version-string is read,
        # Then it is exactly the composed version bomwerk --version prints.
        project_version, prerelease = read_cmake_version_parts()
        manifest = json.loads(VCPKG_MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(manifest.get("version-string"), compose_version(project_version, prerelease))

    def test_prerelease_label_is_empty_or_valid_semver(self) -> None:
        # Given the pre-release label in CMakeLists.txt,
        # When it is split into SemVer identifiers,
        # Then it is empty (a final release) or every identifier is well formed.
        _, prerelease = read_cmake_version_parts()
        if not prerelease:
            return
        for identifier in prerelease.split("."):
            self.assertRegex(identifier, SEMVER_PRERELEASE_IDENTIFIER_PATTERN)

    def test_composed_version_omits_the_separator_for_a_final_release(self) -> None:
        # Given a final release with no pre-release label, and a release candidate,
        # When each version is composed,
        # Then only the candidate carries a "-label" suffix.
        self.assertEqual(compose_version("1.0.0", ""), "1.0.0")
        self.assertEqual(compose_version("1.0.0", "rc.1"), "1.0.0-rc.1")


if __name__ == "__main__":
    unittest.main()
