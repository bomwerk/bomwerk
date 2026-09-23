#!/usr/bin/env python3
"""Adversarial tests for the public-history auditor."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
AUDITOR_PATH = REPOSITORY_ROOT / "scripts" / "audit_public_history.py"

HERMETIC_GIT_ENVIRONMENT = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
}

# Long enough to pass the auditor's fingerprint size floor.
PRIVATE_FILE_CONTENT = "// paid implementation\n" * 8
PUBLIC_FILE_CONTENT = "// community implementation\n" * 8


class Repository:
    """A throwaway git repository built one commit at a time."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.git("init", "--initial-branch=main")

    def git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            env=HERMETIC_GIT_ENVIRONMENT,
        )
        return completed.stdout.strip()

    def write(self, relative_path: str, content: str) -> None:
        absolute_path = self.root / relative_path
        absolute_path.parent.mkdir(parents=True, exist_ok=True)
        absolute_path.write_text(content, encoding="utf-8")

    def remove(self, relative_path: str) -> None:
        self.git("rm", "-q", relative_path)

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def commit_files(self, files: dict[str, str], message: str = "commit") -> str:
        for relative_path, content in files.items():
            self.write(relative_path, content)
        return self.commit(message)

    def root_tree(self) -> str:
        return self.git("rev-parse", "HEAD^{tree}")


def make_public_repository(root: Path) -> Repository:
    """A repository whose single root commit looks like the Community tree."""
    repository = Repository(root)
    repository.commit_files(
        {
            "README.md": "# bomwerk\n",
            "CMakeLists.txt": "project(bomwerk)\n",
            "src/core/result.hpp": PUBLIC_FILE_CONTENT,
            "scripts/check-format.sh": "#!/bin/sh\n",
            "docs/open-core-boundary.md": "# boundary\n",
        },
        "Initial public release of bomwerk Community",
    )
    return repository


def write_policy(
    path: Path,
    forbidden_paths: list[str] | None = None,
    markers: list[str] | None = None,
    shared_private_paths: list[str] | None = None,
) -> Path:
    path.write_text(
        json.dumps(
            {
                "forbidden_paths": forbidden_paths or [],
                "markers": markers or [],
                "shared_private_paths": shared_private_paths or [],
            }
        ),
        encoding="utf-8",
    )
    return path


def audit(repository_path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(AUDITOR_PATH), str(repository_path), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=HERMETIC_GIT_ENVIRONMENT,
    )


class PublicLayoutTest(unittest.TestCase):
    def test_clean_single_root_history_is_accepted(self) -> None:
        # Given a fresh history holding only public paths,
        # When it is audited, Then the audit passes.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            result = audit(repository.root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("public history audit: OK", result.stdout)

    def test_unknown_source_module_is_rejected(self) -> None:
        # Given a paid module added under src/, Then the audit fails.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            repository.commit_files({"src/paid_addon/gate.cpp": PRIVATE_FILE_CONTENT})
            result = audit(repository.root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("src/paid_addon/gate.cpp", result.stderr)

    def test_unknown_top_level_entry_is_rejected(self) -> None:
        # Given a file at the repository root that the layout does not
        # declare, Then the audit fails without naming anything private here.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            repository.commit_files({"INTERNAL-NOTES.md": "# notes\n"})
            result = audit(repository.root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("INTERNAL-NOTES.md", result.stderr)

    def test_path_deleted_later_is_still_rejected(self) -> None:
        # Given a paid path added and then deleted, Then history still carries it.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            repository.commit_files({"src/paid_addon/feature.cpp": PRIVATE_FILE_CONTENT})
            repository.remove("src/paid_addon/feature.cpp")
            repository.commit("remove the paid module")
            result = audit(repository.root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("src/paid_addon/feature.cpp", result.stderr)

    def test_path_reachable_only_from_a_tag_is_rejected(self) -> None:
        # Given a paid path that only a tag reaches, Then the audit fails.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            repository.git("checkout", "-q", "-b", "side")
            repository.commit_files({"src/paid_addon/layout.cpp": PRIVATE_FILE_CONTENT})
            repository.git("tag", "v0.0.1-example")
            repository.git("checkout", "-q", "main")
            repository.git("branch", "-q", "-D", "side")
            result = audit(repository.root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("src/paid_addon/layout.cpp", result.stderr)

    def test_path_reachable_only_from_a_pull_request_ref_is_rejected(self) -> None:
        # Given a mirror clone's refs/pull/* ref, Then the audit still sees it.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            repository.git("checkout", "-q", "-b", "contribution")
            contributed = repository.commit_files({"src/paid_addon/key.hpp": PRIVATE_FILE_CONTENT})
            repository.git("checkout", "-q", "main")
            repository.git("branch", "-q", "-D", "contribution")
            repository.git("update-ref", "refs/pull/1/head", contributed)
            result = audit(repository.root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("src/paid_addon/key.hpp", result.stderr)


class RootHistoryTest(unittest.TestCase):
    def test_second_root_commit_is_rejected(self) -> None:
        # Given an unrelated history merged in, Then the audit fails.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            repository.git("checkout", "-q", "--orphan", "old-history")
            repository.commit_files({"README.md": "# old\n"}, "old root")
            repository.git("checkout", "-q", "main")
            result = audit(repository.root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("exactly one root commit", result.stderr)

    def test_expected_root_tree_is_enforced(self) -> None:
        # Given the reviewed tree, Then only that tree is accepted.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            expected_tree = repository.root_tree()
            accepted = audit(repository.root, "--expect-root-tree", expected_tree)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            rejected = audit(repository.root, "--expect-root-tree", "0" * 40)
            self.assertEqual(rejected.returncode, 1)
            self.assertIn("expected", rejected.stderr)


class PrivatePolicyTest(unittest.TestCase):
    def test_policy_path_inside_the_public_layout_is_rejected(self) -> None:
        # Given a paid document that lives in docs/, Then the policy catches it.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            repository.commit_files({"docs/paid-addon-notes.md": "# internal\n"})
            policy = write_policy(
                Path(temporary_directory) / "policy.json",
                forbidden_paths=["docs/paid-addon-notes.md"],
            )
            result = audit(repository.root, "--private-policy", str(policy))
            self.assertEqual(result.returncode, 1)
            self.assertIn("private path", result.stderr)

    def test_policy_marker_in_a_blob_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            repository.commit_files(
                {"src/core/logging.hpp": "// see PRIVATE-MARKER rule 2\n"}
            )
            policy = write_policy(
                Path(temporary_directory) / "policy.json", markers=["PRIVATE-MARKER"]
            )
            result = audit(repository.root, "--private-policy", str(policy))
            self.assertEqual(result.returncode, 1)
            self.assertIn("PRIVATE-MARKER", result.stderr)

    def test_policy_marker_in_a_commit_message_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            repository.commit("chore: PRIVATE-MARKER cleanup")
            policy = write_policy(
                Path(temporary_directory) / "policy.json", markers=["PRIVATE-MARKER"]
            )
            result = audit(repository.root, "--private-policy", str(policy))
            self.assertEqual(result.returncode, 1)
            self.assertIn("PRIVATE-MARKER", result.stderr)

    def test_marker_in_an_unreachable_object_is_rejected(self) -> None:
        # Given a branch pushed and then deleted, Then its objects are still
        # fetchable by id, so the audit must still find them.
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            repository.git("checkout", "-q", "-b", "leak")
            repository.commit_files({"src/core/leak.hpp": "// PRIVATE-MARKER\n"})
            repository.git("checkout", "-q", "main")
            repository.git("branch", "-q", "-D", "leak")
            policy = write_policy(
                Path(temporary_directory) / "policy.json", markers=["PRIVATE-MARKER"]
            )
            result = audit(repository.root, "--private-policy", str(policy))
            self.assertEqual(result.returncode, 1)
            self.assertIn("PRIVATE-MARKER", result.stderr)


class ReferenceRepositoryTest(unittest.TestCase):
    def test_commit_shared_with_the_archive_is_rejected(self) -> None:
        # Given a public history cloned from the archive instead of created
        # fresh, Then the shared commit gives it away.
        with tempfile.TemporaryDirectory() as temporary_directory:
            archive = make_public_repository(Path(temporary_directory) / "archive")
            public_path = Path(temporary_directory) / "public"
            subprocess.run(
                ["git", "clone", "-q", str(archive.root), str(public_path)],
                check=True,
                capture_output=True,
                env=HERMETIC_GIT_ENVIRONMENT,
            )
            result = audit(public_path, "--archive-reference", str(archive.root))
            self.assertEqual(result.returncode, 1)
            self.assertIn("shares commit", result.stderr)

    def test_private_blob_republished_under_another_name_is_rejected(self) -> None:
        # Given a paid file copied to a public-looking path, Then the blob
        # fingerprint catches it even though the path looks fine.
        with tempfile.TemporaryDirectory() as temporary_directory:
            private_repository = Repository(Path(temporary_directory) / "private")
            private_repository.commit_files({"src/paid_addon/feature.cpp": PRIVATE_FILE_CONTENT})
            public_repository = make_public_repository(Path(temporary_directory) / "public")
            public_repository.commit_files({"src/vuln/helper.cpp": PRIVATE_FILE_CONTENT})
            result = audit(
                public_repository.root,
                "--private-reference",
                str(private_repository.root),
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("src/vuln/helper.cpp", result.stderr)

    def test_small_shared_blob_is_ignored(self) -> None:
        # Given a file too short to prove anything, Then it is not a finding.
        with tempfile.TemporaryDirectory() as temporary_directory:
            private_repository = Repository(Path(temporary_directory) / "private")
            private_repository.commit_files({"src/paid_addon/feature.cpp": "#pragma once\n"})
            public_repository = make_public_repository(Path(temporary_directory) / "public")
            public_repository.commit_files({"src/vuln/helper.hpp": "#pragma once\n"})
            result = audit(
                public_repository.root,
                "--private-reference",
                str(private_repository.root),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_declared_shared_file_is_ignored(self) -> None:
        # Given a config file both repositories intentionally share,
        # Then shared_private_paths keeps it out of the fingerprint.
        with tempfile.TemporaryDirectory() as temporary_directory:
            private_repository = Repository(Path(temporary_directory) / "private")
            private_repository.commit_files({".clang-format": PRIVATE_FILE_CONTENT})
            public_repository = make_public_repository(Path(temporary_directory) / "public")
            public_repository.commit_files({".clang-format": PRIVATE_FILE_CONTENT})
            policy = write_policy(
                Path(temporary_directory) / "policy.json",
                shared_private_paths=[".clang-format"],
            )
            result = audit(
                public_repository.root,
                "--private-reference",
                str(private_repository.root),
                "--private-policy",
                str(policy),
            )
            self.assertEqual(result.returncode, 0, result.stderr)


class InvocationTest(unittest.TestCase):
    def test_missing_repository_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = audit(Path(temporary_directory) / "absent")
            self.assertEqual(result.returncode, 1)
            self.assertIn("not a git repository", result.stderr)

    def test_unreadable_policy_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = make_public_repository(Path(temporary_directory) / "public")
            result = audit(
                repository.root,
                "--private-policy",
                str(Path(temporary_directory) / "absent.json"),
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("cannot read private policy", result.stderr)


if __name__ == "__main__":
    unittest.main()
