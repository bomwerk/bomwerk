#!/usr/bin/env python3
"""Fail when a repository's history contains anything that must not be public.

`validate_pro_boundary.py` checks one working tree and one built binary. This
checks a whole repository: every ref, every commit, and every object in the
object database, including objects a deleted branch left behind, because a
published object stays fetchable by id long after nothing points at it.

The public checks are positive allowlists. A path is acceptable because this
repository is known to contain it, not because it fails to match a list of
paths we remember to be secret. An unknown top-level entry or an unknown
`src/` module is therefore a finding, which is exactly what a composed private
source tree, an assistant instruction file, or a resurrected old branch looks
like.

Private names never appear here. A policy file supplied with --private-policy
(it lives in the private extension repository) adds the concrete forbidden
paths and content markers, so running with it is strictly stronger. Reference
repositories turn on two more checks: sharing a commit with the pre-publication
archive, and republishing a private blob under any name at all.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from public_layout import path_is_public  # noqa: E402  (same-directory module)


# A blob small enough to be shared by accident (an empty file, a one-line
# marker, a short header guard) is not evidence that private content was
# republished.
kMinimumFingerprintBytes = 64


class GitError(RuntimeError):
    """A git command that must succeed did not."""


def run_git(git_directory: Path, arguments: list[str]) -> str:
    completed = subprocess.run(
        ["git", "--git-dir", str(git_directory), *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        raise GitError(
            f"git {' '.join(arguments)} failed in {git_directory}: "
            f"{completed.stderr.strip()}"
        )
    return completed.stdout


def run_git_bytes(git_directory: Path, arguments: list[str], stdin: bytes) -> bytes:
    completed = subprocess.run(
        ["git", "--git-dir", str(git_directory), *arguments],
        check=False,
        capture_output=True,
        input=stdin,
    )
    if completed.returncode != 0:
        raise GitError(
            f"git {' '.join(arguments)} failed in {git_directory}: "
            f"{completed.stderr.decode('utf-8', 'replace').strip()}"
        )
    return completed.stdout


def resolve_git_directory(repository_path: Path) -> Path:
    """Accept a bare repository, a `.git` directory, or a working tree."""
    candidate = repository_path.resolve()
    if (candidate / "HEAD").is_file() and (candidate / "objects").is_dir():
        return candidate
    nested = candidate / ".git"
    if (nested / "HEAD").is_file():
        return nested
    raise GitError(f"{repository_path} is not a git repository or git directory")


def load_private_policy(policy_paths: list[Path], errors: list[str]) -> dict[str, list[str]]:
    forbidden_paths: list[str] = []
    markers: list[str] = []
    shared_private_paths: list[str] = []
    for policy_path in policy_paths:
        try:
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"cannot read private policy {policy_path}: {error}")
            continue
        forbidden_paths.extend(policy.get("forbidden_paths", []))
        markers.extend(policy.get("markers", []))
        shared_private_paths.extend(policy.get("shared_private_paths", []))
    return {
        "forbidden_paths": forbidden_paths,
        "markers": markers,
        "shared_private_paths": shared_private_paths,
    }


def list_commits(git_directory: Path) -> list[str]:
    return run_git(git_directory, ["rev-list", "--all"]).split()


def list_root_commits(git_directory: Path) -> list[str]:
    return run_git(git_directory, ["rev-list", "--all", "--max-parents=0"]).split()


def list_reference_count(git_directory: Path) -> int:
    return len(run_git(git_directory, ["for-each-ref", "--format=%(refname)"]).splitlines())


def tree_of_commit(git_directory: Path, commit: str) -> str:
    return run_git(git_directory, ["rev-parse", f"{commit}^{{tree}}"]).strip()


def list_tree_paths(git_directory: Path, tree: str) -> list[tuple[str, str, str]]:
    """Return (object type, object id, path) for everything under one tree."""
    listing = run_git(git_directory, ["ls-tree", "-r", "-t", "--full-tree", "-z", tree])
    entries: list[tuple[str, str, str]] = []
    for record in listing.split("\0"):
        if not record:
            continue
        metadata, _, path = record.partition("\t")
        fields = metadata.split()
        if len(fields) < 3:
            continue
        entries.append((fields[1], fields[2], path))
    return entries


def path_is_forbidden(path: str, forbidden_paths: list[str]) -> bool:
    for forbidden_path in forbidden_paths:
        if forbidden_path.endswith("/"):
            if path == forbidden_path.rstrip("/") or path.startswith(forbidden_path):
                return True
        elif path == forbidden_path:
            return True
    return False


def validate_root_history(
    git_directory: Path, expected_root_tree: str | None, errors: list[str]
) -> None:
    root_commits = list_root_commits(git_directory)
    if len(root_commits) != 1:
        errors.append(
            "public history must have exactly one root commit, found "
            f"{len(root_commits)}: {' '.join(sorted(root_commits))}"
        )
        return
    if expected_root_tree is None:
        return
    root_tree = tree_of_commit(git_directory, root_commits[0])
    if root_tree != expected_root_tree:
        errors.append(
            f"root commit {root_commits[0]} has tree {root_tree}, expected "
            f"{expected_root_tree}"
        )


def validate_paths(
    git_directory: Path, forbidden_paths: list[str], errors: list[str]
) -> dict[str, set[str]]:
    """Check every path in every reachable tree; return blob id -> paths."""
    blob_paths: dict[str, set[str]] = {}
    visited_trees: set[str] = set()
    for commit in list_commits(git_directory):
        root_tree = tree_of_commit(git_directory, commit)
        if root_tree in visited_trees:
            continue
        visited_trees.add(root_tree)
        for object_type, object_id, path in list_tree_paths(git_directory, root_tree):
            if object_type == "blob":
                blob_paths.setdefault(object_id, set()).add(path)
            if not path_is_public(path):
                errors.append(
                    f"commit {commit} carries a path outside the public layout: {path}"
                )
            if path_is_forbidden(path, forbidden_paths):
                errors.append(f"commit {commit} carries a private path: {path}")
    return blob_paths


def list_all_objects(git_directory: Path) -> list[tuple[str, str, int]]:
    listing = run_git(
        git_directory,
        [
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ],
    )
    objects: list[tuple[str, str, int]] = []
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        objects.append((fields[0], fields[1], int(fields[2])))
    return objects


def read_object_bytes(git_directory: Path, object_ids: list[str]) -> dict[str, bytes]:
    """Read several objects in one `git cat-file --batch` pass."""
    if not object_ids:
        return {}
    stream = run_git_bytes(
        git_directory, ["cat-file", "--batch"], "\n".join(object_ids).encode() + b"\n"
    )
    contents: dict[str, bytes] = {}
    position = 0
    while position < len(stream):
        header_end = stream.find(b"\n", position)
        if header_end == -1:
            break
        header = stream[position:header_end].split()
        position = header_end + 1
        if len(header) != 3:
            continue
        object_id = header[0].decode()
        object_size = int(header[2])
        contents[object_id] = stream[position : position + object_size]
        position += object_size + 1
    return contents


def validate_object_contents(
    git_directory: Path,
    objects: list[tuple[str, str, int]],
    markers: list[str],
    errors: list[str],
) -> None:
    if not markers:
        return
    encoded_markers = [(marker, marker.encode("utf-8")) for marker in markers]
    scannable = [
        object_id
        for object_id, object_type, _ in objects
        if object_type in ("blob", "commit", "tag")
    ]
    kBatchSize = 256
    for batch_start in range(0, len(scannable), kBatchSize):
        batch = scannable[batch_start : batch_start + kBatchSize]
        for object_id, content in read_object_bytes(git_directory, batch).items():
            for marker, encoded_marker in encoded_markers:
                if encoded_marker in content:
                    errors.append(
                        f"object {object_id} contains the private marker {marker!r}"
                    )


def collect_private_blob_ids(
    git_directory: Path,
    forbidden_paths: list[str] | None,
    shared_private_paths: list[str],
) -> set[str]:
    """Fingerprint a reference repository's private blobs.

    With `forbidden_paths`, only blobs that ever lived at one of those paths
    count, which is what the pre-publication archive needs. Without it, every
    blob in the repository counts, which is what the private extension needs.
    """
    private_blob_ids: set[str] = set()
    blob_sizes = {
        object_id: object_size
        for object_id, object_type, object_size in list_all_objects(git_directory)
        if object_type == "blob"
    }
    visited_trees: set[str] = set()
    for commit in list_commits(git_directory):
        root_tree = tree_of_commit(git_directory, commit)
        if root_tree in visited_trees:
            continue
        visited_trees.add(root_tree)
        for object_type, object_id, path in list_tree_paths(git_directory, root_tree):
            if object_type != "blob":
                continue
            if blob_sizes.get(object_id, 0) < kMinimumFingerprintBytes:
                continue
            if path in shared_private_paths:
                continue
            if forbidden_paths is not None and not path_is_forbidden(path, forbidden_paths):
                continue
            private_blob_ids.add(object_id)
    return private_blob_ids


def validate_against_reference(
    public_blob_paths: dict[str, set[str]],
    public_commits: set[str],
    reference_name: str,
    reference_commits: set[str],
    private_blob_ids: set[str],
    errors: list[str],
) -> None:
    shared_commits = sorted(public_commits & reference_commits)
    for commit in shared_commits:
        errors.append(
            f"public history shares commit {commit} with {reference_name}; the "
            "public history must be freshly created, never copied"
        )
    for blob_id in sorted(set(public_blob_paths) & private_blob_ids):
        paths = ", ".join(sorted(public_blob_paths[blob_id]))
        errors.append(
            f"public object {blob_id} is byte-identical to a private blob in "
            f"{reference_name}, published as: {paths}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path, help="public repository or git directory")
    parser.add_argument(
        "--archive-reference",
        type=Path,
        action="append",
        default=[],
        help="pre-publication archive; its commits and paid-path blobs must not reappear",
    )
    parser.add_argument(
        "--private-reference",
        type=Path,
        action="append",
        default=[],
        help="private repository; none of its blobs may appear in public history",
    )
    parser.add_argument(
        "--private-policy",
        type=Path,
        action="append",
        default=[],
        help="JSON policy adding forbidden paths and content markers",
    )
    parser.add_argument(
        "--expect-root-tree",
        help="object id the single root commit's tree must equal",
    )
    arguments = parser.parse_args()

    errors: list[str] = []
    try:
        git_directory = resolve_git_directory(arguments.repository)
        policy = load_private_policy(arguments.private_policy, errors)

        validate_root_history(git_directory, arguments.expect_root_tree, errors)
        public_blob_paths = validate_paths(git_directory, policy["forbidden_paths"], errors)
        public_objects = list_all_objects(git_directory)
        validate_object_contents(git_directory, public_objects, policy["markers"], errors)

        public_commits = set(list_commits(git_directory))
        for archive_path in arguments.archive_reference:
            archive_directory = resolve_git_directory(archive_path)
            validate_against_reference(
                public_blob_paths,
                public_commits,
                f"archive {archive_path}",
                set(list_commits(archive_directory)),
                collect_private_blob_ids(
                    archive_directory,
                    policy["forbidden_paths"],
                    policy["shared_private_paths"],
                ),
                errors,
            )
        for private_path in arguments.private_reference:
            private_directory = resolve_git_directory(private_path)
            validate_against_reference(
                public_blob_paths,
                public_commits,
                f"private repository {private_path}",
                set(list_commits(private_directory)),
                collect_private_blob_ids(
                    private_directory, None, policy["shared_private_paths"]
                ),
                errors,
            )
    except GitError as error:
        errors.append(str(error))

    if errors:
        for error in sorted(set(errors)):
            print(f"public history error: {error}", file=sys.stderr)
        return 1

    print(
        "public history audit: OK "
        f"({len(public_commits)} commits, {len(public_objects)} objects, "
        f"{list_reference_count(git_directory)} refs)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
