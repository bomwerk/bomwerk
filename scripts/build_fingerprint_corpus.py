#!/usr/bin/env python3
"""Build a fingerprint corpus index from pinned upstream releases.

The index maps a file's SHA-256 to the releases that contain exactly those
bytes, which is what lets `bomwerk scan --fingerprint-index` identify a vendored
C/C++ library by content instead of by a version header.

What this script does NOT do, deliberately:

- It never executes anything it downloads. Repositories are fetched at an
  immutable commit, checked out detached, hooks disabled, and read as files.
- It never normalizes file content. The index records the digest of the bytes
  upstream published, so an operator can verify any claim with `sha256sum` and a
  third party can rebuild the index and get the same bytes. The consequence is
  real: a checkout that rewrote line endings will not match. The fix belongs
  here, as additional CRLF-variant entries, not in the matcher.
- It never writes into the repository. The corpus directory defaults to a
  sibling of the checkout, and the built index is an artifact, not a tracked
  file: bomwerk ships the matcher and the manifest, not the corpus.

Reproducibility: the output is canonical JSON (sorted keys, no whitespace), all
integers, with no clock, no hostname and no absolute paths anywhere in it.
Building the same manifest twice produces identical bytes, which `--verify`
checks.

The xxh3 prefilter needs the same algorithm the scanner uses. When the `xxhash`
module is absent the index is still correct and complete, just without that
cheap first pass, and matching pays for a SHA-256 on every hashable file.
Install it (`pip install xxhash`) to emit the prefilter.

Examples:

    # Everything the tests and the nightmare check need.
    build_fingerprint_corpus.py --profile smoke --out ../corpus/index.json

    # Re-resolve every pinned ref against its remote (needs the network).
    build_fingerprint_corpus.py --resolve

    # Prove the build is reproducible.
    build_fingerprint_corpus.py --profile smoke --verify ../corpus/index.json

    # Index one local tree, for a test fixture.
    build_fingerprint_corpus.py --from-tree fixtures/golden/x/tree/third_party/zlib \\
        --library zlib --version 1.2.11 --license Zlib --out fixtures/golden/x/index.json
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Iterable, Sequence


K_SCHEMA_VERSION = 1
K_INDEX_SCHEMA_VERSION = 1
K_PROFILE_MAX_TIER = {"smoke": 0, "demo": 1, "all": 2}
K_GIT_TIMEOUT_SECONDS = 900
K_COMMIT_LENGTH = 40

# Mirrors heuristics::fingerprint::kMinHashableBytes. A file below it never
# votes in the matcher, so recording one would only inflate the index: an empty
# file or a 20-byte `#pragma once` header is identical across unrelated
# projects. Keep the two in step; validate_fingerprint_corpus.py asserts it.
K_MIN_HASHABLE_BYTES = 64

# Mirrors heuristics::fingerprint::kMaxHashedFileBytes: the matcher refuses a
# file above this, so an entry for one could never match.
K_MAX_HASHED_FILE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class Release:
    version: str
    ref: str
    commit: str


@dataclass(frozen=True)
class Library:
    name: str
    tier: int
    source: str
    upstream: str
    purl_type: str
    purl_namespace: str
    license: str
    why: str
    include_globs: tuple[str, ...]
    exclude_globs: tuple[str, ...]
    releases: tuple[Release, ...]

    def slug(self, release: Release) -> str:
        return f"{self.name}--{release.version}".replace("/", "--")


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_corpus_directory() -> Path:
    # Outside the checkout by default, like run_real_world_corpus.py: downloaded
    # third-party source is never mixed into the repository being scanned.
    return repository_root().parent / "bomwerk-fingerprint-corpus"


def manifest_path() -> Path:
    return Path(__file__).with_name("fingerprint_corpus.json")


def load_manifest(path: Path | None = None) -> tuple[str, tuple[Library, ...]]:
    document = json.loads((path or manifest_path()).read_text(encoding="utf-8"))
    if document.get("schema_version") != K_SCHEMA_VERSION:
        raise SystemExit(
            f"manifest schema_version must be {K_SCHEMA_VERSION}, "
            f"got {document.get('schema_version')!r}"
        )
    pinned_at = document.get("pinned_at")
    if not isinstance(pinned_at, str) or not pinned_at:
        raise SystemExit("manifest has no pinned_at")

    libraries: list[Library] = []
    for entry in document.get("libraries", []):
        releases = tuple(
            Release(
                version=release["version"],
                ref=release["ref"],
                commit=release["commit"],
            )
            for release in entry["releases"]
        )
        libraries.append(
            Library(
                name=entry["name"],
                tier=int(entry["tier"]),
                source=entry.get("source", "git"),
                upstream=entry["upstream"],
                purl_type=entry.get("purl_type", "generic"),
                purl_namespace=entry.get("purl_namespace", ""),
                license=entry.get("license", ""),
                why=entry.get("why", ""),
                include_globs=tuple(entry.get("include_globs", ())),
                exclude_globs=tuple(entry.get("exclude_globs", ())),
                releases=releases,
            )
        )
    # Sorted by name so the built index's library order never depends on the
    # manifest's own ordering.
    return pinned_at, tuple(sorted(libraries, key=lambda library: library.name))


def select_libraries(
    libraries: Sequence[Library], profile: str, requested: Sequence[str]
) -> list[Library]:
    if requested:
        by_name = {library.name: library for library in libraries}
        missing = [name for name in requested if name not in by_name]
        if missing:
            raise SystemExit(f"unknown library name(s): {', '.join(sorted(missing))}")
        return [by_name[name] for name in sorted(requested)]
    max_tier = K_PROFILE_MAX_TIER[profile]
    return [library for library in libraries if library.tier <= max_tier]


# --- git, sandboxed the same way run_real_world_corpus.py does ---------------


def sanitized_git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_LFS_SKIP_SMUDGE"] = "1"
    environment.pop("GIT_DIR", None)
    environment.pop("GIT_WORK_TREE", None)
    return environment


def run_git(arguments: Sequence[str], *, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=K_GIT_TIMEOUT_SECONDS,
    )


def checked_git(arguments: Sequence[str], *, environment: dict[str, str]) -> str:
    completed = run_git(arguments, environment=environment)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "git failed"
        raise RuntimeError(f"git {' '.join(arguments[:3])}: {detail}")
    return completed.stdout


def resolve_remote_commit(upstream: str, ref: str, *, environment: dict[str, str]) -> str | None:
    """The commit `ref` names upstream, dereferenced through an annotated tag.

    This is the trap nightmare's pins.json documents: an annotated tag has its
    own object id, and pinning that instead of `refs/tags/<ref>^{}` still fetches
    the right tree, so the mistake stays invisible. The dereferenced id wins
    whenever the remote advertises one.
    """
    output = checked_git(
        ["ls-remote", "--tags", upstream, f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"],
        environment=environment,
    )
    plain: str | None = None
    dereferenced: str | None = None
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        object_id, name = parts
        if name == f"refs/tags/{ref}^{{}}":
            dereferenced = object_id
        elif name == f"refs/tags/{ref}":
            plain = object_id
    return dereferenced or plain


def verify_existing_checkout(library: Library, release: Release, checkout: Path) -> None:
    """Refuse a leftover checkout that is not the pinned commit, byte for byte.

    A checkout directory is named by library and version, not by commit, so
    re-pinning a release (the usual way a wrong commit gets fixed) leaves the old
    directory in place under the same name. Reusing it would hash the OLD bytes
    and record the NEW commit beside them: an index whose provenance is a lie,
    with nothing in the output to show it. A hand-edited file under the same name
    does the same. Asking git catches both; trusting the directory name does not.
    """
    environment = sanitized_git_environment()
    head = checked_git(["-C", str(checkout), "rev-parse", "HEAD"], environment=environment)
    if head.strip() != release.commit:
        raise RuntimeError(
            f"{checkout}: checked out at {head.strip()}, but the manifest pins "
            f"{library.name} {release.version} at {release.commit}; delete the directory "
            f"to download it again"
        )
    modified = checked_git(
        ["-C", str(checkout), "status", "--porcelain", "--untracked-files=no"],
        environment=environment,
    )
    if modified.strip():
        raise RuntimeError(
            f"{checkout}: has modified tracked files, so its bytes are no longer the pinned "
            f"release; delete the directory to download it again"
        )


def download_release(
    library: Library, release: Release, corpus_directory: Path, *, verify_ref: bool
) -> Path:
    destination = corpus_directory / library.slug(release)
    if (destination / ".git").is_dir():
        verify_existing_checkout(library, release, destination)
        return destination

    environment = sanitized_git_environment()
    if verify_ref:
        advertised = resolve_remote_commit(library.upstream, release.ref, environment=environment)
        if advertised is None:
            raise RuntimeError(f"{library.name} {release.ref}: the remote advertises no such tag")
        if advertised != release.commit:
            raise RuntimeError(
                f"{library.name} {release.ref}: manifest pins {release.commit} but the remote "
                f"resolves it to {advertised}; re-pin with --resolve rather than editing by hand"
            )

    corpus_directory.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{library.slug(release)}-", dir=corpus_directory))
    try:
        checked_git(
            ["-c", "init.templateDir=", "init", "--quiet", str(staging)], environment=environment
        )
        disabled_hooks = staging / ".git" / "disabled-hooks"
        disabled_hooks.mkdir()
        for name, value in (
            ("core.hooksPath", str(disabled_hooks)),
            # The bytes upstream published, not the bytes this platform prefers.
            # Without these a Windows checkout would hash CRLF content and build
            # an index nothing on Linux can match.
            ("core.autocrlf", "false"),
            ("core.eol", "lf"),
            ("core.symlinks", "false"),
        ):
            checked_git(["-C", str(staging), "config", name, value], environment=environment)
        checked_git(
            ["-C", str(staging), "remote", "add", "origin", library.upstream],
            environment=environment,
        )
        checked_git(
            [
                "-C",
                str(staging),
                "-c",
                "protocol.file.allow=never",
                "fetch",
                "--depth=1",
                "--filter=blob:none",
                "origin",
                release.commit,
            ],
            environment=environment,
        )
        checked_git(
            [
                "-C",
                str(staging),
                "-c",
                "advice.detachedHead=false",
                "checkout",
                "--quiet",
                "--detach",
                "FETCH_HEAD",
            ],
            environment=environment,
        )
        staging.replace(destination)
        return destination
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


# --- hashing ----------------------------------------------------------------


def load_fast_hasher(enabled: bool = True):
    """`xxhash.xxh3_64` when available and wanted, else None.

    The prefilter is an optimisation, never an authority: the matcher treats an
    index without one as "always maybe" and falls back to SHA-256 per file. So a
    missing module costs scan time, not correctness, and is not worth a hard
    dependency on a script most people never run.

    The equivalence that makes it work is load-bearing and worth stating:
    `xxhash.xxh3_64().hexdigest()` is the big-endian hex of the same 64-bit value
    the scanner's `XXH3_64bits` produces at the default seed, which is how the
    scanner's probe can hit an entry this script wrote. If a prefilter were ever
    written in the other byte order, every probe would miss and matching would
    quietly find nothing, so `--no-prefilter` exists to rule that out in one run.
    """
    if not enabled:
        return None
    try:
        import xxhash  # noqa: PLC0415  (optional dependency, probed at runtime)
    except ImportError:
        return None
    return xxhash.xxh3_64


def is_excluded(relative_posix: str, patterns: Sequence[str]) -> bool:
    """Whether an exclude glob covers this path.

    A pattern matches the path itself, and `test/*` additionally covers the
    WHOLE subtree rather than only its immediate children: a manifest that says
    "not the tests" means it, and `fnmatch` alone would let `test/unit/foo.c`
    through. Exclusion always wins over inclusion, the same precedence
    `core::build_file_index` applies.
    """
    for pattern in patterns:
        if fnmatch.fnmatch(relative_posix, pattern):
            return True
        subtree = pattern[:-2] if pattern.endswith("/*") else pattern
        if relative_posix == subtree or relative_posix.startswith(subtree + "/"):
            return True
    return False


def selected_files(checkout: Path, library: Library) -> list[Path]:
    """Files under `checkout` the manifest selects, as sorted relative paths.

    Globs are matched against POSIX-style relative paths so a manifest reads the
    same on every platform. Symlinks are skipped rather than followed: a
    repository is untrusted input here, and a link out of the checkout must not
    pull an unrelated file into the index.
    """
    chosen: set[Path] = set()
    for pattern in library.include_globs:
        for candidate in checkout.glob(pattern):
            if candidate.is_file() and not candidate.is_symlink():
                chosen.add(candidate.relative_to(checkout))
    # Never index the clone's own repository metadata.
    return sorted(
        relative
        for relative in chosen
        if ".git" not in relative.parts
        and not is_excluded(relative.as_posix(), library.exclude_globs)
    )


def digest_file(path: Path, fast_hasher) -> tuple[str, str | None, int] | None:
    """`(sha256_hex, xxh3_hex_or_None, size)`, or None when the file is skipped.

    Skips exactly what the matcher would skip, so the index never holds an entry
    that could not match: unreadable files, files below the minimum hashable
    size, and files above the per-file cap.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size < K_MIN_HASHABLE_BYTES or size > K_MAX_HASHED_FILE_BYTES:
        return None

    sha256 = hashlib.sha256()
    fast = fast_hasher() if fast_hasher is not None else None
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                sha256.update(chunk)
                if fast is not None:
                    fast.update(chunk)
    except OSError:
        return None
    return sha256.hexdigest(), (fast.hexdigest() if fast is not None else None), size


# --- index assembly ---------------------------------------------------------


class IndexBuilder:
    def __init__(self, corpus_revision: str, built_from: str) -> None:
        self._corpus_revision = corpus_revision
        self._built_from = built_from
        self._libraries: list[dict[str, object]] = []
        self._releases: list[dict[str, object]] = []
        self._files: dict[str, set[int]] = {}
        self._prefilter: set[str] = set()
        self._skipped_files = 0

    def add_library(self, library: Library) -> int:
        self._libraries.append(
            {
                "name": library.name,
                "purl_type": library.purl_type,
                "purl_namespace": library.purl_namespace,
                "license": library.license,
                "upstream": library.upstream,
            }
        )
        return len(self._libraries) - 1

    def add_release(self, library_index: int, release: Release, file_count: int) -> int:
        self._releases.append(
            {
                "library": library_index,
                "version": release.version,
                "ref": release.ref,
                "commit": release.commit,
                # Assigned from the manifest's own listing order, so the matcher
                # never has to parse a version string.
                "order": len(self._releases),
                "file_count": file_count,
            }
        )
        return len(self._releases) - 1

    def add_file(self, release_index: int, sha256_hex: str, fast_hex: str | None) -> None:
        self._files.setdefault(sha256_hex, set()).add(release_index)
        if fast_hex is not None:
            self._prefilter.add(fast_hex)

    def note_skipped_file(self) -> None:
        self._skipped_files += 1

    @property
    def skipped_files(self) -> int:
        return self._skipped_files

    def document(self) -> dict[str, object]:
        return {
            "schema_version": K_INDEX_SCHEMA_VERSION,
            "generator": "bomwerk build_fingerprint_corpus.py",
            "built_from": self._built_from,
            "corpus_revision": self._corpus_revision,
            "digest_algorithm": "sha256",
            "libraries": self._libraries,
            "releases": self._releases,
            "prefilter": sorted(self._prefilter),
            "files": {
                digest: sorted(releases) for digest, releases in sorted(self._files.items())
            },
        }


def serialize(document: dict[str, object]) -> str:
    """Canonical JSON: sorted keys, no incidental whitespace, one newline.

    No clock, no hostname, no absolute path, integers only. Two builds of one
    manifest therefore produce identical bytes (hard rule 3's discipline applied
    to a data artifact rather than to an SBOM).
    """
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def build_from_manifest(
    libraries: Sequence[Library],
    pinned_at: str,
    corpus_directory: Path,
    *,
    verify_refs: bool,
    prefilter: bool,
) -> tuple[str, list[str]]:
    fast_hasher = load_fast_hasher(prefilter)
    builder = IndexBuilder(corpus_revision=pinned_at, built_from="scripts/fingerprint_corpus.json")
    notes: list[str] = []
    if fast_hasher is None:
        notes.append(
            "xxhash module not installed: built without the prefilter, so scans using this "
            "index will hash every vendored file with SHA-256 (correct, just slower). "
            "pip install xxhash to emit it."
        )

    for library in libraries:
        library_index = builder.add_library(library)
        for release in library.releases:
            checkout = download_release(
                library, release, corpus_directory, verify_ref=verify_refs
            )
            files = selected_files(checkout, library)
            digests: list[tuple[str, str | None]] = []
            for relative in files:
                digested = digest_file(checkout / relative, fast_hasher)
                if digested is None:
                    builder.note_skipped_file()
                    continue
                sha256_hex, fast_hex, _size = digested
                digests.append((sha256_hex, fast_hex))
            if not digests:
                notes.append(
                    f"{library.name} {release.version}: no file matched include_globs "
                    f"{list(library.include_globs)}, release recorded with no content"
                )
            # file_count is release coverage's denominator in the matcher, so it
            # counts the files actually HASHED, not the files on disk.
            release_index = builder.add_release(library_index, release, len(digests))
            for sha256_hex, fast_hex in digests:
                builder.add_file(release_index, sha256_hex, fast_hex)

    return serialize(builder.document()), notes


def build_from_tree(
    tree: Path,
    name: str,
    version: str,
    license_id: str,
    corpus_revision: str,
    *,
    prefilter: bool = True,
    exclude_globs: Sequence[str] = (),
) -> tuple[str, list[str]]:
    """Index one local directory as a single release.

    For a test fixture: the hermetic golden case needs an index built from the
    fixture's own bytes, so no third-party content has to enter the repository
    for the wiring to be proved end to end.
    """
    fast_hasher = load_fast_hasher(prefilter)
    library = Library(
        name=name,
        tier=0,
        source="tree",
        upstream="",
        purl_type="generic",
        purl_namespace="",
        license=license_id,
        why="built from a local tree",
        include_globs=("**/*",),
        exclude_globs=tuple(exclude_globs),
        releases=(Release(version=version, ref=version, commit=""),),
    )
    builder = IndexBuilder(corpus_revision=corpus_revision, built_from=str(tree.name))
    library_index = builder.add_library(library)
    digests: list[tuple[str, str | None]] = []
    for relative in selected_files(tree, library):
        digested = digest_file(tree / relative, fast_hasher)
        if digested is None:
            builder.note_skipped_file()
            continue
        digests.append((digested[0], digested[1]))
    release_index = builder.add_release(library_index, library.releases[0], len(digests))
    for sha256_hex, fast_hex in digests:
        builder.add_file(release_index, sha256_hex, fast_hex)

    notes: list[str] = []
    if builder.skipped_files:
        notes.append(
            f"{builder.skipped_files} file(s) skipped as too small to be evidence "
            f"(under {K_MIN_HASHABLE_BYTES} bytes); pad a fixture file if it must match"
        )
    return serialize(builder.document()), notes


def report_resolution(libraries: Iterable[Library]) -> int:
    """Re-resolve every pinned ref against its remote and report disagreements."""
    environment = sanitized_git_environment()
    problems = 0
    for library in libraries:
        for release in library.releases:
            try:
                advertised = resolve_remote_commit(
                    library.upstream, release.ref, environment=environment
                )
            except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
                print(f"{library.name} {release.ref}: {error}", file=sys.stderr)
                problems += 1
                continue
            if advertised is None:
                print(f"{library.name} {release.ref}: no such tag upstream", file=sys.stderr)
                problems += 1
            elif advertised != release.commit:
                print(
                    f"{library.name} {release.ref}: manifest says {release.commit}, "
                    f"remote says {advertised}",
                    file=sys.stderr,
                )
                problems += 1
            else:
                print(f"{library.name} {release.ref} -> {advertised} (ok)")
    return problems


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, help="where to write the index")
    parser.add_argument(
        "--profile",
        choices=sorted(K_PROFILE_MAX_TIER),
        default="smoke",
        help="which manifest tiers to include (default: smoke)",
    )
    parser.add_argument(
        "--only", action="append", default=[], metavar="NAME", help="build just this library"
    )
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=None,
        help=f"where downloads live (default: {default_corpus_directory()})",
    )
    parser.add_argument(
        "--no-verify-refs",
        action="store_true",
        help="skip re-resolving each pinned ref against its remote before fetching",
    )
    parser.add_argument(
        "--verify",
        type=Path,
        metavar="INDEX",
        help="rebuild and compare against an existing index instead of writing one",
    )
    parser.add_argument(
        "--no-prefilter",
        action="store_true",
        help="omit the xxh3 prefilter; scans stay correct and hash every file with SHA-256",
    )
    parser.add_argument("--resolve", action="store_true", help="re-resolve pinned refs and exit")
    parser.add_argument("--from-tree", type=Path, help="index one local directory")
    parser.add_argument("--library", help="library name for --from-tree")
    parser.add_argument("--version", dest="release_version", help="version for --from-tree")
    parser.add_argument("--license", dest="license_id", default="", help="SPDX id for --from-tree")
    parser.add_argument(
        "--exclude-glob",
        action="append",
        default=[],
        metavar="GLOB",
        help="with --from-tree: leave these paths out of the index (repeatable)",
    )
    parser.add_argument(
        "--corpus-revision",
        default=None,
        help="corpus_revision to record (default: the manifest's pinned_at)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    pinned_at, libraries = load_manifest()

    if arguments.resolve:
        return 1 if report_resolution(libraries) else 0

    if arguments.from_tree is not None:
        if not arguments.library or not arguments.release_version:
            raise SystemExit("--from-tree needs --library and --version")
        if not arguments.from_tree.is_dir():
            raise SystemExit(f"not a directory: {arguments.from_tree}")
        document, notes = build_from_tree(
            arguments.from_tree,
            arguments.library,
            arguments.release_version,
            arguments.license_id,
            arguments.corpus_revision or pinned_at,
            prefilter=not arguments.no_prefilter,
            exclude_globs=tuple(arguments.exclude_glob),
        )
    else:
        selected = select_libraries(libraries, arguments.profile, arguments.only)
        if not selected:
            raise SystemExit(f"no library in profile {arguments.profile!r}")
        corpus_directory = arguments.corpus_dir or default_corpus_directory()
        try:
            document, notes = build_from_manifest(
                selected,
                arguments.corpus_revision or pinned_at,
                corpus_directory,
                verify_refs=not arguments.no_verify_refs,
                prefilter=not arguments.no_prefilter,
            )
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
            raise SystemExit(str(error)) from error

    for note in notes:
        print(f"note: {note}", file=sys.stderr)

    if arguments.verify is not None:
        existing = arguments.verify.read_text(encoding="utf-8")
        if existing == document:
            print(f"{arguments.verify}: reproduced byte for byte")
            return 0
        print(
            f"{arguments.verify}: differs from a fresh build "
            f"({len(existing)} bytes on disk, {len(document)} rebuilt)",
            file=sys.stderr,
        )
        return 1

    if arguments.out is None:
        raise SystemExit("--out is required unless --verify or --resolve is given")
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(document, encoding="utf-8")
    parsed = json.loads(document)
    print(
        f"{arguments.out}: {len(parsed['libraries'])} libraries, "
        f"{len(parsed['releases'])} release(s), {len(parsed['files'])} digest(s), "
        f"{len(parsed['prefilter'])} prefilter entries"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
