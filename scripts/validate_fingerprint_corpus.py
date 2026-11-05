#!/usr/bin/env python3
"""Hermetic contract checks for the fingerprint corpus manifest and builder.

Runs as a ctest with no network: it reads `scripts/fingerprint_corpus.json`,
checks its shape, and exercises the builder's pure functions against synthetic
trees. The one check that needs the network, re-resolving each pinned ref
against its remote, lives in `build_fingerprint_corpus.py --resolve` and runs on
a schedule or by hand, never on a pull request.

Three classes of drift this is here to catch:

1. A hand-edited manifest. Commit ids must be 40 lowercase hex, versions unique
   per library, every library must have at least one release.
2. The manifest losing a library the rest of the repository depends on. The
   nightmare-corpus documentation claims a corpus match on specific vendored
   directories, so those libraries have to be in tier 0.
3. The builder and the matcher disagreeing about which files are evidence.
   `K_MIN_HASHABLE_BYTES` and `K_MAX_HASHED_FILE_BYTES` are duplicated in C++
   and in Python, and an index that records a file the matcher would skip holds
   an entry that can never match.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPOSITORY_ROOT / "scripts" / "fingerprint_corpus.json"
FINGERPRINT_HEADER = REPOSITORY_ROOT / "src" / "heuristics" / "fingerprint.hpp"

COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")

# Libraries the rest of the repository's claims depend on. Each one is a
# vendored directory the nightmare corpus pins, so dropping it from tier 0 would
# silently stop the documented match from happening.
REQUIRED_TIER_0 = frozenset({"zlib", "freertos", "uthash", "cjson"})


def load_builder():
    script_path = REPOSITORY_ROOT / "scripts" / "build_fingerprint_corpus.py"
    specification = importlib.util.spec_from_file_location("build_fingerprint_corpus", script_path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot import {script_path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def check_manifest_shape(builder) -> None:
    pinned_at, libraries = builder.load_manifest(MANIFEST_PATH)
    require(bool(pinned_at), "manifest has no pinned_at")
    require(bool(libraries), "manifest lists no libraries")

    seen_names: set[str] = set()
    for library in libraries:
        require(library.name not in seen_names, f"duplicate library {library.name}")
        seen_names.add(library.name)
        require(library.name == library.name.lower(), f"{library.name}: name must be lowercase")
        require(library.source == "git", f"{library.name}: only git sources are supported today")
        require(
            library.upstream.startswith("https://"),
            f"{library.name}: upstream must be an https URL",
        )
        require(bool(library.purl_type), f"{library.name}: no purl_type")
        require(bool(library.why), f"{library.name}: no why, every pin states its reason")
        require(bool(library.include_globs), f"{library.name}: no include_globs")
        require(0 <= library.tier <= 2, f"{library.name}: tier {library.tier} is out of range")
        require(bool(library.releases), f"{library.name}: no releases")

        seen_versions: set[str] = set()
        for release in library.releases:
            label = f"{library.name} {release.version}"
            require(bool(release.version), f"{library.name}: a release has no version")
            require(release.version not in seen_versions, f"{label}: duplicate version")
            seen_versions.add(release.version)
            require(bool(release.ref), f"{label}: no ref")
            require(
                COMMIT_PATTERN.match(release.commit) is not None,
                f"{label}: commit must be 40 lowercase hex, got {release.commit!r}. Run "
                f"build_fingerprint_corpus.py --resolve rather than editing it by hand",
            )

    # Sorted by name, which is what keeps a built index's library order
    # independent of the manifest's own ordering.
    names = [library.name for library in libraries]
    require(names == sorted(names), "load_manifest must return libraries sorted by name")


def check_required_libraries_are_in_smoke(builder) -> None:
    _pinned_at, libraries = builder.load_manifest(MANIFEST_PATH)
    smoke = {library.name for library in builder.select_libraries(libraries, "smoke", [])}
    missing = REQUIRED_TIER_0 - smoke
    require(
        not missing,
        f"libraries the repository's own claims depend on are missing from the smoke profile: "
        f"{', '.join(sorted(missing))}",
    )
    # Profiles have to nest, or --profile demo could lose a smoke library.
    demo = {library.name for library in builder.select_libraries(libraries, "demo", [])}
    everything = {library.name for library in builder.select_libraries(libraries, "all", [])}
    require(smoke <= demo <= everything, "profiles must nest: smoke within demo within all")


def check_limits_match_the_matcher(builder) -> None:
    header = FINGERPRINT_HEADER.read_text(encoding="utf-8")

    def constant(name: str) -> int:
        match = re.search(rf"{name}\s*=\s*([0-9u*\s]+);", header)
        require(match is not None, f"{name} not found in fingerprint.hpp")
        # A product of integer literals, folded by hand rather than eval'd: the
        # input comes from a source file, and a parser this small is not worth
        # reaching for eval.
        value = 1
        for factor in match.group(1).replace("u", "").split("*"):
            value *= int(factor.strip())
        return value

    require(
        builder.K_MIN_HASHABLE_BYTES == constant("kMinHashableBytes"),
        "K_MIN_HASHABLE_BYTES does not match kMinHashableBytes: the builder would record files "
        "the matcher skips, or skip files it would have matched",
    )
    require(
        builder.K_MAX_HASHED_FILE_BYTES == constant("kMaxHashedFileBytes"),
        "K_MAX_HASHED_FILE_BYTES does not match kMaxHashedFileBytes",
    )
    require(
        builder.K_INDEX_SCHEMA_VERSION == constant("kIndexSchemaVersion"),
        "the builder writes a schema version the matcher would refuse",
    )


def check_exclusion_covers_subtrees(builder) -> None:
    patterns = ("test/*", "doc")
    require(builder.is_excluded("test/foo.c", patterns), "an immediate child must be excluded")
    require(
        builder.is_excluded("test/unit/deep/foo.c", patterns),
        "'test/*' must exclude the whole subtree, not only immediate children",
    )
    require(builder.is_excluded("doc/readme.md", patterns), "a bare directory name must exclude")
    require(not builder.is_excluded("src/test_helpers.c", patterns), "a prefix must not match")
    require(not builder.is_excluded("latest/foo.c", patterns), "a look-alike must not match")


def check_tree_build_is_reproducible_and_skips_tiny_files(builder) -> None:
    with tempfile.TemporaryDirectory(prefix="bomwerk_fingerprint_") as temporary:
        tree = Path(temporary) / "zlib"
        tree.mkdir()
        # Comfortably over the floor, so it is real evidence.
        (tree / "deflate.c").write_bytes(b"/* deflate */\n" + b"x" * 200)
        (tree / "inflate.c").write_bytes(b"/* inflate */\n" + b"y" * 200)
        # Under the floor, so the builder must leave it out.
        (tree / "tiny.h").write_bytes(b"#pragma once\n")

        first, _notes = builder.build_from_tree(tree, "zlib", "1.2.11", "Zlib", "2026-11-03")
        second, _again = builder.build_from_tree(tree, "zlib", "1.2.11", "Zlib", "2026-11-03")
        require(first == second, "two builds of one tree must be byte-identical")

        document = json.loads(first)
        require(document["schema_version"] == builder.K_INDEX_SCHEMA_VERSION, "wrong schema")
        require(len(document["libraries"]) == 1, "one library expected")
        require(len(document["releases"]) == 1, "one release expected")
        require(
            len(document["files"]) == 2,
            f"the file under {builder.K_MIN_HASHABLE_BYTES} bytes must be skipped, "
            f"got {len(document['files'])} digests",
        )
        require(
            document["releases"][0]["file_count"] == 2,
            "file_count is release coverage's denominator: it counts files HASHED, not files "
            "on disk",
        )
        for digest, releases in document["files"].items():
            require(COMMIT_PATTERN.match(digest) is None, "a digest is 64 hex, not 40")
            require(re.match(r"^[0-9a-f]{64}$", digest) is not None, f"bad digest key {digest!r}")
            require(releases == [0], f"{digest}: should reference release 0")
        require(
            document["corpus_revision"] == "2026-11-03",
            "corpus_revision must come from the manifest, never from a clock",
        )
        # No absolute path may reach the artifact: it would differ per machine.
        require(temporary not in first, "the index must not embed an absolute path")


def check_serialization_is_canonical(builder) -> None:
    text = builder.serialize({"b": 2, "a": {"d": 4, "c": 3}})
    require(text == '{"a":{"c":3,"d":4},"b":2}\n', f"serialization is not canonical: {text!r}")


def check_prefilter_encoding_matches_the_scanner(builder) -> None:
    """The cheap pass only works if both sides agree on one number.

    The scanner probes with the numeric XXH3_64bits value and parses the index's
    16 hex digits as a big-endian integer, and xxhash's hexdigest() is the
    canonical big-endian form. XXH3_64bits of empty input is the published value
    0x2D06800538D394C2, which test_file_io asserts on the C++ side. Pinning the
    Python side to the same digits closes the loop: were the two byte orders ever
    to differ, every probe would miss and matching would quietly find nothing.
    Skipped, not failed, without the optional module, since an index with no
    prefilter is still correct.
    """
    try:
        import xxhash  # noqa: PLC0415  (optional dependency, probed at runtime)
    except ImportError:
        print("note: xxhash not installed, prefilter encoding not checked", file=sys.stderr)
        return
    require(
        xxhash.xxh3_64().hexdigest() == "2d06800538d394c2",
        "xxh3_64 of empty input must hex to 2d06800538d394c2, the value the scanner expects",
    )
    require(
        builder.load_fast_hasher(True) is not None,
        "the builder must find the xxhash module the validator just imported",
    )
    require(
        builder.load_fast_hasher(False) is None,
        "--no-prefilter must really disable the prefilter",
    )


def check_stale_checkout_is_refused(builder) -> None:
    """A leftover checkout must be the pinned commit, unmodified, or it is refused."""
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        print("note: git not found, stale-checkout guard not checked", file=sys.stderr)
        return

    _pinned_at, libraries = builder.load_manifest(MANIFEST_PATH)
    library = libraries[0]
    environment = builder.sanitized_git_environment()
    environment.update(
        GIT_AUTHOR_NAME="test",
        GIT_AUTHOR_EMAIL="test@example.invalid",
        GIT_COMMITTER_NAME="test",
        GIT_COMMITTER_EMAIL="test@example.invalid",
    )

    def git(checkout: Path, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        require(
            completed.returncode == 0,
            f"git {' '.join(arguments)} failed: {completed.stderr.strip()}",
        )
        return completed.stdout.strip()

    def refused(release) -> bool:
        try:
            builder.verify_existing_checkout(library, release, checkout)
        except RuntimeError:
            return True
        return False

    with tempfile.TemporaryDirectory(prefix="bomwerk_fingerprint_git_") as temporary:
        checkout = Path(temporary) / "pinned"
        checkout.mkdir()
        git(checkout, "init", "--quiet")
        (checkout / "a.c").write_text("int a;\n", encoding="utf-8")
        git(checkout, "add", "a.c")
        git(checkout, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "pinned")
        head = git(checkout, "rev-parse", "HEAD")

        pinned = builder.Release(version="1.0", ref="v1.0", commit=head)
        repinned = builder.Release(version="1.0", ref="v1.0", commit="0" * 40)

        require(not refused(pinned), "a checkout at the pinned commit must be accepted")
        require(
            refused(repinned),
            "a checkout left over from an earlier pin must be refused: reusing it would "
            "record the new commit beside the old bytes",
        )
        (checkout / "a.c").write_text("int tampered;\n", encoding="utf-8")
        require(
            refused(pinned),
            "a checkout with a modified tracked file must be refused even at the right commit",
        )


def main() -> int:
    builder = load_builder()
    checks = (
        check_manifest_shape,
        check_required_libraries_are_in_smoke,
        check_limits_match_the_matcher,
        check_exclusion_covers_subtrees,
        check_tree_build_is_reproducible_and_skips_tiny_files,
        check_serialization_is_canonical,
        check_prefilter_encoding_matches_the_scanner,
        check_stale_checkout_is_refused,
    )
    failures = 0
    for check in checks:
        try:
            check(builder)
        except AssertionError as error:
            print(f"{check.__name__}: {error}", file=sys.stderr)
            failures += 1
    if failures:
        print(f"{failures} fingerprint corpus check(s) failed", file=sys.stderr)
        return 1
    print(f"fingerprint corpus: {len(checks)} check(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
