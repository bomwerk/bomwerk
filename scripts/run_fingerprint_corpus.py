#!/usr/bin/env python3
"""Check a built fingerprint corpus against the nightmare test corpus.

This is the ticket's own evidence: "a corpus match found on the nightmare repo".
It is deliberately NOT a ctest. It needs a checkout of
https://github.com/bomwerk/nightmare and an index built from pinned upstream
releases, so it runs by hand or on a schedule beside run_real_world_corpus.py,
never on a pull request.

It checks the CORPUS, not the scanner. It hashes nightmare's vendored files with
hashlib and looks the digests up in the index, which answers "does the corpus
know these bytes" without a bomwerk binary in the picture at all. That
separation is the point: when a scan reports no fingerprint evidence, this says
whether the corpus or the matcher is at fault. Confirming what the SCANNER then
reports is a separate step, documented at the bottom of this docstring.

The expectations below are facts about nightmare, taken from its own
`third_party/pins.json`, which records for every vendored file whether it
matches upstream byte for byte. The interesting ones:

- `freertos/list.c` is pinned `"modified": true`, so it must NOT match. It is the
  fork no tool in nightmare's own comparison detects.
- `freertos/include/FreeRTOSConfig.h` comes from upstream's
  `examples/template_configuration/`, so it must match DESPITE sitting at a
  different path. Any path-keyed scheme fails here.
- cJSON and uthash must be attributed to an exact version, which is what no
  version-header heuristic can do for them.

Usage:

    python3 scripts/build_fingerprint_corpus.py --profile smoke \\
        --out ../bomwerk-fingerprint-corpus/index.json
    python3 scripts/run_fingerprint_corpus.py \\
        --index ../bomwerk-fingerprint-corpus/index.json \\
        --nightmare ../nightmare

To confirm what the scanner makes of the same tree, scan an exported copy
(nightmare's own rule: scan an exported tree, never the working tree) and read
the `bomwerk:fingerprint` properties:

    ./build/bomwerk scan <exported-nightmare> --no-vuln \\
        --fingerprint-index ../bomwerk-fingerprint-corpus/index.json -o /tmp/n.cdx.json
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import sys


# Mirrors heuristics::fingerprint::kMinHashableBytes: a file below it never
# votes in the matcher, so this must not count it either.
K_MIN_HASHABLE_BYTES = 64

# Mirrors the matcher's sliver rule: a vendor root whose matched files are
# under one in eight of its hashable files is dropped outright, because a
# first-party directory holding one copied header is not that library. This
# harness has to apply it too, or it would report a healthy attribution for a
# root a real scan says nothing about.
K_SLIVER_NUMERATOR = 1
K_SLIVER_DENOMINATOR = 8


@dataclass(frozen=True)
class Expectation:
    """What `third_party/<root>` must come back as."""

    root: str
    library: str
    version: str
    #: Files that must NOT match, because pins.json records them as modified or
    #: as written by the corpus itself.
    must_not_match: tuple[str, ...] = ()
    #: Files that must match even though upstream keeps them elsewhere.
    must_match: tuple[str, ...] = ()


EXPECTATIONS = (
    Expectation(root="zlib", library="zlib", version="1.2.11"),
    Expectation(
        root="freertos",
        library="freertos",
        version="V11.1.0",
        must_not_match=("list.c",),
        must_match=("include/FreeRTOSConfig.h", "include/task.h"),
    ),
    Expectation(root="uthash", library="uthash", version="2.4.0"),
    Expectation(root="cjson-prebuilt", library="cjson", version="1.7.15"),
)


@dataclass
class RootOutcome:
    considered: int = 0
    matched: int = 0
    per_release: dict[int, int] = field(default_factory=dict)
    matched_paths: set[str] = field(default_factory=set)
    unmatched_paths: list[str] = field(default_factory=list)


class Index:
    def __init__(self, path: Path) -> None:
        document = json.loads(path.read_text(encoding="utf-8"))
        self.revision = document.get("corpus_revision", "unknown")
        self.libraries = document["libraries"]
        self.releases = document["releases"]
        self.files = document["files"]

    def label(self, release_index: int) -> tuple[str, str]:
        release = self.releases[release_index]
        return self.libraries[release["library"]]["name"], release["version"]

    def file_count(self, release_index: int) -> int:
        return int(self.releases[release_index]["file_count"])


def probe_root(index: Index, base: Path) -> RootOutcome:
    outcome = RootOutcome()
    for path in sorted(candidate for candidate in base.rglob("*") if candidate.is_file()):
        if path.stat().st_size < K_MIN_HASHABLE_BYTES:
            continue
        relative = path.relative_to(base).as_posix()
        outcome.considered += 1
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        hits = index.files.get(digest)
        if not hits:
            outcome.unmatched_paths.append(relative)
            continue
        outcome.matched += 1
        outcome.matched_paths.add(relative)
        for release_index in hits:
            outcome.per_release[release_index] = outcome.per_release.get(release_index, 0) + 1
    return outcome


def attribute(index: Index, outcome: RootOutcome) -> tuple[int, ...]:
    """The best-supported releases, by the matcher's own two criteria.

    Most matched files first, then the release whose own file list is most
    completely accounted for. More than one survivor means the evidence cannot
    separate them, which is exactly when the matcher asserts no version.
    """
    if not outcome.per_release:
        return ()
    ranked = sorted(
        outcome.per_release.items(),
        key=lambda item: (-item[1], index.file_count(item[0])),
    )
    best_count = ranked[0][1]
    best_file_count = index.file_count(ranked[0][0])
    return tuple(
        release_index
        for release_index, count in ranked
        if count == best_count and index.file_count(release_index) == best_file_count
    )


def check(index: Index, nightmare: Path, expectation: Expectation) -> list[str]:
    base = nightmare / "third_party" / expectation.root
    if not base.is_dir():
        return [f"{expectation.root}: no such directory under {nightmare}"]

    outcome = probe_root(index, base)
    problems: list[str] = []
    best = attribute(index, outcome)

    if not best:
        problems.append(
            f"{expectation.root}: no file matched the corpus at all. Is "
            f"{expectation.library} in the manifest's smoke profile, and do its "
            f"include_globs cover the files this directory vendors?"
        )
    elif len(best) > 1:
        candidates = ", ".join(sorted(f"{index.label(i)[1]}" for i in best))
        problems.append(
            f"{expectation.root}: the corpus cannot separate {candidates}, so a scan would "
            f"report the library with no version. Pin fewer, more distinct releases"
        )
    else:
        library, version = index.label(best[0])
        if library != expectation.library:
            problems.append(
                f"{expectation.root}: attributed to {library}, expected {expectation.library}"
            )
        if version != expectation.version:
            problems.append(
                f"{expectation.root}: attributed to {library} {version}, "
                f"expected {expectation.version}"
            )

    for relative in expectation.must_match:
        if relative not in outcome.matched_paths:
            problems.append(
                f"{expectation.root}: {relative} did not match, and it must. pins.json records "
                f"it as byte-identical to upstream; if it sits at a different path upstream, "
                f"that path has to be in the library's include_globs"
            )
    for relative in expectation.must_not_match:
        if relative in outcome.matched_paths:
            problems.append(
                f"{expectation.root}: {relative} matched upstream, and it must not. pins.json "
                f"records it as modified, so a match means the corpus holds the forked bytes "
                f"rather than the upstream ones"
            )

    if outcome.matched * K_SLIVER_DENOMINATOR < outcome.considered * K_SLIVER_NUMERATOR:
        problems.append(
            f"{expectation.root}: only {outcome.matched} of {outcome.considered} hashable "
            f"file(s) match, under one in {K_SLIVER_DENOMINATOR}, so the matcher drops this "
            f"root entirely and a scan would report no fingerprint evidence for it. Widen the "
            f"library's include_globs so the corpus covers more of what this directory vendors"
        )

    summary = f"{expectation.root}: {outcome.matched} of {outcome.considered} hashable file(s)"
    if best and len(best) == 1:
        library, version = index.label(best[0])
        summary += f" -> {library} {version}"
    print(summary)
    if outcome.unmatched_paths:
        print(f"    not in the corpus: {', '.join(outcome.unmatched_paths)}")
    return problems


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--index", type=Path, required=True, help="a built corpus index")
    parser.add_argument(
        "--nightmare", type=Path, required=True, help="a checkout of bomwerk/nightmare"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    if not arguments.index.is_file():
        raise SystemExit(
            f"no index at {arguments.index}; build one with build_fingerprint_corpus.py"
        )
    if not (arguments.nightmare / "third_party" / "pins.json").is_file():
        raise SystemExit(f"{arguments.nightmare} does not look like a nightmare checkout")

    index = Index(arguments.index)
    print(
        f"corpus {index.revision}: {len(index.libraries)} libraries, "
        f"{len(index.releases)} release(s), {len(index.files)} digest(s)"
    )
    problems: list[str] = []
    for expectation in EXPECTATIONS:
        problems.extend(check(index, arguments.nightmare, expectation))

    if problems:
        print("", file=sys.stderr)
        for problem in problems:
            print(f"FAIL {problem}", file=sys.stderr)
        return 1
    print("")
    print(f"all {len(EXPECTATIONS)} vendored root(s) attributed as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
