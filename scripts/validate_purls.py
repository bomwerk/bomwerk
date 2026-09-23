#!/usr/bin/env python3
"""Validate every purl in an SBOM against the reference purl-spec parser.

Usage: validate_purls.py <sbom.json> [<sbom.json> ...]

Reads CycloneDX (components[].purl) and SPDX 2.3/3.0 (externalRefs with
referenceType "purl", or software_packageUrl) documents, and for each component
asserts three things:

  1. a purl is present and non-empty -- bomwerk is the identity source of truth
     for every downstream consumer, so a component without one silently breaks
     THEIR vulnerability matching, not just ours;
  2. the reference parser (packageurl-python, the purl-spec implementation)
     accepts it;
  3. parsing is a fixed point -- re-parsing the reference serializer's own
     output yields an identical (type, namespace, name, version, qualifiers,
     subpath) tuple.

Why compare the parsed TUPLE and not the raw strings: bomwerk percent-encodes
':' and '/' inside qualifier values (download_url=https%3A%2F%2F...), which is
spec-legal but is not the spelling the reference serializer emits. A byte
round-trip would therefore fail on correct output and prove nothing. The tuple
comparison is the check that actually carries meaning: it says the two sides
agree on what the purl MEANS, which is precisely what a downstream consumer
reads.

Deliberately separate from core::Purl (src/core/purl.cpp), which is the identity
CANONICALIZER, not a validator: it is lenient on purpose because it feeds
component_identity -> merge_all grouping -> the UUIDv5 bom-refs, and tightening
it would move identities across all producers. The authoritative spec check
lives out here instead, where being strict is free.

CI/dev tooling, like validate_cyclonedx_schema.py -- not a bomwerk build
dependency, so it is not a vcpkg.json entry (Hard Rule 4 governs what the
scanner links, not what CI runs).
"""
import json
import sys
from pathlib import Path

# Exit code reserved for "the reference parser is not installed". CMake maps it
# to a ctest SKIP so a bare dev machine reports the test as skipped rather than
# failed, while CI -- which installs the module -- can never skip silently. A
# real spec violation is exit 1, and a usage error exit 2.
TOOLING_UNAVAILABLE = 77

try:
    from packageurl import PackageURL
except ImportError:
    print(
        "packageurl-python is not installed; install it with\n"
        "  python3 -m pip install packageurl-python",
        file=sys.stderr,
    )
    sys.exit(TOOLING_UNAVAILABLE)


def qualifier_items(qualifiers):
    """Qualifiers as a sorted (key, value) tuple, order-independent.
    packageurl-python returns a dict from from_string(), but its PackageURL
    accepts a raw "a=b&c=d" string too; normalize both so a future version
    changing that representation surfaces as a real diff, not a crash."""
    if not qualifiers:
        return ()
    if isinstance(qualifiers, str):
        pairs = []
        for entry in qualifiers.split("&"):
            key, separator, value = entry.partition("=")
            if separator:
                pairs.append((key, value))
        return tuple(sorted(pairs))
    return tuple(sorted(qualifiers.items()))


def purl_identity(purl):
    """The tuple a downstream consumer actually reads, with qualifiers order-
    independent. Compared instead of the raw string -- see module docstring."""
    return (
        purl.type,
        purl.namespace,
        purl.name,
        purl.version,
        qualifier_items(purl.qualifiers),
        purl.subpath,
    )


def collect_components(document):
    """Yield (label, purl-or-None) for every component in a CycloneDX or SPDX
    document. `label` names the component in failure output."""
    # CycloneDX 1.6: components[].purl
    for component in document.get("components", []):
        label = component.get("name") or component.get("bom-ref") or "<unnamed>"
        yield label, component.get("purl")

    # SPDX 2.3: packages[].externalRefs[] with referenceType "purl"
    for package in document.get("packages", []):
        label = package.get("name") or package.get("SPDXID") or "<unnamed>"
        purl = None
        for external_ref in package.get("externalRefs", []):
            if external_ref.get("referenceType") == "purl":
                purl = external_ref.get("referenceLocator")
                break
        yield label, purl

    # SPDX 3.0: the graph carries software_Package elements directly.
    for element in document.get("@graph", []):
        if not isinstance(element, dict):
            continue
        if "software_packageUrl" not in element:
            continue
        label = element.get("name") or element.get("spdxId") or "<unnamed>"
        yield label, element.get("software_packageUrl")


def validate_document(sbom_path):
    """Validate one SBOM. Returns (checked_count, [failure messages])."""
    document = json.loads(sbom_path.read_text(encoding="utf-8"))
    failures = []
    checked = 0

    for label, raw_purl in collect_components(document):
        checked += 1

        if not raw_purl:
            failures.append(f"{label}: component has no purl (null or empty)")
            continue

        try:
            parsed = PackageURL.from_string(raw_purl)
        except ValueError as error:
            failures.append(f"{label}: purl-spec parser rejected {raw_purl!r}: {error}")
            continue

        try:
            reparsed = PackageURL.from_string(parsed.to_string())
        except ValueError as error:
            failures.append(
                f"{label}: {raw_purl!r} did not survive a round trip through the "
                f"reference serializer: {error}"
            )
            continue

        if purl_identity(parsed) != purl_identity(reparsed):
            failures.append(
                f"{label}: {raw_purl!r} is not a parsing fixed point -- "
                f"{purl_identity(parsed)} became {purl_identity(reparsed)}"
            )

    return checked, failures


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <sbom.json> [<sbom.json> ...]", file=sys.stderr)
        return 2

    total_checked = 0
    total_failures = 0

    for argument in sys.argv[1:]:
        sbom_path = Path(argument)
        checked, failures = validate_document(sbom_path)
        total_checked += checked
        total_failures += len(failures)
        for failure in failures:
            print(f"{sbom_path}: {failure}", file=sys.stderr)

    if total_failures:
        print(
            f"FAIL: {total_failures} of {total_checked} purls are not spec-valid",
            file=sys.stderr,
        )
        return 1

    # An SBOM with no components at all would otherwise "pass" vacuously; the
    # golden cases all carry components, so zero means the harness broke.
    if total_checked == 0:
        print("FAIL: no components found to validate", file=sys.stderr)
        return 1

    print(f"OK: {total_checked} purls conform to the purl spec")
    return 0


if __name__ == "__main__":
    sys.exit(main())
