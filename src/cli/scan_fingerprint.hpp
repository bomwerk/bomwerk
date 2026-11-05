#pragma once
#include <cstddef>
#include <vector>

#include "core/model.hpp"
#include "core/result.hpp"
#include "heuristics/fingerprint.hpp"

namespace bomwerk::cli
{

/// What one fingerprint pass did to the component list, for the scan summary.
struct FingerprintApplication
{
  std::size_t roots_matched = 0;
  std::size_t versions_filled = 0;
  std::size_t identities_rewritten = 0;
  std::size_t version_disagreements = 0;
  std::size_t matches_without_component = 0;
};

/// Attribute `matches` onto `components`, joining on `Component::root`.
///
/// CALL BEFORE `core::merge_all`. This pass can change a component's purl, and
/// `core::component_identity` (the canonical purl) is the merge key, while
/// rule 3 derives every bom-ref as UUIDv5 of that purl. Rewriting afterwards
/// would leave a stale merge key, emit an id computed from a purl the component
/// no longer carries, and let two components rewritten to one purl survive as
/// separate entries sharing a bom-ref. `binscan::apply_binary_evidence` is
/// post-merge precisely because it only appends evidence and never touches
/// identity, so it is the wrong precedent here. Running pre-merge also means a
/// rewritten identity merges normally with whatever conan or vcpkg declared.
///
/// What it does to a component whose `root` a match names:
/// - always appends `core::Source::Fingerprint` evidence;
/// - fills `license` only when empty;
/// - never touches `sha256`: `core::Component::sha256` is the digest of the
///   source archive or main artifact, and a per-file corpus match is not that;
/// - touches `name`, `version` and `purl` in exactly ONE case, when the
///   existing identity is unversioned AND folder-derived. That single predicate
///   characterises the vendored heuristic's last-resort branch and nothing else
///   in the tree, so an identity another producer resolved provably cannot be
///   overwritten. It is what turns `pkg:generic/cjson-prebuilt` into
///   `pkg:generic/cjson@1.7.15`;
/// - otherwise never changes identity. A version another producer resolved is a
///   declaration BY THE PROJECT, and replacing it would hide a real finding, so
///   a conflict raises `BW-FINGERPRINT-004` and keeps the declared value. An
///   unversioned component whose identity came from somewhere other than its
///   folder name gets evidence only: filling its version would mean rebuilding
///   a purl this pass did not author, whose type is not ours to change.
///
/// A match whose root no component carries raises
/// `BW-FINGERPRINT-005` and is otherwise ignored. v1 deliberately does not
/// invent a component there: doing so would make this pass a second, competing
/// producer of identity and would change component counts on trees that scan
/// correctly today.
///
/// Never throws across the CLI boundary (rule 1), and never sets
/// `complete = false`: the SBOM is whole without a corpus.
[[nodiscard]] core::Result<FingerprintApplication> apply_fingerprint_matches(
    const std::vector<heuristics::fingerprint::RootMatch>& matches,
    std::vector<core::Component>& components);

}  // namespace bomwerk::cli
