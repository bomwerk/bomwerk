#pragma once
#include <cstddef>
#include <string>

#include "binscan/binary_map.hpp"

namespace bomwerk::binscan
{

/// Schema version of the sidecar document. Bumped when a reader could
/// misinterpret the new shape: the fingerprint matcher is the first consumer, and it must be able
/// to refuse a document it does not understand rather than silently read
/// fields that moved.
inline constexpr int kSidecarSchemaVersion = 1;

/// Render `map` as the `.bomwerk/binscan.json` sidecar: every artifact opened,
/// what it declared, and the symbol sample taken from it.
///
/// This is where "symbol sample stored" lands. It is deliberately NOT part of
/// the SBOM: a sample of a few hundred symbols per artifact would dominate a
/// CycloneDX document that consumers read for identity, while the fingerprint
/// matcher that wants it reads a file, not a BOM. The SBOM carries the
/// conclusion (`core::Source::Binary` evidence); this carries the workings.
///
/// Deterministic (rule 3), and more strictly than the SBOM writers: plain
/// `nlohmann::json` (not `ordered_json`) so object keys are canonically
/// sorted, every array pre-sorted by its producer, paths root-relative so two
/// machines with different checkout locations emit identical bytes, and NO
/// timestamp at all: there is nothing here whose value is the moment it was
/// written, so the file needs no `SOURCE_DATE_EPOCH` handling to be
/// reproducible.
///
/// Never throws (rule 1): invalid UTF-8 in a symbol or member name is replaced
/// during serialization, not rejected: the same guard the CycloneDX, SPDX and
/// coverage writers apply, and it matters more here, since these bytes came
/// out of an untrusted binary rather than a text manifest.
[[nodiscard]] std::string render_binscan_sidecar(const BinaryMap& map);

}  // namespace bomwerk::binscan
