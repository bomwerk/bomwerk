#pragma once
#include <cstddef>
#include <filesystem>
#include <string_view>

#include "core/result.hpp"
#include "sbom/document.hpp"

namespace bomwerk::sbom
{

/// Upper bound for one SBOM file read (`core::read_file_bounded`). A real
/// product SBOM runs from a few KiB to a few MiB; this only exists to cap
/// the memory/parse cost a hostile or corrupted file dropped into a watched
/// folder could otherwise impose on a long-running daemon (same defensive
/// posture as `core::json_utils::kMaxFileBytes`, sized up for a whole-BOM
/// document rather than one manifest).
inline constexpr std::size_t kMaxSbomFileBytes = 32u * 1024u * 1024u;  // 32 MiB

/// Parse `bytes` as a CycloneDX 1.x JSON document: the shape
/// `output::write_cyclonedx` produces: into the shared `core::Component`
/// model. Never throws (rule 1): malformed JSON, an over-deep document, a
/// missing or wrong-typed `components` array, or an individual component
/// entry that is not a JSON object all degrade to a warning plus whatever
/// components parsed: partial output beats none. Components are returned
/// through `core::merge_all`, so the result carries the same identity and
/// ordering guarantees as every producer's output (rule 3).
[[nodiscard]] core::Result<SbomDocument> read_cyclonedx(std::string_view bytes);

/// Read `path` (bounded to `kMaxSbomFileBytes`) and dispatch on
/// `detect_sbom_format`. An SPDX document warns by name: this reader takes
/// CycloneDX only today: rather than silently parsing as empty; an
/// unrecognized or unreadable file warns and yields an empty document.
/// Never throws.
[[nodiscard]] core::Result<SbomDocument> load_sbom_file(const std::filesystem::path& path);

}  // namespace bomwerk::sbom
