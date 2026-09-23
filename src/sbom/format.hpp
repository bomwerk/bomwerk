#pragma once
#include <string_view>

namespace bomwerk::sbom
{

/// Which SBOM serialization a document's bytes look like, sniffed before any
/// real parsing happens. Exists so a document in the wrong format is named
/// correctly ("this is SPDX, not CycloneDX") instead of silently parsing as
/// an empty CycloneDX document with every field defaulted: the shape a bare
/// `{}` would also produce, which would otherwise be indistinguishable from
/// "a genuinely empty product".
enum class SbomInputFormat
{
  CycloneDx,
  Spdx,
  Unknown
};

/// Lower-case display label: the one user-facing string table shared with
/// every other `to_string(...)` in the codebase (future `--lang` hook), same
/// shape as `core::to_string(Confidence)`.
constexpr const char* to_string(SbomInputFormat format)
{
  switch (format)
  {
    case SbomInputFormat::CycloneDx:
      return "cyclonedx";
    case SbomInputFormat::Spdx:
      return "spdx";
    case SbomInputFormat::Unknown:
      return "unknown";
  }
  return "unknown";  // unreachable: all enumerators handled above
}

/// Sniff `bytes` for a CycloneDX `"bomFormat":"CycloneDX"` pair or a
/// top-level SPDX `"spdxVersion"` key: cheap, string-level checks that never
/// parse a single token of JSON, so a truncated or hostile file is still
/// named correctly even when it cannot be parsed at all (rule 1). Never
/// throws; anything unrecognized is `Unknown`, never an error.
[[nodiscard]] SbomInputFormat detect_sbom_format(std::string_view bytes);

}  // namespace bomwerk::sbom
