#pragma once

namespace bomwerk::core
{

/// SBOM output flavors bomwerk can produce. Typed so
/// invalid formats are unrepresentable past the CLI boundary.
enum class SbomFormat
{
  CycloneDx,
  Spdx
};

/// Canonical lower-case name, as spelled on the CLI and in reports.
constexpr const char* to_string(SbomFormat format)
{
  switch (format)
  {
    case SbomFormat::CycloneDx:
      return "cyclonedx";
    case SbomFormat::Spdx:
      return "spdx";
  }
  return "unknown";  // unreachable: all enumerators handled above
}

/// Which SPDX specification the `Spdx` writer emits. Kept a separate axis
/// from `SbomFormat`: `spdx` is one format with two serializations, so the
/// enum and its existing tests stay unchanged and the CLI selects it with its
/// own `--spdx-version` flag. `V3_0` (3.0.1, JSON-LD) is the default; `V2_3`
/// (classic flat JSON) stays available for consumers whose tooling has not yet
/// moved. Only meaningful when `SbomFormat::Spdx` is selected.
enum class SpdxVersion
{
  V2_3,
  V3_0
};

/// Canonical dotted version string, as spelled on the CLI (`--spdx-version`)
/// and written into the document (`SPDX-2.3` / `specVersion 3.0.1`).
constexpr const char* to_string(SpdxVersion version)
{
  switch (version)
  {
    case SpdxVersion::V2_3:
      return "2.3";
    case SpdxVersion::V3_0:
      return "3.0";
  }
  return "unknown";  // unreachable: all enumerators handled above
}

}  // namespace bomwerk::core
