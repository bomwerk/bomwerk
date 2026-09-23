#pragma once
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/model.hpp"

namespace bomwerk::vuln
{

/// Longest product or version segment accepted into a CPE match string. Real
/// CPE dictionary entries are far shorter (the longest NVD product names sit
/// under 60 characters); this is a hostile-input bound, not a spec limit.
inline constexpr std::size_t kMaxCpeSegmentBytes = 128;

/// Build the NVD `virtualMatchString` for a component purl, or nothing when
/// the purl cannot safely produce one.
///
/// The result has the shape `cpe:2.3:a:*:<product>:<version>`: part `a`
/// (Conan/vcpkg/generic all package applications and libraries), a WILDCARD
/// VENDOR, the purl's bare name as product and its resolved version.
///
/// The wildcard vendor is the whole reason this path works without a
/// hand-maintained vendor table: NVD's `virtualMatchString` does not require a
/// value in the vendor component, so `cpe:2.3:a:*:zlib:1.2.11` matches
/// whichever vendor NVD filed zlib under. The price is that a DIFFERENT
/// vendor's product with the same name matches too, which is exactly why every
/// finding from this path carries `MatchProvenance::CpeFallback` and is shown
/// as lower-confidence rather than being presented like an OSV purl match.
///
/// SECURITY (rule 1): `purl` comes from a manifest in the repo under audit and
/// this value is interpolated into a URL query parameter, so the segments are
/// VALIDATED, never escaped into submission. Nothing is produced when either
/// segment is empty, exceeds `kMaxCpeSegmentBytes`, or holds any character
/// outside `[a-z0-9._+-]` after ASCII-lowercasing. That set excludes `:` and
/// `*` (which would forge CPE structure), `?`, `&` and `#` (which would forge
/// query parameters), `/`, `\`, quotes, whitespace and every control byte. A
/// rejected component is counted and warned about by the caller: never
/// silently dropped, and never sent.
///
/// Examples: `pkg:conan/zlib@1.2.11` -> `cpe:2.3:a:*:zlib:1.2.11`;
/// `pkg:vcpkg/OpenSSL@3.2.0` -> `cpe:2.3:a:*:openssl:3.2.0`;
/// `pkg:conan/zlib` (no version) -> nothing.
[[nodiscard]] std::optional<std::string> cpe_match_string_for(std::string_view purl);

/// Build a complete CPE 2.3 formatted identifier for SBOM publication, or
/// nothing when `purl` cannot safely produce one. This shares all parsing and
/// validation with `cpe_match_string_for`, but appends the seven remaining
/// wildcard attributes required by the formatted-string binding.
[[nodiscard]] std::optional<std::string> cpe_identifier_for(std::string_view purl);

/// How broadly `populate_cpe_identifiers` synthesizes CPEs. There is
/// deliberately no default: every call site (`scan`/`trim`/`binscan`) must
/// say which behavior it wants rather than silently inheriting one, since the
/// two scopes change SBOM bytes very differently.
enum class CpePopulationScope
{
  /// The long-standing default: only the same versioned Conan, vcpkg and
  /// generic components the NVD fallback targets (`core::MatchCoverage::
  /// UnmappedPurlType`): the ecosystems with no OSV mapping at all. A plain
  /// scan's output is byte-identical to before `--all-cpes` existed.
  UnmappedOnly,
  /// The `--all-cpes` opt-in: every purl `cpe_identifier_for` can safely turn
  /// into a non-empty product/version pair, regardless of OSV coverage: this
  /// adds npm, Go, and every other OSV-native ecosystem, plus commit-pinned
  /// purls of any type. Every identifier this scope creates is marked
  /// `core::CpeProvenance::SynthesizedWildcardVendor` so a consumer can tell
  /// it apart from a precise, upstream-sourced CPE.
  AllVersioned
};

/// Populate missing CPE identifiers under `scope` (see `CpePopulationScope`).
/// Existing identifiers (and their provenance) are always preserved verbatim,
/// and failure to derive one is silent: publishing an optional identifier
/// must not degrade a scan or change its exit code.
void populate_cpe_identifiers(std::vector<core::Component>& components, CpePopulationScope scope);

/// Percent-encode `value` for use as a URL query-parameter value, escaping
/// everything outside the RFC 3986 unreserved set (`A-Za-z0-9-._~`). Exposed
/// (rather than kept internal to the NVD client) so the encoding a request
/// actually uses is directly testable.
[[nodiscard]] std::string percent_encode_query_value(std::string_view value);

}  // namespace bomwerk::vuln
