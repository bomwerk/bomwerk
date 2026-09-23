#pragma once
#include <cstddef>
#include <string_view>
#include <vector>

#include "core/model.hpp"

namespace bomwerk::core
{

/// How well a component's identifier supports vulnerability matching by ANY
/// purl-driven tool: not just whether bomwerk's own OSV client queried it on
/// this run. Every purl-based scanner (CRANE, Syft, Trivy) silently drops a
/// component once its purl falls outside the small set of ecosystems those
/// tools know; this taxonomy exists to make that drop visible instead of
/// invisible. `vuln::has_no_known_osv_coverage`/`is_queryable_purl` answer
/// the narrower "did THIS run query it" question and are defined in terms of
/// this classification (module dependency law: `vuln` may depend on `core`,
/// not the other way around).
enum class MatchCoverage
{
  Matched,           ///< purl-shaped, versioned, and OSV can query it: either directly (a mapped
                     ///< ecosystem) or by commit id (any purl type, when the version resolves to
                     ///< a 40/64-hex object id)
  UnmappedPurlType,  ///< purl-shaped and versioned, but the type has no OSV ecosystem at all
                     ///< (Conan, vcpkg, generic) and the version is not a resolvable commit id
  UnversionedPurl,   ///< purl-shaped but carries no resolved `@version` (a bare manifest
                     ///< dependency, e.g. an un-pinned vcpkg.json entry)
  NoIdentifier       ///< not purl-shaped at all: empty, or malformed
};

/// Lower-case, hyphenated label: the CycloneDX property value and the one
/// user-facing string table shared by the CLI, the coverage file and the
/// HTML report (future `--lang` hook). Same shape as `to_string(Confidence)`.
constexpr const char* to_string(MatchCoverage coverage)
{
  switch (coverage)
  {
    case MatchCoverage::Matched:
      return "matched";
    case MatchCoverage::UnmappedPurlType:
      return "unmapped-purl-type";
    case MatchCoverage::UnversionedPurl:
      return "unversioned-purl";
    case MatchCoverage::NoIdentifier:
      return "no-identifier";
  }
  return "no-identifier";  // unreachable: all enumerators handled above
}

/// One-sentence, human-readable reason a class is unmatched, shown next to
/// its count in the HTML report's coverage card and the coverage file.
/// `Matched` has nothing to explain, so its reason is empty.
constexpr const char* match_coverage_reason(MatchCoverage coverage)
{
  switch (coverage)
  {
    case MatchCoverage::Matched:
      return "";
    case MatchCoverage::UnmappedPurlType:
      return "package type has no OSV ecosystem mapping (Conan, vcpkg, generic)";
    case MatchCoverage::UnversionedPurl:
      return "no resolved version: nothing to match against";
    case MatchCoverage::NoIdentifier:
      return "no purl at all: component has no matchable identifier";
  }
  return "";  // unreachable: all enumerators handled above
}

/// Classify a bare purl. The commit check runs BEFORE the type check: a
/// component pinned to a 40/64-hex commit id queries OSV's global commit
/// index, which matches regardless of purl type: so `pkg:generic/x@<sha>`
/// (a submodule with no resolvable origin URL, or vendored code with no
/// upstream) is `Matched`, exactly like `pkg:github/x/x@<sha>` is, not
/// `UnmappedPurlType`.
[[nodiscard]] MatchCoverage classify_match_coverage(std::string_view purl);

/// Convenience overload over `component.purl`.
[[nodiscard]] MatchCoverage classify_match_coverage(const Component& component);

/// Aggregate counts across a component set. Order-independent by
/// construction (each component contributes to exactly one bucket), so two
/// runs over the same set in different orders agree (rule 3).
struct MatchCoverageSummary
{
  std::size_t total = 0;
  std::size_t matchable = 0;  ///< total - (the three unmatched counts below)
  std::size_t unmapped_purl_type = 0;
  std::size_t unversioned_purl = 0;
  std::size_t no_identifier = 0;
};

[[nodiscard]] MatchCoverageSummary summarize_match_coverage(
    const std::vector<Component>& components);

}  // namespace bomwerk::core
