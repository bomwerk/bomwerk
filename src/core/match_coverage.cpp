#include "core/match_coverage.hpp"

#include <string_view>

#include "core/purl.hpp"
#include "core/text.hpp"

namespace bomwerk::core
{
namespace
{

/// Package types with no OSV ecosystem at all (verified against OSV's own
/// ecosystem list: see `vuln::osv.hpp`'s doc comment for how). A component
/// of one of these types is still `Matched` when its version is a resolvable
/// commit id: see `classify_match_coverage`'s doc comment.
constexpr std::string_view kUnmappedPurlTypes[] = {"conan", "vcpkg", "generic"};

}  // namespace

MatchCoverage classify_match_coverage(std::string_view purl)
{
  const std::string_view identity_part = purl_identity_part(purl);
  if (!identity_part.starts_with("pkg:"))
  {
    return MatchCoverage::NoIdentifier;
  }

  const std::string_view version = purl_version_of(identity_part);
  if (version.empty())
  {
    return MatchCoverage::UnversionedPurl;
  }

  // The commit check precedes the type check: OSV's commit index matches by
  // sha regardless of purl type, so a commit-pinned Conan/vcpkg/generic
  // component is coverable exactly like a commit-pinned github one.
  if (is_hex_object_id(version))
  {
    return MatchCoverage::Matched;
  }

  const std::string_view type = purl_type_of(purl);
  for (const std::string_view unmapped_type : kUnmappedPurlTypes)
  {
    if (type == unmapped_type)
    {
      return MatchCoverage::UnmappedPurlType;
    }
  }
  return MatchCoverage::Matched;
}

MatchCoverage classify_match_coverage(const Component& component)
{
  return classify_match_coverage(component.purl);
}

MatchCoverageSummary summarize_match_coverage(const std::vector<Component>& components)
{
  MatchCoverageSummary summary;
  summary.total = components.size();
  for (const Component& component : components)
  {
    switch (classify_match_coverage(component))
    {
      case MatchCoverage::Matched:
        break;
      case MatchCoverage::UnmappedPurlType:
        ++summary.unmapped_purl_type;
        break;
      case MatchCoverage::UnversionedPurl:
        ++summary.unversioned_purl;
        break;
      case MatchCoverage::NoIdentifier:
        ++summary.no_identifier;
        break;
    }
  }
  summary.matchable =
      summary.total - summary.unmapped_purl_type - summary.unversioned_purl - summary.no_identifier;
  return summary;
}

}  // namespace bomwerk::core
