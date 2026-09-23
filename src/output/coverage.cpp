#include "output/coverage.hpp"

#include <algorithm>
#include <nlohmann/json.hpp>
#include <utility>

#include "core/match_coverage.hpp"
#include "core/timestamp.hpp"

namespace bomwerk::output
{
namespace
{

/// One component plus the two values every other part of this writer needs
/// about it, each computed exactly once: `identity` backs both the sort key
/// and the `"identity"` JSON field (`core::component_identity` parses the
/// purl: not free), and `coverage` backs both the `"coverage"` JSON field
/// and the running summary.
struct ClassifiedComponent
{
  const core::Component* component = nullptr;
  std::string identity;
  core::MatchCoverage coverage = core::MatchCoverage::Matched;
};

nlohmann::json component_to_json(const ClassifiedComponent& classified)
{
  const core::Component& component = *classified.component;
  nlohmann::json entry;
  entry["identity"] = classified.identity;
  entry["name"] = component.name;
  if (!component.version.empty())
  {
    entry["version"] = component.version;
  }
  if (!component.purl.empty())
  {
    entry["purl"] = component.purl;
  }
  entry["confidence"] = core::to_string(core::highest_confidence(component));
  entry["coverage"] = core::to_string(classified.coverage);
  return entry;
}

/// `summary.by_class`: every class, including `matched`, so a reader never
/// has to compute the matched count by subtraction (object key order is
/// canonical/alphabetical automatically: plain `nlohmann::json` is
/// map-backed, unlike the CycloneDX writer's `properties` ARRAY, which needs
/// its own explicit sort).
nlohmann::json summary_to_json(const core::MatchCoverageSummary& summary)
{
  nlohmann::json summary_json;
  summary_json["components"] = summary.total;
  summary_json["matchable"] = summary.matchable;
  summary_json["unmatched"] = summary.total - summary.matchable;

  nlohmann::json by_class;
  by_class[core::to_string(core::MatchCoverage::Matched)] = summary.matchable;
  by_class[core::to_string(core::MatchCoverage::UnmappedPurlType)] = summary.unmapped_purl_type;
  by_class[core::to_string(core::MatchCoverage::UnversionedPurl)] = summary.unversioned_purl;
  by_class[core::to_string(core::MatchCoverage::NoIdentifier)] = summary.no_identifier;
  summary_json["by_class"] = std::move(by_class);

  return summary_json;
}

}  // namespace

std::string write_coverage_report(const std::vector<core::Component>& components,
                                  const ToolInfo& tool, const core::ReleaseMeta& release_meta)
{
  nlohmann::json document;
  document["tool"]["name"] = tool.name;
  document["tool"]["version"] = tool.version;
  document["generated_at"] = core::current_timestamp_iso8601();

  if (!release_meta.product_id.empty())
  {
    document["product"]["id"] = release_meta.product_id;
    if (!release_meta.version.empty())
    {
      document["product"]["version"] = release_meta.version;
    }
  }

  // Identity and coverage class are each computed exactly once per component
  // here: not once for sorting/summarizing and again for serializing: and
  // the identity is precomputed before the sort so the comparator does a
  // plain string compare instead of re-parsing a purl on every comparison
  // (rule 3: still order-independent, since std::sort on a total order over
  // precomputed identities gives the same result regardless of input order).
  std::vector<ClassifiedComponent> classified_components;
  classified_components.reserve(components.size());
  core::MatchCoverageSummary summary;
  summary.total = components.size();
  for (const core::Component& component : components)
  {
    const core::MatchCoverage coverage = core::classify_match_coverage(component);
    switch (coverage)
    {
      case core::MatchCoverage::Matched:
        ++summary.matchable;
        break;
      case core::MatchCoverage::UnmappedPurlType:
        ++summary.unmapped_purl_type;
        break;
      case core::MatchCoverage::UnversionedPurl:
        ++summary.unversioned_purl;
        break;
      case core::MatchCoverage::NoIdentifier:
        ++summary.no_identifier;
        break;
    }
    classified_components.push_back(
        ClassifiedComponent{&component, core::component_identity(component), coverage});
  }
  document["summary"] = summary_to_json(summary);

  std::sort(classified_components.begin(), classified_components.end(),
            [](const ClassifiedComponent& left, const ClassifiedComponent& right)
            { return left.identity < right.identity; });

  nlohmann::json components_json = nlohmann::json::array();
  for (const ClassifiedComponent& classified : classified_components)
  {
    components_json.push_back(component_to_json(classified));
  }
  document["components"] = std::move(components_json);

  return document.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
}

}  // namespace bomwerk::output
