#include "core/cvss.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <iterator>
#include <optional>
#include <string_view>

namespace bomwerk::core
{
namespace
{

/// CVSS v3.1 base-metric constants (specification §7.4, metric weights).
constexpr double kExploitabilityCoefficient = 8.22;
constexpr double kScopeChangedCoefficient = 1.08;
constexpr double kImpactUnchangedCoefficient = 6.42;
constexpr double kImpactChangedCoefficient = 7.52;
constexpr double kImpactChangedSubtractor = 0.029;
constexpr double kImpactChangedScaler = 3.25;
constexpr double kImpactChangedScalerSubtractor = 0.02;
constexpr double kImpactChangedExponent = 15.0;
constexpr double kMaxScore = 10.0;

/// Qualitative-rating thresholds (spec §5, table 14): [0]=None only at 0.0,
/// then Low ≥0.1, Medium ≥4.0, High ≥7.0, Critical ≥9.0.
constexpr double kLowFloor = 0.1;
constexpr double kMediumFloor = 4.0;
constexpr double kHighFloor = 7.0;
constexpr double kCriticalFloor = 9.0;

/// One metric's weight lookup: matches an abbreviation to its numeric weight.
struct MetricWeight
{
  std::string_view abbreviation;
  double weight;
};

/// Attack Vector (AV) weights.
constexpr MetricWeight kAttackVectorWeights[] = {{"N", 0.85}, {"A", 0.62}, {"L", 0.55}, {"P", 0.2}};
/// Attack Complexity (AC) weights.
constexpr MetricWeight kAttackComplexityWeights[] = {{"L", 0.77}, {"H", 0.44}};
/// User Interaction (UI) weights.
constexpr MetricWeight kUserInteractionWeights[] = {{"N", 0.85}, {"R", 0.62}};
/// Confidentiality/Integrity/Availability (C/I/A) weights, shared.
constexpr MetricWeight kImpactWeights[] = {{"H", 0.56}, {"L", 0.22}, {"N", 0.0}};
/// Privileges Required (PR) when Scope is Unchanged.
constexpr MetricWeight kPrivilegesUnchangedWeights[] = {{"N", 0.85}, {"L", 0.62}, {"H", 0.27}};
/// Privileges Required (PR) when Scope is Changed (L/H are worth more).
constexpr MetricWeight kPrivilegesChangedWeights[] = {{"N", 0.85}, {"L", 0.68}, {"H", 0.5}};

std::optional<double> weight_of(const MetricWeight* table, std::size_t count,
                                std::string_view value)
{
  for (std::size_t index = 0; index < count; ++index)
  {
    if (table[index].abbreviation == value)
    {
      return table[index].weight;
    }
  }
  return std::nullopt;
}

/// The parsed base metrics needed for scoring. Each is filled from the vector;
/// a missing mandatory metric leaves its optional empty => unscorable.
struct BaseMetrics
{
  std::optional<std::string_view> attack_vector;
  std::optional<std::string_view> attack_complexity;
  std::optional<std::string_view> privileges_required;
  std::optional<std::string_view> user_interaction;
  std::optional<std::string_view> scope;
  std::optional<std::string_view> confidentiality;
  std::optional<std::string_view> integrity;
  std::optional<std::string_view> availability;
};

/// Assign one `KEY:VALUE` metric pair into `metrics`; unknown keys (temporal,
/// environmental, or vendor extensions) are ignored: only base metrics score.
void assign_metric(BaseMetrics& metrics, std::string_view key, std::string_view value)
{
  if (key == "AV")
  {
    metrics.attack_vector = value;
  }
  else if (key == "AC")
  {
    metrics.attack_complexity = value;
  }
  else if (key == "PR")
  {
    metrics.privileges_required = value;
  }
  else if (key == "UI")
  {
    metrics.user_interaction = value;
  }
  else if (key == "S")
  {
    metrics.scope = value;
  }
  else if (key == "C")
  {
    metrics.confidentiality = value;
  }
  else if (key == "I")
  {
    metrics.integrity = value;
  }
  else if (key == "A")
  {
    metrics.availability = value;
  }
}

/// CVSS v3.1 Roundup (spec §7.5): round up to one decimal place using an
/// integer intermediate so binary floating-point noise cannot tip a boundary
/// score the wrong way.
double roundup(double input)
{
  const int scaled = static_cast<int>(std::lround(input * 100000.0));
  if (scaled % 10000 == 0)
  {
    return scaled / 100000.0;
  }
  return (std::floor(scaled / 10000.0) + 1.0) / 10.0;
}

SeverityRating rating_for_score(double score)
{
  if (score >= kCriticalFloor)
  {
    return SeverityRating::Critical;
  }
  if (score >= kHighFloor)
  {
    return SeverityRating::High;
  }
  if (score >= kMediumFloor)
  {
    return SeverityRating::Medium;
  }
  if (score >= kLowFloor)
  {
    return SeverityRating::Low;
  }
  return SeverityRating::None;
}

}  // namespace

const char* to_string(SeverityRating rating)
{
  switch (rating)
  {
    case SeverityRating::Critical:
      return "Critical";
    case SeverityRating::High:
      return "High";
    case SeverityRating::Medium:
      return "Medium";
    case SeverityRating::Low:
      return "Low";
    case SeverityRating::None:
      return "None";
    case SeverityRating::Unknown:
      return "Unknown";
  }
  return "Unknown";  // unreachable: all enumerators handled above
}

bool more_severe(const ScoredAdvisory& left, const ScoredAdvisory& right)
{
  // A scored advisory always outranks an unscored one; two scored ones compare
  // by score; anything still tied falls back to id for a total order.
  if (left.severity.has_score != right.severity.has_score)
  {
    return left.severity.has_score;
  }
  if (left.severity.has_score && left.severity.score != right.severity.score)
  {
    return left.severity.score > right.severity.score;
  }
  return left.id < right.id;
}

CvssScore score_cvss_vector(std::string_view vector_string)
{
  // Only CVSS v3.0/v3.1 share this base formula. A v2 or v4 vector: or a bare
  // score with no version prefix: is honestly left unscored (rule: never
  // claim more accuracy than the data supports), not forced through a formula
  // that does not apply to it.
  if (!vector_string.starts_with("CVSS:3.0/") && !vector_string.starts_with("CVSS:3.1/"))
  {
    return {};
  }
  const std::string_view metrics_part = vector_string.substr(std::string_view("CVSS:3.0").size());

  BaseMetrics metrics;
  std::size_t cursor = 0;
  while (cursor < metrics_part.size())
  {
    if (metrics_part[cursor] == '/')
    {
      ++cursor;
      continue;
    }
    const std::size_t segment_end = metrics_part.find('/', cursor);
    const std::string_view segment =
        metrics_part.substr(cursor, segment_end == std::string_view::npos ? std::string_view::npos
                                                                          : segment_end - cursor);
    const std::size_t colon = segment.find(':');
    if (colon != std::string_view::npos)
    {
      assign_metric(metrics, segment.substr(0, colon), segment.substr(colon + 1));
    }
    if (segment_end == std::string_view::npos)
    {
      break;
    }
    cursor = segment_end + 1;
  }

  // Every base metric is mandatory; a vector missing any is malformed and
  // stays unscored rather than scored on defaults.
  if (!metrics.attack_vector || !metrics.attack_complexity || !metrics.privileges_required ||
      !metrics.user_interaction || !metrics.scope || !metrics.confidentiality ||
      !metrics.integrity || !metrics.availability)
  {
    return {};
  }
  const bool scope_changed = *metrics.scope == "C";
  const bool scope_unchanged = *metrics.scope == "U";
  if (!scope_changed && !scope_unchanged)
  {
    return {};
  }

  const std::optional<double> attack_vector =
      weight_of(kAttackVectorWeights, std::size(kAttackVectorWeights), *metrics.attack_vector);
  const std::optional<double> attack_complexity = weight_of(
      kAttackComplexityWeights, std::size(kAttackComplexityWeights), *metrics.attack_complexity);
  const std::optional<double> user_interaction = weight_of(
      kUserInteractionWeights, std::size(kUserInteractionWeights), *metrics.user_interaction);
  const MetricWeight* privileges_table =
      scope_changed ? kPrivilegesChangedWeights : kPrivilegesUnchangedWeights;
  const std::optional<double> privileges_required = weight_of(
      privileges_table, std::size(kPrivilegesUnchangedWeights), *metrics.privileges_required);
  const std::optional<double> confidentiality =
      weight_of(kImpactWeights, std::size(kImpactWeights), *metrics.confidentiality);
  const std::optional<double> integrity =
      weight_of(kImpactWeights, std::size(kImpactWeights), *metrics.integrity);
  const std::optional<double> availability =
      weight_of(kImpactWeights, std::size(kImpactWeights), *metrics.availability);
  if (!attack_vector || !attack_complexity || !user_interaction || !privileges_required ||
      !confidentiality || !integrity || !availability)
  {
    return {};
  }

  const double impact_sub_score =
      1.0 - ((1.0 - *confidentiality) * (1.0 - *integrity) * (1.0 - *availability));
  double impact = 0.0;
  if (scope_changed)
  {
    impact = kImpactChangedCoefficient * (impact_sub_score - kImpactChangedSubtractor) -
             kImpactChangedScaler * std::pow(impact_sub_score - kImpactChangedScalerSubtractor,
                                             kImpactChangedExponent);
  }
  else
  {
    impact = kImpactUnchangedCoefficient * impact_sub_score;
  }

  double base_score = 0.0;
  if (impact > 0.0)
  {
    const double exploitability = kExploitabilityCoefficient * *attack_vector * *attack_complexity *
                                  *privileges_required * *user_interaction;
    const double combined = scope_changed ? kScopeChangedCoefficient * (impact + exploitability)
                                          : impact + exploitability;
    base_score = roundup(std::min(combined, kMaxScore));
  }

  CvssScore result;
  result.score = base_score;
  result.rating = rating_for_score(base_score);
  result.has_score = true;
  return result;
}

}  // namespace bomwerk::core
