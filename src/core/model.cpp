#include "core/model.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <utility>

#include "core/purl.hpp"

namespace bomwerk::core
{
namespace
{

int confidence_rank(Confidence confidence)
{
  return static_cast<int>(confidence);
}

int source_rank(Source source)
{
  return static_cast<int>(source);
}

bool evidence_order(const Evidence& left, const Evidence& right)
{
  if (left.source != right.source)
  {
    return source_rank(left.source) < source_rank(right.source);
  }
  if (left.detail != right.detail)
  {
    return left.detail < right.detail;
  }
  return confidence_rank(left.confidence) > confidence_rank(right.confidence);
}

bool has_same_evidence_identity(const Evidence& left, const Evidence& right)
{
  return left.source == right.source && left.detail == right.detail;
}

void normalize_evidence(std::vector<Evidence>& evidence)
{
  std::sort(evidence.begin(), evidence.end(), evidence_order);
  evidence.erase(std::unique(evidence.begin(), evidence.end(), has_same_evidence_identity),
                 evidence.end());
}

/// Restrictiveness rank for the scope merge: lower rank = less restrictive.
/// Taking the minimum is commutative, so merge order can never change the
/// outcome (rule 3: two runs must be byte-identical).
int scope_rank(Scope scope)
{
  switch (scope)
  {
    case Scope::Required:
      return 0;
    case Scope::Optional:
      return 1;
    case Scope::Excluded:
      return 2;
  }
  return 0;  // unreachable: all enumerators handled above
}

}  // namespace

std::string component_identity(const Component& component)
{
  if (!component.purl.empty())
  {
    auto parsed_purl = Purl::parse(component.purl);
    if (parsed_purl.complete)
    {
      return parsed_purl.value.canonical();
    }
    return component.purl;
  }
  return component.name + "@" + component.version;
}

void merge_into(Component& destination, const Component& source)
{
  if (destination.name.empty())
  {
    destination.name = source.name;
  }
  if (destination.version.empty())
  {
    destination.version = source.version;
  }
  if (destination.supplier.empty())
  {
    destination.supplier = source.supplier;
  }
  if (destination.license.empty())
  {
    destination.license = source.license;
  }
  if (destination.cpe.empty())
  {
    // Merged together, not independently: a provenance value describes THIS
    // cpe string, so whichever side's cpe wins must carry its own provenance
    // along, never the destination's leftover default.
    destination.cpe = source.cpe;
    destination.cpe_provenance = source.cpe_provenance;
  }
  if (destination.sha256.empty())
  {
    destination.sha256 = source.sha256;
  }
  if (destination.root.empty())
  {
    destination.root = source.root;
  }
  destination.used_in_build = destination.used_in_build || source.used_in_build;
  if (scope_rank(source.scope) < scope_rank(destination.scope))
  {
    destination.scope = source.scope;
  }
  destination.evidence.insert(destination.evidence.end(), source.evidence.begin(),
                              source.evidence.end());
  normalize_evidence(destination.evidence);
}

Confidence highest_confidence(const Component& component)
{
  Confidence highest = Confidence::Low;
  for (const Evidence& evidence : component.evidence)
  {
    if (confidence_rank(evidence.confidence) > confidence_rank(highest))
    {
      highest = evidence.confidence;
    }
  }
  return highest;
}

std::vector<Component> merge_all(std::vector<Component> components)
{
  std::map<std::string, Component> components_by_identity;  // ordered => deterministic (rule 3)
  for (Component& component : components)
  {
    std::string identity_key = component_identity(component);
    auto existing_entry = components_by_identity.find(identity_key);
    if (existing_entry == components_by_identity.end())
    {
      normalize_evidence(component.evidence);
      components_by_identity.emplace(std::move(identity_key), std::move(component));
    }
    else
    {
      merge_into(existing_entry->second, component);
    }
  }

  std::vector<Component> merged;
  merged.reserve(components_by_identity.size());
  for (auto& [identity_key, component] : components_by_identity)
  {
    merged.push_back(std::move(component));
  }
  return merged;
}

}  // namespace bomwerk::core
