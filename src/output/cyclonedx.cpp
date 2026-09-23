#include "output/cyclonedx.hpp"

#include <algorithm>
#include <cstddef>
#include <nlohmann/json.hpp>
#include <utility>

#include "core/match_coverage.hpp"
#include "core/percent.hpp"
#include "core/text.hpp"
#include "core/timestamp.hpp"
#include "core/uuid.hpp"

namespace bomwerk::output
{
namespace
{

constexpr const char* kBomFormat = "CycloneDX";
constexpr const char* kSpecVersion = "1.6";
constexpr int kBomVersion = 1;
constexpr std::size_t kSha256HexLength = 64;

/// True when `sha256` is a well-formed SHA-256 hex digest. Anything else
/// (empty, truncated, non-hex evidence) would fail the CycloneDX
/// hash-content schema pattern, so it is left out of `hashes` rather than
/// emitted invalid.
bool is_valid_sha256(const std::string& sha256)
{
  return sha256.size() == kSha256HexLength && core::is_hex_digits(sha256);
}

std::string bom_ref_for(const core::Component& component)
{
  return core::uuidv5(core::purl_namespace(), core::component_identity(component)).to_string();
}

/// `metadata.component`'s own bom-ref, so it can anchor a root
/// `dependencies[]` entry the same way every component already does. A
/// `"product:"` prefix keeps this identity in a namespace no purl-derived
/// `component_identity()` value can ever land in, so a product id can never
/// collide with a component's bom-ref.
std::string product_bom_ref_for(const core::ReleaseMeta& release_meta)
{
  return core::uuidv5(core::purl_namespace(),
                      "product:" + release_meta.product_id + "@" + release_meta.version)
      .to_string();
}

/// `coverage` is classified once by the caller (which also needs it to
/// accumulate the BOM-level summary) and threaded in here rather than
/// reclassified: the per-component and BOM-level coverage totals both derive from
/// one classification pass per component, not two.
nlohmann::json component_to_json(const core::Component& component, core::MatchCoverage coverage)
{
  nlohmann::json component_json;
  component_json["type"] = "library";
  component_json["bom-ref"] = bom_ref_for(component);
  component_json["name"] = component.name;
  if (!component.version.empty())
  {
    component_json["version"] = component.version;
  }
  if (!component.purl.empty())
  {
    component_json["purl"] = component.purl;
  }
  if (!component.cpe.empty())
  {
    component_json["cpe"] = component.cpe;
  }
  // Absent scope means "required" per the CycloneDX schema default, so the
  // field is emitted only when it carries information: this also keeps every
  // pre-scope golden snapshot byte-identical (rule 3).
  if (component.scope != core::Scope::Required)
  {
    component_json["scope"] = core::to_string(component.scope);
  }
  if (!component.supplier.empty())
  {
    component_json["supplier"]["name"] = component.supplier;
  }
  if (is_valid_sha256(component.sha256))
  {
    nlohmann::json hash_entry;
    hash_entry["alg"] = "SHA-256";
    hash_entry["content"] = component.sha256;
    component_json["hashes"] = nlohmann::json::array();
    component_json["hashes"].push_back(std::move(hash_entry));
  }
  if (!component.license.empty())
  {
    nlohmann::json license_entry;
    license_entry["license"]["name"] = component.license;
    component_json["licenses"] = nlohmann::json::array();
    component_json["licenses"].push_back(std::move(license_entry));
  }
  // Where the component lives in the scanned tree, in CycloneDX's own
  // field for it rather than a bomwerk property, so any spec-aware consumer
  // reads it. This is what lets `bomwerk trim` map a build trace onto an SBOM
  // it did not itself produce: without it a component read back off disk has
  // no root, and a compile trace has nothing to attribute compiles to.
  // Only submodule and vendored-code components carry a root, and a rootless
  // one gets no `evidence` key at all, so a plain scan's bytes are unchanged
  // for everything else: the same precedent `scope` and the coverage
  // property below already set. `generic_string` so a Windows build never
  // writes a backslash path into an SBOM (rule 3: one repo, one byte stream,
  // whatever the host).
  if (!component.root.empty())
  {
    nlohmann::json occurrence;
    occurrence["location"] = component.root.generic_string();
    component_json["evidence"]["occurrences"] = nlohmann::json::array();
    component_json["evidence"]["occurrences"].push_back(std::move(occurrence));
  }
  // Match coverage, the binary pass and --all-cpes all surface through `properties`, so they are
  // gathered into one array here and attached only if something landed in it
  //: a component with none of them gets no `properties` key at all, which is
  // what keeps every pre-existing golden snapshot byte-identical (rule 3),
  // the same precedent `scope` above already set. Order is fixed (coverage,
  // CPE provenance, then binary evidence) rather than incidental: nlohmann
  // sorts object KEYS, not array elements, so insertion order is the emitted
  // order and must be decided once.
  nlohmann::json properties = nlohmann::json::array();
  // A matched component gains nothing here. An unmatched one carries
  // WHY, in the CycloneDX Property Taxonomy's name-value shape, so a consumer
  // sees it without cross-referencing the coverage file.
  if (coverage != core::MatchCoverage::Matched)
  {
    nlohmann::json coverage_property;
    coverage_property["name"] = "bomwerk:match-coverage";
    coverage_property["value"] = core::to_string(coverage);
    properties.push_back(std::move(coverage_property));
  }
  // --all-cpes: a component's cpe carries no recognized provenance gets no
  // property at all: this is what keeps a plain scan's (and a pre-scope
  // synthesized CPE's) bytes unchanged, same precedent as coverage above.
  if (component.cpe_provenance != core::CpeProvenance::Unspecified)
  {
    nlohmann::json cpe_provenance_property;
    cpe_provenance_property["name"] = std::string(core::kCpeProvenancePropertyName);
    cpe_provenance_property["value"] = core::to_string(component.cpe_provenance);
    properties.push_back(std::move(cpe_provenance_property));
  }
  // What the SHIPPED BINARY says, as opposed to what a manifest declared.
  // A `DT_NEEDED` entry in a linked artifact is the only record of a shared
  // library the deliverable actually loads, and it is CRA evidence, so it has
  // to survive into the document rather than living only in binscan's own
  // sidecar. Every other evidence source is already visible through the
  // fields it produced (a manifest through name/version/purl, a location
  // through `evidence.occurrences`); Binary evidence has no such field of its
  // own in the spec, so it takes the same namespaced-property route match coverage does.
  // No producer run by `scan` emits Source::Binary, so this is inert for
  // every existing scan and every golden snapshot.
  for (const core::Evidence& evidence : component.evidence)
  {
    if (evidence.source != core::Source::Binary)
    {
      continue;
    }
    nlohmann::json binary_property;
    binary_property["name"] = "bomwerk:binary";
    binary_property["value"] = evidence.detail;
    properties.push_back(std::move(binary_property));
  }
  if (!properties.empty())
  {
    component_json["properties"] = std::move(properties);
  }
  return component_json;
}

/// Fold one component's already-computed classification into a running
/// summary: the same bucketing `core::summarize_match_coverage` does, but
/// incremental, so a caller that already classifies each component for
/// `component_to_json` doesn't also pay for `summarize_match_coverage`'s own
/// full second pass over `components`.
void accumulate_match_coverage(core::MatchCoverageSummary& summary, core::MatchCoverage coverage)
{
  ++summary.total;
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
}

/// `metadata.properties`: BOM-level match-coverage totals, always
/// present so a consumer can tell "matched" apart from "an older bomwerk that
/// never computed this". Values are decimal counts, not percentages: a
/// locale-sensitive fractional value has no place in bytes that must be
/// byte-identical across runs (rule 3); a percentage is a display concern for
/// the CLI/report/coverage-file only. Names are sorted (rule 3): the object
/// itself doesn't require it, but the array's own element order still must be
/// deterministic across runs, and alphabetical is the simplest guarantee.
nlohmann::json coverage_summary_properties(const core::MatchCoverageSummary& summary)
{
  const std::size_t unmatched_count = summary.total - summary.matchable;

  nlohmann::json properties = nlohmann::json::array();
  const std::pair<const char*, std::size_t> entries[] = {
      {"bomwerk:coverage:components", summary.total},
      {"bomwerk:coverage:matchable", summary.matchable},
      {"bomwerk:coverage:no-identifier", summary.no_identifier},
      {"bomwerk:coverage:unmapped-purl-type", summary.unmapped_purl_type},
      {"bomwerk:coverage:unmatched", unmatched_count},
      {"bomwerk:coverage:unversioned-purl", summary.unversioned_purl},
  };
  for (const auto& [name, count] : entries)
  {
    nlohmann::json property;
    property["name"] = name;
    property["value"] = std::to_string(count);
    properties.push_back(std::move(property));
  }
  return properties;
}

/// Deterministic per-document serial number: `uuidv5` of the sorted set of
/// component identities, so two runs over the same components: regardless
/// of caller-supplied order: produce the same serial number (rule 3). A
/// random UUID would break the byte-identical guarantee.
std::string serial_number_for(const std::vector<core::Component>& components)
{
  std::vector<std::string> identities;
  identities.reserve(components.size());
  for (const core::Component& component : components)
  {
    identities.push_back(core::component_identity(component));
  }
  std::sort(identities.begin(), identities.end());

  std::string joined;
  for (const std::string& identity : identities)
  {
    joined += identity;
    joined += '\n';
  }
  return "urn:uuid:" + core::uuidv5(core::purl_namespace(), joined).to_string();
}

}  // namespace

std::string write_cyclonedx(const std::vector<core::Component>& components, const ToolInfo& tool,
                            const core::ReleaseMeta& release_meta,
                            const core::CraMetadata& cra_metadata)
{
  nlohmann::json bom;
  bom["bomFormat"] = kBomFormat;
  bom["specVersion"] = kSpecVersion;
  bom["version"] = kBomVersion;
  bom["serialNumber"] = serial_number_for(components);

  nlohmann::json tool_entry;
  tool_entry["type"] = "application";
  tool_entry["name"] = tool.name;
  tool_entry["version"] = tool.version;
  nlohmann::json tool_components = nlohmann::json::array();
  tool_components.push_back(std::move(tool_entry));

  bom["metadata"]["timestamp"] = core::current_timestamp_iso8601();
  bom["metadata"]["tools"]["components"] = std::move(tool_components);

  std::string product_bom_ref;
  if (!release_meta.product_id.empty())
  {
    product_bom_ref = product_bom_ref_for(release_meta);
    nlohmann::json product_component;
    product_component["type"] = "application";
    product_component["bom-ref"] = product_bom_ref;
    product_component["name"] = release_meta.product_id;
    if (!release_meta.version.empty())
    {
      product_component["version"] = release_meta.version;
    }
    // `sbom-tools` (and by extension NTIA/CRA) checks `metadata.component`
    // against the exact same per-component identifier/supplier rules as every
    // dependency: it is not exempt for being the primary component. A synthetic
    // `pkg:generic` purl (the same fallback shape every producer already uses
    // for an otherwise-unidentifiable component) gives it a real identifier;
    // `cra_metadata.manufacturer_name`, when configured, doubles as its
    // supplier: omitted when unconfigured rather than inventing one.
    product_component["purl"] = "pkg:generic/" + core::percent_encode(release_meta.product_id) +
                                "@" + core::percent_encode(release_meta.version);
    if (!cra_metadata.manufacturer_name.empty())
    {
      product_component["supplier"]["name"] = cra_metadata.manufacturer_name;
    }
    bom["metadata"]["component"] = std::move(product_component);
  }

  // `metadata.manufacturer`: CycloneDX's own field for "who made this
  // product" (CRA Art. 13(16) manufacturer identification), sourced from
  // bomwerk.toml's [cra] table (core::CraMetadata) since no producer can
  // observe a manufacturer from source code. Omitted entirely when
  // unconfigured, same precedent as `component.scope`/`evidence` above.
  if (!cra_metadata.manufacturer_name.empty())
  {
    nlohmann::json manufacturer;
    manufacturer["name"] = cra_metadata.manufacturer_name;
    if (!cra_metadata.manufacturer_email.empty())
    {
      nlohmann::json contact;
      contact["email"] = cra_metadata.manufacturer_email;
      manufacturer["contact"] = nlohmann::json::array();
      manufacturer["contact"].push_back(std::move(contact));
    }
    bom["metadata"]["manufacturer"] = std::move(manufacturer);
  }

  std::vector<const core::Component*> components_by_identity;
  components_by_identity.reserve(components.size());
  for (const core::Component& component : components)
  {
    components_by_identity.push_back(&component);
  }
  std::sort(components_by_identity.begin(), components_by_identity.end(),
            [](const core::Component* left, const core::Component* right)
            { return core::component_identity(*left) < core::component_identity(*right); });

  // Each component is classified once here and the result is threaded
  // both into its own JSON and into the running BOM-level summary: one
  // classification pass over `components`, not two.
  nlohmann::json components_json = nlohmann::json::array();
  nlohmann::json dependencies_json = nlohmann::json::array();
  // The product's own dependsOn list, built alongside the per-component
  // loop below so it stays in the same deterministic identity order (rule 3)
  // rather than a second pass over `components_by_identity`. Only populated
  // when there is a product to root it at: see the `dependencies_json`
  // assembly below.
  nlohmann::json product_depends_on = nlohmann::json::array();
  core::MatchCoverageSummary coverage_summary;
  for (const core::Component* component : components_by_identity)
  {
    const core::MatchCoverage coverage = core::classify_match_coverage(*component);
    accumulate_match_coverage(coverage_summary, coverage);
    components_json.push_back(component_to_json(*component, coverage));

    const std::string component_bom_ref = bom_ref_for(*component);
    nlohmann::json dependency_entry;
    dependency_entry["ref"] = component_bom_ref;
    dependencies_json.push_back(std::move(dependency_entry));
    product_depends_on.push_back(component_bom_ref);
  }
  bom["components"] = std::move(components_json);
  // A root `dependencies[]` entry naming every component as a direct
  // dependency of the product (NTIA/CRA "dependency relationships": a real
  // graph edge, not just each component's own childless entry): emitted
  // only when `metadata.component` exists, since without a product there is
  // nothing to root the graph at. Prepended so the product's own entry reads
  // first, matching where `metadata.component` itself appears.
  if (!product_bom_ref.empty())
  {
    nlohmann::json product_dependency_entry;
    product_dependency_entry["ref"] = product_bom_ref;
    product_dependency_entry["dependsOn"] = std::move(product_depends_on);
    dependencies_json.insert(dependencies_json.begin(), std::move(product_dependency_entry));
  }
  bom["dependencies"] = std::move(dependencies_json);
  // Order-independent by construction (each component contributes to exactly
  // one bucket regardless of iteration order), so caller-supplied `components`
  // ordering cannot change these bytes (rule 3): same guarantee the old
  // separate `summarize_match_coverage(components)` pass gave.
  bom["metadata"]["properties"] = coverage_summary_properties(coverage_summary);

  return bom.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
}

}  // namespace bomwerk::output
