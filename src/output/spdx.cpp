#include "output/spdx.hpp"

#include <algorithm>
#include <cstddef>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/text.hpp"
#include "core/timestamp.hpp"
#include "core/uuid.hpp"
#include "output/spdx_license_ids.hpp"

namespace bomwerk::output
{
namespace
{

constexpr std::size_t kSha256HexLength = 64;
constexpr const char* kNoAssertion = "NOASSERTION";
constexpr const char* kDefaultDocumentName = "bomwerk-sbom";

// SPDX 2.3 (classic flat JSON).
constexpr const char* kSpdx23SpecVersion = "SPDX-2.3";
constexpr const char* kSpdx23DataLicense = "CC0-1.0";
constexpr const char* kSpdx23DocumentId = "SPDXRef-DOCUMENT";
constexpr const char* kSpdx23PackageIdPrefix = "SPDXRef-Package-";
constexpr const char* kSpdx23NamespacePrefix = "https://bomwerk.dev/spdx/2.3/";

// SPDX 3.0.1 (JSON-LD). The CreationInfo is a blank node every element points
// at; ids are absolute IRIs under bomwerk's own namespace. The agent/tool IRIs
// are fixed (identity, not version), so the version lives only in the tool
// name: the one field a golden snapshot templates out.
constexpr const char* kSpdx30SpecVersion = "3.0.1";
constexpr const char* kSpdx30Context = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld";
constexpr const char* kSpdx30CreationInfoId = "_:creationInfo";
constexpr const char* kSpdx30AgentIri = "https://bomwerk.dev/spdx/3.0.1/agent/bomwerk";
constexpr const char* kSpdx30ToolIri = "https://bomwerk.dev/spdx/3.0.1/tool/bomwerk";
constexpr const char* kSpdx30RelationshipIri =
    "https://bomwerk.dev/spdx/3.0.1/relationship/describes";
constexpr const char* kSpdx30PackageIriPrefix = "https://bomwerk.dev/spdx/3.0.1/package/";
constexpr const char* kSpdx30DocumentIriPrefix = "https://bomwerk.dev/spdx/3.0.1/document/";

/// True when `sha256` is a well-formed SHA-256 hex digest. Anything else
/// (empty, truncated, non-hex evidence) would fail the SPDX hash-value schema
/// pattern, so it is left out rather than emitted invalid: same guard the
/// CycloneDX writer applies.
bool is_valid_sha256(const std::string& sha256)
{
  return sha256.size() == kSha256HexLength && core::is_hex_digits(sha256);
}

/// Components sorted by `core::component_identity`, so caller order can never
/// change the output (rule 3). Pointers, to avoid copying the model.
std::vector<const core::Component*> sorted_component_pointers(
    const std::vector<core::Component>& components)
{
  std::vector<const core::Component*> ordered;
  ordered.reserve(components.size());
  for (const core::Component& component : components)
  {
    ordered.push_back(&component);
  }
  std::sort(ordered.begin(), ordered.end(),
            [](const core::Component* left, const core::Component* right)
            { return core::component_identity(*left) < core::component_identity(*right); });
  return ordered;
}

/// The UUIDv5 (of the component's identity) shared with the CycloneDX writer's
/// `bom-ref`, so a component has one identifier across both formats.
std::string component_uuid(const core::Component& component)
{
  return core::uuidv5(core::purl_namespace(), core::component_identity(component)).to_string();
}

/// Deterministic per-document UUIDv5 from the sorted set of component
/// identities: the SPDX analogue of the CycloneDX `serialNumber`, so caller
/// ordering cannot change the document identifier.
std::string document_uuid(const std::vector<core::Component>& components)
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
  return core::uuidv5(core::purl_namespace(), joined).to_string();
}

std::string document_name_for(const core::ReleaseMeta& release_meta)
{
  return release_meta.product_id.empty() ? std::string(kDefaultDocumentName)
                                         : release_meta.product_id;
}

/// Distinct component license texts that are not a recognized SPDX License
/// List identifier (SPDX 2.3 only: see spdx.hpp for why 3.0.1 defers license
/// entirely), each mapped to a stable "LicenseRef-declared-N" id
/// assigned in sorted-text order rather than component order, so the mapping
/// never depends on caller-supplied component ordering (rule 3). Every
/// component carrying the same free-text license shares one entry.
std::map<std::string, std::string> license_ref_ids_for_unmatched_licenses(
    const std::vector<core::Component>& components)
{
  std::set<std::string> unmatched_texts;
  for (const core::Component& component : components)
  {
    if (!component.license.empty() && !canonical_spdx_license_id(component.license).has_value())
    {
      unmatched_texts.insert(component.license);
    }
  }

  std::map<std::string, std::string> ref_id_by_text;
  std::size_t ordinal = 1;
  for (const std::string& text : unmatched_texts)
  {
    ref_id_by_text[text] = "LicenseRef-declared-" + std::to_string(ordinal);
    ++ordinal;
  }
  return ref_id_by_text;
}

/// `licenseDeclared` value for one component: its canonical SPDX id when
/// recognized, NOASSERTION when empty, otherwise the LicenseRef- id
/// `license_ref_ids` assigned it. Never raw free text: this field holds an
/// SPDX Annex D license expression, not arbitrary text, so unrecognized text
/// must be wrapped rather than emitted as-is (still JSON-Schema-valid either
/// way, but only the wrapped form is a real license expression).
std::string license_declared_for(const core::Component& component,
                                 const std::map<std::string, std::string>& license_ref_ids)
{
  if (component.license.empty())
  {
    return kNoAssertion;
  }
  const std::optional<std::string_view> canonical = canonical_spdx_license_id(component.license);
  if (canonical.has_value())
  {
    return std::string(*canonical);
  }
  return license_ref_ids.at(component.license);
}

std::string write_spdx_2_3(const std::vector<core::Component>& components, const ToolInfo& tool,
                           const core::ReleaseMeta& release_meta)
{
  const std::map<std::string, std::string> license_ref_ids =
      license_ref_ids_for_unmatched_licenses(components);

  nlohmann::json document;
  document["spdxVersion"] = kSpdx23SpecVersion;
  document["dataLicense"] = kSpdx23DataLicense;
  document["SPDXID"] = kSpdx23DocumentId;
  document["name"] = document_name_for(release_meta);
  document["documentNamespace"] = std::string(kSpdx23NamespacePrefix) + document_uuid(components);

  nlohmann::json creation_info;
  creation_info["created"] = core::current_timestamp_iso8601();
  nlohmann::json creators = nlohmann::json::array();
  creators.push_back(std::string("Tool: ") + tool.name + "-" + tool.version);
  creators.push_back(std::string("Organization: ") + tool.name);
  creation_info["creators"] = std::move(creators);
  document["creationInfo"] = std::move(creation_info);

  nlohmann::json packages = nlohmann::json::array();
  nlohmann::json relationships = nlohmann::json::array();
  for (const core::Component* component : sorted_component_pointers(components))
  {
    const std::string package_id = std::string(kSpdx23PackageIdPrefix) + component_uuid(*component);

    nlohmann::json package;
    package["SPDXID"] = package_id;
    package["name"] = component->name;
    package["downloadLocation"] = kNoAssertion;
    package["filesAnalyzed"] = false;
    // We never *conclude* a license, only report what a manifest declared, so
    // `licenseConcluded` stays NOASSERTION and the observed text (when any)
    // goes to `licenseDeclared`: never claim more than the evidence supports.
    package["licenseConcluded"] = kNoAssertion;
    package["licenseDeclared"] = license_declared_for(*component, license_ref_ids);
    package["copyrightText"] = kNoAssertion;
    if (!component->version.empty())
    {
      package["versionInfo"] = component->version;
    }
    if (!component->supplier.empty())
    {
      package["supplier"] = std::string("Organization: ") + component->supplier;
    }
    if (is_valid_sha256(component->sha256))
    {
      nlohmann::json checksum;
      checksum["algorithm"] = "SHA256";
      checksum["checksumValue"] = component->sha256;
      package["checksums"] = nlohmann::json::array();
      package["checksums"].push_back(std::move(checksum));
    }
    nlohmann::json external_refs = nlohmann::json::array();
    if (!component->purl.empty())
    {
      nlohmann::json external_ref;
      external_ref["referenceCategory"] = "PACKAGE-MANAGER";
      external_ref["referenceType"] = "purl";
      external_ref["referenceLocator"] = component->purl;
      external_refs.push_back(std::move(external_ref));
    }
    if (!component->cpe.empty())
    {
      nlohmann::json external_ref;
      external_ref["referenceCategory"] = "SECURITY";
      external_ref["referenceType"] = "cpe23";
      external_ref["referenceLocator"] = component->cpe;
      external_refs.push_back(std::move(external_ref));
    }
    if (!external_refs.empty())
    {
      package["externalRefs"] = std::move(external_refs);
    }
    packages.push_back(std::move(package));

    nlohmann::json relationship;
    relationship["spdxElementId"] = kSpdx23DocumentId;
    relationship["relationshipType"] = "DESCRIBES";
    relationship["relatedSpdxElement"] = package_id;
    relationships.push_back(std::move(relationship));
  }
  document["packages"] = std::move(packages);
  document["relationships"] = std::move(relationships);

  // Omitted when empty: every component's license was either unset or a
  // recognized SPDX id, so there is nothing to extract.
  if (!license_ref_ids.empty())
  {
    nlohmann::json extracted_infos = nlohmann::json::array();
    // std::map already iterates key-sorted (by license text), so this array
    // is deterministic independent of component order (rule 3).
    for (const auto& [text, ref_id] : license_ref_ids)
    {
      nlohmann::json extracted_info;
      extracted_info["licenseId"] = ref_id;
      extracted_info["extractedText"] = text;
      extracted_infos.push_back(std::move(extracted_info));
    }
    document["hasExtractedLicensingInfos"] = std::move(extracted_infos);
  }

  return document.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
}

std::string write_spdx_3_0(const std::vector<core::Component>& components, const ToolInfo& tool,
                           const core::ReleaseMeta& release_meta)
{
  nlohmann::json graph = nlohmann::json::array();

  // The CreationInfo blank node every element references via "creationInfo".
  nlohmann::json creation_info;
  creation_info["@id"] = kSpdx30CreationInfoId;
  creation_info["type"] = "CreationInfo";
  creation_info["specVersion"] = kSpdx30SpecVersion;
  creation_info["created"] = core::current_timestamp_iso8601();
  creation_info["createdBy"] = nlohmann::json::array({kSpdx30AgentIri});
  creation_info["createdUsing"] = nlohmann::json::array({kSpdx30ToolIri});
  graph.push_back(std::move(creation_info));

  // Creating agent (createdBy, an Agent) and tool (createdUsing). The tool
  // name carries bomwerk's version: the fixed IRIs above do not, so the
  // identifiers stay stable across version bumps.
  nlohmann::json creator_agent;
  creator_agent["type"] = "Organization";
  creator_agent["spdxId"] = kSpdx30AgentIri;
  creator_agent["creationInfo"] = kSpdx30CreationInfoId;
  creator_agent["name"] = tool.name;
  graph.push_back(std::move(creator_agent));

  nlohmann::json creator_tool;
  creator_tool["type"] = "Tool";
  creator_tool["spdxId"] = kSpdx30ToolIri;
  creator_tool["creationInfo"] = kSpdx30CreationInfoId;
  creator_tool["name"] = tool.name + "-" + tool.version;
  graph.push_back(std::move(creator_tool));

  // Package IRIs feed the package elements, the document's element/rootElement
  // lists and the describes relationship, so derive them once, in sorted order.
  const std::vector<const core::Component*> ordered = sorted_component_pointers(components);
  std::vector<std::string> package_iris;
  package_iris.reserve(ordered.size());
  for (const core::Component* component : ordered)
  {
    package_iris.push_back(std::string(kSpdx30PackageIriPrefix) + component_uuid(*component));
  }

  const std::string document_iri =
      std::string(kSpdx30DocumentIriPrefix) + document_uuid(components);

  // SpdxDocument: `element` lists every contained element (creators, packages,
  // the relationship); `rootElement` is what the SBOM is about (the packages).
  nlohmann::json spdx_document;
  spdx_document["type"] = "SpdxDocument";
  spdx_document["spdxId"] = document_iri;
  spdx_document["creationInfo"] = kSpdx30CreationInfoId;
  spdx_document["name"] = document_name_for(release_meta);
  spdx_document["profileConformance"] = nlohmann::json::array({"core", "software"});
  nlohmann::json element_list = nlohmann::json::array();
  element_list.push_back(kSpdx30AgentIri);
  element_list.push_back(kSpdx30ToolIri);
  for (const std::string& package_iri : package_iris)
  {
    element_list.push_back(package_iri);
  }
  if (!package_iris.empty())
  {
    element_list.push_back(kSpdx30RelationshipIri);
  }
  spdx_document["element"] = std::move(element_list);
  spdx_document["rootElement"] = package_iris;
  graph.push_back(std::move(spdx_document));

  for (std::size_t index = 0; index < ordered.size(); ++index)
  {
    const core::Component& component = *ordered[index];
    nlohmann::json package;
    package["type"] = "software_Package";
    package["spdxId"] = package_iris[index];
    package["creationInfo"] = kSpdx30CreationInfoId;
    package["name"] = component.name;
    package["software_downloadLocation"] = kNoAssertion;
    if (!component.version.empty())
    {
      package["software_packageVersion"] = component.version;
    }
    if (!component.purl.empty())
    {
      package["software_packageUrl"] = component.purl;
    }
    if (!component.cpe.empty())
    {
      nlohmann::json external_identifier;
      external_identifier["type"] = "ExternalIdentifier";
      external_identifier["externalIdentifierType"] = "cpe23";
      external_identifier["identifier"] = component.cpe;
      package["externalIdentifier"] = nlohmann::json::array();
      package["externalIdentifier"].push_back(std::move(external_identifier));
    }
    if (is_valid_sha256(component.sha256))
    {
      nlohmann::json hash_entry;
      hash_entry["type"] = "Hash";
      hash_entry["algorithm"] = "sha256";
      hash_entry["hashValue"] = component.sha256;
      package["verifiedUsing"] = nlohmann::json::array();
      package["verifiedUsing"].push_back(std::move(hash_entry));
    }
    graph.push_back(std::move(package));
  }

  // The single describes edge (document -> all packages). Omitted for an empty
  // component set: a relationship with an empty `to` records no fact and some
  // validators reject it.
  if (!package_iris.empty())
  {
    nlohmann::json relationship;
    relationship["type"] = "Relationship";
    relationship["spdxId"] = kSpdx30RelationshipIri;
    relationship["creationInfo"] = kSpdx30CreationInfoId;
    relationship["from"] = document_iri;
    relationship["relationshipType"] = "describes";
    relationship["to"] = package_iris;
    graph.push_back(std::move(relationship));
  }

  nlohmann::json document;
  document["@context"] = kSpdx30Context;
  document["@graph"] = std::move(graph);
  return document.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
}

}  // namespace

std::string write_spdx(const std::vector<core::Component>& components, const ToolInfo& tool,
                       core::SpdxVersion spdx_version, const core::ReleaseMeta& release_meta)
{
  if (spdx_version == core::SpdxVersion::V2_3)
  {
    return write_spdx_2_3(components, tool, release_meta);
  }
  return write_spdx_3_0(components, tool, release_meta);
}

}  // namespace bomwerk::output
