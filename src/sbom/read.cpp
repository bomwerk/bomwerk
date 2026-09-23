#include "sbom/read.hpp"

#include <cstddef>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>
#include <vector>

#include "core/file_index.hpp"
#include "core/file_io.hpp"
#include "core/git_dir.hpp"
#include "core/json_utils.hpp"
#include "core/model.hpp"
#include "core/text.hpp"
#include "core/warning.hpp"
#include "core/warning_code.hpp"
#include "sbom/format.hpp"

namespace bomwerk::sbom
{
namespace
{

/// `node[key]` as a string, or "" when absent, non-object, or not a string :
/// every field this reader looks at is optional in the CycloneDX schema, so
/// "not present" and "wrong type" are the same non-fatal outcome here.
std::string string_field(const nlohmann::json& node, const char* key)
{
  if (!node.is_object())
  {
    return {};
  }
  const auto entry = node.find(key);
  if (entry == node.end() || !entry->is_string())
  {
    return {};
  }
  return entry->get<std::string>();
}

constexpr std::size_t kSha256HexLength = 64;

/// `evidence.occurrences[0].location` -> `Component::root`, the inverse
/// of what `output::write_cyclonedx` emits for a component that carries one.
///
/// An SBOM handed to `bomwerk trim` is untrusted input: it may have come from
/// another tool, another vendor, or an attacker who can drop a file into a
/// watched folder. `root` is later JOINED against a scanned directory, so a
/// location of `/etc` or `../../..` would walk the mapping straight out of the
/// tree. `core::is_contained_relative_path` is the same guard `bomwerk.toml`
/// paths and submodule working-tree paths already go through; a location that
/// fails it is dropped WITH A WARNING rather than silently, because a
/// component whose root vanished will be reported unused and the operator
/// needs to know why. Every level is checked independently: anything that is
/// not object/array/object/string is simply absent, never an error (rule 1).
std::filesystem::path occurrence_root(const nlohmann::json& component_json,
                                      std::vector<core::Warning>& warnings)
{
  const auto evidence_entry = component_json.find("evidence");
  if (evidence_entry == component_json.end() || !evidence_entry->is_object())
  {
    return {};
  }
  const auto occurrences_entry = evidence_entry->find("occurrences");
  if (occurrences_entry == evidence_entry->end() || !occurrences_entry->is_array() ||
      occurrences_entry->empty())
  {
    return {};
  }
  const std::string location = string_field((*occurrences_entry)[0], "location");
  if (location.empty())
  {
    return {};
  }
  // Normalized through the same function that keys every later comparison, so
  // `Component::root` is canonical the moment it exists: a location spelled
  // "third_party/zlib/" must not become a root that fails to match the
  // "third_party/zlib" the mapping looks up.
  const std::filesystem::path root = core::normalized_subtree_path(location);
  if (!core::is_contained_relative_path(root))
  {
    // TODO: no WarningCode names "one component's evidence
    // location escaped the repo" specifically; kSbomComponentEntrySkipped is
    // the closest existing sbom-reader cause even though the entry itself is
    // still read (only its root is dropped).
    warnings.push_back(
        core::Warning{core::WarningCode::kSbomComponentEntrySkipped,
                      "component evidence location \"" + location +
                          "\" is not a relative path inside the repo (no absolute, no \"..\"), "
                          "ignored; this component cannot be matched against a build trace",
                      {},
                      {}});
    return {};
  }
  return root;
}

/// One `components[i]` entry -> `core::Component`. A field the document omits
/// stays default-constructed (empty string / `Scope::Required`), mirroring
/// exactly what `output::write_cyclonedx`'s `component_to_json` omits and why
///: this function is that one's inverse. `warnings` collects anything about
/// THIS entry the caller should surface: an unrecognized `scope`, or an
/// evidence location that escapes the repo (see `occurrence_root`); pass
/// `result.warnings` directly, it is just a `std::vector<core::Warning>&`.
core::Component component_from_json(const nlohmann::json& component_json,
                                    std::vector<core::Warning>& warnings)
{
  core::Component component;
  component.name = string_field(component_json, "name");
  component.version = string_field(component_json, "version");
  component.purl = string_field(component_json, "purl");
  component.cpe = string_field(component_json, "cpe");

  // --all-cpes: recognize ONLY the exact name/value pair output::write_cyclonedx
  // emits for a recognized provenance (core/model.hpp's kCpeProvenancePropertyName
  // / to_string(CpeProvenance)): a typo'd, hand-edited, or future-spec value is
  // silently ignored rather than guessed at, leaving the component at
  // Unspecified, the same forward-compatibility posture the scope reader above
  // already takes for an unrecognized value.
  const auto properties_entry = component_json.find("properties");
  if (properties_entry != component_json.end() && properties_entry->is_array())
  {
    for (const nlohmann::json& property_entry : *properties_entry)
    {
      if (string_field(property_entry, "name") == core::kCpeProvenancePropertyName &&
          string_field(property_entry, "value") ==
              core::to_string(core::CpeProvenance::SynthesizedWildcardVendor))
      {
        component.cpe_provenance = core::CpeProvenance::SynthesizedWildcardVendor;
        break;
      }
    }
  }

  const auto supplier_entry = component_json.find("supplier");
  if (supplier_entry != component_json.end())
  {
    component.supplier = string_field(*supplier_entry, "name");
  }

  const auto hashes_entry = component_json.find("hashes");
  if (hashes_entry != component_json.end() && hashes_entry->is_array())
  {
    for (const nlohmann::json& hash_entry : *hashes_entry)
    {
      if (string_field(hash_entry, "alg") == "SHA-256")
      {
        // Mirrors output::write_cyclonedx's own is_valid_sha256 gate: an
        // invalid digest (wrong length, non-hex: a hand-edited or hostile
        // document) is dropped silently rather than stored, the same
        // posture the writer takes when it declines to EMIT one, so a
        // malformed hash can never reach a component field pretending to be
        // a real SHA-256.
        const std::string candidate_sha256 = string_field(hash_entry, "content");
        if (candidate_sha256.size() == kSha256HexLength && core::is_hex_digits(candidate_sha256))
        {
          component.sha256 = candidate_sha256;
        }
        break;
      }
    }
  }

  const auto licenses_entry = component_json.find("licenses");
  if (licenses_entry != component_json.end() && licenses_entry->is_array() &&
      !licenses_entry->empty())
  {
    // `licenses[0].license.name`: one level deeper than the fields above,
    // matching write_cyclonedx's `license_entry["license"]["name"]` shape.
    const nlohmann::json& first_license = (*licenses_entry)[0];
    const auto license_object = first_license.find("license");
    if (license_object != first_license.end())
    {
      component.license = string_field(*license_object, "name");
    }
  }

  const std::string scope_text = string_field(component_json, "scope");
  if (scope_text == "optional")
  {
    component.scope = core::Scope::Optional;
  }
  else if (scope_text == "excluded")
  {
    component.scope = core::Scope::Excluded;
  }
  else if (!scope_text.empty())
  {
    // An unrecognized, non-empty scope (a typo, a future spec value bomwerk
    // does not know yet) stays Required: the least restrictive value: but
    // SAYS SO: silently downgrading "excluded" to "required" on a typo would
    // be exactly the kind of quiet misclassification rule 1's spirit forbids.
    // TODO: no WarningCode names "an unrecognized scope value
    // was downgraded to required"; kSbomComponentEntrySkipped is the closest
    // existing sbom-reader cause even though this entry is still fully read.
    warnings.push_back(
        core::Warning{core::WarningCode::kSbomComponentEntrySkipped,
                      "component \"" + (component.purl.empty() ? component.name : component.purl) +
                          "\" has unrecognized scope \"" + scope_text + "\", treated as required",
                      {},
                      {}});
  }
  // Absent: Scope::Required, the default constructed value.

  component.root = occurrence_root(component_json, warnings);

  // A component read back off a finished SBOM carries none of its scan-time
  // evidence: those facts were never written to the document in the first
  // place: so "this purl is in the SBOM that was read" is recorded as the
  // evidence in its own right, at High confidence: the document is the
  // product's own declared bill of materials, not a heuristic guess.
  component.evidence.push_back(
      core::Evidence{core::Source::Manifest, "SBOM input", core::Confidence::High});
  return component;
}

}  // namespace

core::Result<SbomDocument> read_cyclonedx(std::string_view bytes)
{
  core::Result<SbomDocument> result;
  const std::string_view without_bom = core::json_utils::without_utf8_bom(bytes);

  if (core::json_utils::exceeds_json_nesting_depth(without_bom,
                                                   core::json_utils::kMaxJsonNestingDepth))
  {
    result.warn(core::WarningCode::kJsonNestingDepthExceeded,
                "SBOM document nested too deeply, not read");
    return result;
  }

  const nlohmann::json document =
      nlohmann::json::parse(without_bom, nullptr, /*allow_exceptions=*/false);
  if (document.is_discarded() || !document.is_object())
  {
    result.warn(core::WarningCode::kInvalidJson, "SBOM document is not valid JSON, not read");
    return result;
  }

  result.value.serial_number = string_field(document, "serialNumber");
  const auto metadata_entry = document.find("metadata");
  if (metadata_entry != document.end() && metadata_entry->is_object())
  {
    result.value.generated_timestamp = string_field(*metadata_entry, "timestamp");
    const auto component_entry = metadata_entry->find("component");
    if (component_entry != metadata_entry->end())
    {
      result.value.product_id = string_field(*component_entry, "name");
      result.value.product_version = string_field(*component_entry, "version");
    }

    const auto manufacturer_entry = metadata_entry->find("manufacturer");
    if (manufacturer_entry != metadata_entry->end() && manufacturer_entry->is_object())
    {
      result.value.manufacturer_name = string_field(*manufacturer_entry, "name");
      const auto contacts_entry = manufacturer_entry->find("contact");
      if (contacts_entry != manufacturer_entry->end() && contacts_entry->is_array())
      {
        for (const nlohmann::json& contact_entry : *contacts_entry)
        {
          const std::string email = string_field(contact_entry, "email");
          if (!email.empty())
          {
            result.value.manufacturer_email = email;
            break;
          }
        }
      }
    }
  }

  const auto components_entry = document.find("components");
  if (components_entry == document.end() || !components_entry->is_array())
  {
    result.warn(core::WarningCode::kSbomDocumentInvalid, "SBOM document has no components array");
    return result;
  }

  std::vector<core::Component> components;
  components.reserve(components_entry->size());
  std::size_t skipped_non_object_entries = 0;
  for (const nlohmann::json& component_json : *components_entry)
  {
    if (!component_json.is_object())
    {
      ++skipped_non_object_entries;
      continue;
    }
    components.push_back(component_from_json(component_json, result.warnings));
  }
  if (skipped_non_object_entries > 0)
  {
    result.warn(core::WarningCode::kSbomComponentEntrySkipped,
                std::to_string(skipped_non_object_entries) + " component entr" +
                    (skipped_non_object_entries == 1 ? std::string("y") : std::string("ies")) +
                    " skipped (not a JSON object)");
  }

  result.value.components = core::merge_all(std::move(components));
  return result;
}

core::Result<SbomDocument> load_sbom_file(const std::filesystem::path& path)
{
  core::Result<SbomDocument> result;
  const core::BoundedFileRead file_read = core::read_file_bounded(path, kMaxSbomFileBytes);
  if (!file_read.readable)
  {
    result.warn(core::WarningCode::kUnreadableFile, "cannot read SBOM file " + path.string());
    return result;
  }

  const SbomInputFormat format = detect_sbom_format(file_read.bytes);
  if (format == SbomInputFormat::Spdx)
  {
    result.warn(core::WarningCode::kSbomWrongFormat,
                path.string() + " is an SPDX document; this reader takes CycloneDX only");
    return result;
  }
  if (format == SbomInputFormat::Unknown)
  {
    result.warn(core::WarningCode::kSbomWrongFormat,
                path.string() + " is not a recognized SBOM format, skipped");
    return result;
  }

  // Assigned after the format check above so a truncation warning below is
  // never discarded by this overwrite (it happens only on the path that
  // reaches here).
  result = read_cyclonedx(file_read.bytes);
  if (file_read.truncated)
  {
    result.warn(core::WarningCode::kFileSizeLimitExceeded,
                "SBOM file " + path.string() + " exceeds " + std::to_string(kMaxSbomFileBytes) +
                    " bytes; only the first part was read");
  }
  return result;
}

}  // namespace bomwerk::sbom
