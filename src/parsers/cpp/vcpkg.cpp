#include "parsers/cpp/vcpkg.hpp"

#include <cstddef>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/exclusions.hpp"
#include "core/file_io.hpp"
#include "core/json_utils.hpp"
#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/submodule_paths.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::cpp::vcpkg
{
namespace
{

using core::json_utils::exceeds_json_nesting_depth;
using core::json_utils::kMaxJsonNestingDepth;
using core::json_utils::without_utf8_bom;

constexpr std::string_view kVcpkgManifestName = "vcpkg.json";
constexpr std::string_view kVcpkgPortsDirectoryName = "ports";

/// Version keys, in preference order: vcpkg accepts several version schemes,
/// and this order is used both for an `overrides` pin and for a
/// ports-registry port's own top-level version declaration (see
/// `is_vcpkg_port_definition`): the same four schemes apply identically in
/// both places.
constexpr std::string_view kVcpkgVersionKeys[] = {"version", "version-semver", "version-date",
                                                  "version-string"};

/// True when `relative_path` (root-relative, already lexically normal per
/// `core::FileIndex`) matches the vcpkg ports-registry shape exactly:
/// `ports/<port-name>/vcpkg.json`: three path components, anchored at the
/// scan root's own top-level `ports/` directory. A deeper nesting
/// (`ports/<name>/nested/vcpkg.json`) does not match: deliberately narrow so
/// an unrelated tree that happens to contain a `ports/` directory is never
/// mistaken for the vcpkg registry itself.
bool is_vcpkg_port_definition(const fs::path& relative_path)
{
  auto path_component = relative_path.begin();
  const auto path_end = relative_path.end();

  if (path_component == path_end || path_component->string() != kVcpkgPortsDirectoryName)
  {
    return false;
  }
  ++path_component;

  if (path_component == path_end || path_component->string().empty())
  {
    return false;
  }
  ++path_component;

  if (path_component == path_end || path_component->string() != kVcpkgManifestName)
  {
    return false;
  }
  ++path_component;

  return path_component == path_end;  // exactly 3 segments
}

/// Consume one unit of the shared cross-file dependency budget. Returns true
/// when the caller should proceed; false when the budget is already exhausted
/// (a warning has been emitted and the caller should stop parsing this file).
bool try_consume_requirement_budget(std::size_t& requirement_budget,
                                    core::Result<std::vector<core::Component>>& result)
{
  if (requirement_budget == 0)
  {
    result.warn(core::WarningCode::kEntryLimitReached,
                "vcpkg: dependency limit reached; remaining entries skipped", "vcpkg");
    return false;
  }
  --requirement_budget;
  return true;
}

/// Read the manifest's `overrides` array into a name -> exact-version map.
/// vcpkg's in-manifest "lock": an override forces a package to exactly that
/// version. A present-but-malformed shape warns once (real pins may be lost),
/// never fails the run (rule 1). First pin for a name wins.
std::unordered_map<std::string, std::string> parse_override_versions(
    const nlohmann::json& manifest, const std::string& label,
    core::Result<std::vector<core::Component>>& result)
{
  std::unordered_map<std::string, std::string> override_versions;
  const auto overrides_iterator = manifest.find("overrides");
  if (overrides_iterator == manifest.end())
  {
    return override_versions;
  }
  if (!overrides_iterator->is_array())
  {
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "vcpkg: " + label + ": overrides is not an array, ignored", "vcpkg");
    return override_versions;
  }

  bool malformed_reported = false;
  for (const nlohmann::json& entry : *overrides_iterator)
  {
    const auto name_iterator = entry.is_object() ? entry.find("name") : entry.end();
    if (name_iterator == entry.end() || !name_iterator->is_string())
    {
      if (!malformed_reported)
      {
        result.warn(core::WarningCode::kMalformedEntrySkipped,
                    "vcpkg: " + label + ": override entry could not be parsed, skipped", "vcpkg");
        malformed_reported = true;
      }
      continue;
    }
    const std::string trimmed_name = core::trimmed(name_iterator->get<std::string>());
    if (trimmed_name.empty())
    {
      if (!malformed_reported)
      {
        result.warn(core::WarningCode::kMalformedEntrySkipped,
                    "vcpkg: " + label + ": override entry has empty name, skipped", "vcpkg");
        malformed_reported = true;
      }
      continue;
    }
    std::string version;
    for (const std::string_view version_key : kVcpkgVersionKeys)
    {
      const auto version_iterator = entry.find(version_key);
      if (version_iterator != entry.end() && version_iterator->is_string())
      {
        version = version_iterator->get<std::string>();
        break;
      }
    }
    if (!version.empty())
    {
      override_versions.emplace(trimmed_name, core::trimmed(version));
    }
  }
  return override_versions;
}

/// Build a `pkg:vcpkg` component from an already-resolved name/version pair
/// and one evidence entry, canonicalizing the purl via `core::canonicalize_purl`.
/// Shared by dependency-entry and port-own-identity construction (see
/// `is_vcpkg_port_definition`) so this sequence exists exactly once. `license`
/// is the port's own declared SPDX expression (vcpkg.json's top-level
/// `"license"` key), empty for a dependency reference: only a port's own
/// manifest carries its own license, never a consumer's `dependencies` entry.
core::Component build_vcpkg_component(const std::string& name, const std::string& version,
                                      std::string evidence_detail, core::Confidence confidence,
                                      const std::string& license,
                                      core::Result<std::vector<core::Component>>& result)
{
  core::Component component;
  component.name = name;
  component.version = version;
  component.purl = "pkg:vcpkg/" + core::percent_encode(name);
  if (!version.empty())
  {
    component.purl += "@" + core::percent_encode(version);
  }
  component.license = license;
  component.evidence.push_back({core::Source::Manifest, std::move(evidence_detail), confidence});
  core::canonicalize_purl(component.purl, "vcpkg", result.warnings);
  return component;
}

/// Build one component from a single `dependencies` entry (bare string or
/// object). Returns nullopt (with a warning) when no usable name is
/// recoverable: an identity-less entry would only pollute the SBOM. Purl
/// validation is `build_vcpkg_component`'s job, via `core::canonicalize_purl`.
std::optional<core::Component> component_from_dependency(
    const nlohmann::json& dependency, const std::string& label,
    const std::unordered_map<std::string, std::string>& override_versions,
    core::Result<std::vector<core::Component>>& result)
{
  std::string name;
  std::string version_floor;    // "version>=": a constraint, not the resolved version
  std::string platform;         // build-condition, e.g. "windows & !x86": evidence only
  std::string features_joined;  // requested features, comma-joined: evidence only
  if (dependency.is_string())
  {
    name = dependency.get<std::string>();
  }
  else if (dependency.is_object())
  {
    const auto name_iterator = dependency.find("name");
    if (name_iterator != dependency.end() && name_iterator->is_string())
    {
      name = name_iterator->get<std::string>();
    }
    const auto floor_iterator = dependency.find("version>=");
    if (floor_iterator != dependency.end() && floor_iterator->is_string())
    {
      version_floor = core::trimmed(floor_iterator->get<std::string>());
    }
    const auto platform_iterator = dependency.find("platform");
    if (platform_iterator != dependency.end() && platform_iterator->is_string())
    {
      platform = core::trimmed(platform_iterator->get<std::string>());
    }
    // Only string features are surfaced; vcpkg's rarer feature-object form is
    // skipped rather than guessed at (evidence, not identity: safe to omit).
    const auto features_iterator = dependency.find("features");
    if (features_iterator != dependency.end() && features_iterator->is_array())
    {
      features_joined.reserve(features_iterator->size() * 20);
      for (const nlohmann::json& feature : *features_iterator)
      {
        if (!feature.is_string())
        {
          continue;
        }
        if (!features_joined.empty())
        {
          features_joined += ",";
        }
        features_joined += feature.get<std::string>();
      }
    }
  }
  else
  {
    result.warn(core::WarningCode::kDependencyMissingSource,
                "vcpkg: " + label + ": dependency entry is neither a string nor an object, skipped",
                "vcpkg");
    return std::nullopt;
  }

  name = core::trimmed(name);
  if (name.empty())
  {
    result.warn(core::WarningCode::kDependencyMissingSource,
                "vcpkg: " + label + ": dependency has no package name, skipped", "vcpkg");
    return std::nullopt;
  }

  // An exact override pin is vcpkg's lock -> High confidence and it defines the
  // identity version. Otherwise the identity purl carries no version (a
  // `version>=` floor is a constraint, not the resolved version) and confidence
  // stays Low; the floor is kept as evidence only.
  const auto override_iterator = override_versions.find(name);
  const bool pinned = override_iterator != override_versions.end();
  const std::string identity_version = pinned ? override_iterator->second : std::string{};
  const core::Confidence confidence = pinned ? core::Confidence::High : core::Confidence::Low;

  std::string detail = label;
  if (pinned)
  {
    detail += " override=" + identity_version;
  }
  else if (!version_floor.empty())
  {
    detail += " version>=" + version_floor;
  }
  if (!platform.empty())
  {
    detail += " platform=" + platform;
  }
  if (!features_joined.empty())
  {
    detail += " features=" + features_joined;
  }

  return build_vcpkg_component(name, identity_version, std::move(detail), confidence,
                               /*license=*/std::string{}, result);
}

/// Build the "own identity" component for a vcpkg ports-registry port
/// definition (a `ports/<name>/vcpkg.json` file; the caller has already
/// confirmed the path shape via `is_vcpkg_port_definition`). A port's own
/// top-level `name`/version fields ARE that package's identity: unlike a
/// consumer manifest, where they describe the scanned project itself and are
/// never one of its dependencies. Returns nullopt (with one warning) when
/// `name` is missing/non-string/empty after trim; the caller still parses
/// this file's `dependencies` array regardless of this function's result. A
/// usable name with no version key at all is a normal shape for a real port
/// and is not warned about: it yields a versionless purl, exactly like a
/// bare dependency reference does today.
std::optional<core::Component> component_from_port_identity(
    const nlohmann::json& manifest, const std::string& label,
    core::Result<std::vector<core::Component>>& result)
{
  const auto name_iterator = manifest.find("name");
  const std::string name = (name_iterator != manifest.end() && name_iterator->is_string())
                               ? core::trimmed(name_iterator->get<std::string>())
                               : std::string{};
  if (name.empty())
  {
    result.warn(core::WarningCode::kSelfIdentityUnresolvable,
                "vcpkg: " + label + ": port definition has no usable name, own identity skipped",
                "vcpkg");
    return std::nullopt;
  }

  std::string version;
  for (const std::string_view version_key : kVcpkgVersionKeys)
  {
    const auto version_iterator = manifest.find(version_key);
    if (version_iterator != manifest.end() && version_iterator->is_string())
    {
      version = core::trimmed(version_iterator->get<std::string>());
      break;
    }
  }

  // The port's own SPDX license expression, e.g. "MIT" or
  // "curl AND ISC AND BSD-3-Clause": present on nearly every real port and
  // otherwise absent from this SBOM entirely for vcpkg, since a dependency
  // reference (component_from_dependency) has no manifest of its own to read
  // one from. vcpkg.json may declare "license": null for "not SPDX-expressed
  // yet"; is_string() already excludes that shape without a separate check.
  std::string license;
  const auto license_iterator = manifest.find("license");
  if (license_iterator != manifest.end() && license_iterator->is_string())
  {
    license = core::trimmed(license_iterator->get<std::string>());
  }

  return build_vcpkg_component(name, version, label + " own-identity", core::Confidence::High,
                               license, result);
}

/// Parse one vcpkg.json manifest into components: its `dependencies` array,
/// plus: only when `is_port_definition` is set, i.e. the file's path matched
/// `ports/<name>/vcpkg.json`: its own name/version identity
/// (`component_from_port_identity`). Parsed in no-throw mode behind the depth
/// pre-scan; malformed JSON degrades to one warning (rule 1). `label` is the
/// root-relative path used in warnings and evidence details.
void parse_manifest(const std::string& bytes, const std::string& label, bool is_port_definition,
                    std::size_t& requirement_budget, std::vector<core::Component>& components,
                    core::Result<std::vector<core::Component>>& result)
{
  const std::string_view json_bytes = without_utf8_bom(bytes);
  if (exceeds_json_nesting_depth(json_bytes, kMaxJsonNestingDepth))
  {
    result.warn(core::WarningCode::kJsonNestingDepthExceeded,
                "vcpkg: " + label + ": JSON nesting exceeds depth limit, skipped", "vcpkg");
    return;
  }
  const nlohmann::json manifest =
      nlohmann::json::parse(json_bytes, nullptr, /*allow_exceptions=*/false);
  if (manifest.is_discarded() || !manifest.is_object())
  {
    result.warn(core::WarningCode::kInvalidJson, "vcpkg: " + label + ": not valid JSON, skipped",
                "vcpkg");
    return;
  }

  if (is_port_definition)
  {
    std::optional<core::Component> port_identity =
        component_from_port_identity(manifest, label, result);
    if (port_identity.has_value())
    {
      components.push_back(std::move(*port_identity));
    }
  }

  const auto dependencies_iterator = manifest.find("dependencies");
  if (dependencies_iterator == manifest.end())
  {
    return;  // no `dependencies` key: a normal, well-formed manifest shape
             // (own identity, if any, was already pushed above)
  }
  if (!dependencies_iterator->is_array())
  {
    // Key present but the wrong shape: real dependencies were likely dropped
    // silently: warn so the operator knows the SBOM may be incomplete.
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "vcpkg: " + label + ": dependencies is not an array, skipped", "vcpkg");
    return;
  }

  const std::unordered_map<std::string, std::string> override_versions =
      parse_override_versions(manifest, label, result);

  for (const nlohmann::json& dependency : *dependencies_iterator)
  {
    if (!try_consume_requirement_budget(requirement_budget, result))
    {
      return;
    }
    std::optional<core::Component> component =
        component_from_dependency(dependency, label, override_versions, result);
    if (component.has_value())
    {
      components.push_back(std::move(*component));
    }
  }
}

}  // namespace

core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                 const fs::path& root, const ParseOptions& options)
{
  core::Result<std::vector<core::Component>> result;
  std::vector<core::Component> components;
  std::size_t scanned_file_count = 0;
  std::size_t requirement_budget = options.max_total_requirements;

  for (const fs::path& relative_path : file_index.files)
  {
    if (relative_path.filename().string() != kVcpkgManifestName)
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      result.warn(core::WarningCode::kFileLimitReached,
                  "vcpkg: file limit reached; remaining vcpkg.json files skipped", "vcpkg");
      break;
    }
    ++scanned_file_count;

    const std::string label = relative_path.generic_string();
    const bool is_port_definition = is_vcpkg_port_definition(relative_path);
    const core::BoundedFileRead file_read =
        core::read_file_bounded(root / relative_path, options.max_file_bytes);
    if (!file_read.readable)
    {
      result.warn(core::WarningCode::kUnreadableFile, "vcpkg: unreadable file: " + label, "vcpkg");
      continue;
    }
    if (file_read.truncated)
    {
      // A truncated JSON manifest cannot parse; skipping beats guessing.
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "vcpkg: file exceeds size limit, skipped: " + label, "vcpkg");
      continue;
    }
    parse_manifest(file_read.bytes, label, is_port_definition, requirement_budget, components,
                   result);
  }

  result.value = core::merge_all(std::move(components));
  return result;
}

core::Result<std::vector<core::Component>> parse(const fs::path& root, const ParseOptions& options)
{
  const core::Result<core::FileIndex> file_index =
      core::build_file_index(root, core::default_excluded_dir_names(),
                             core::with_submodule_subtrees(root, options.excluded_subtrees));
  core::Result<std::vector<core::Component>> result = parse(file_index.value, root, options);
  for (const core::Warning& warning : file_index.warnings)
  {
    result.warn(warning);
  }
  if (!file_index.complete)
  {
    result.complete = false;
  }
  return result;
}

core::Result<std::vector<core::Component>> parse(const fs::path& root)
{
  return parse(root, ParseOptions{});
}

}  // namespace bomwerk::parsers::cpp::vcpkg
