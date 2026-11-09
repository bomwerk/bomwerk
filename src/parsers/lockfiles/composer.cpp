#include "parsers/lockfiles/composer.hpp"

#include <cstddef>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/exclusions.hpp"
#include "core/file_io.hpp"
#include "core/json_utils.hpp"
#include "core/manifest_names.hpp"
#include "core/manifest_walk.hpp"
#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/submodule_paths.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::lockfiles::composer
{
namespace
{

using core::json_utils::exceeds_json_nesting_depth;
using core::json_utils::kMaxJsonNestingDepth;

constexpr std::string_view kProducerName = "composer";
constexpr std::string_view kComposerLockName = "composer.lock";
constexpr std::string_view kComposerJsonName = "composer.json";

/// Build the `pkg:composer` purl: `vendor` is the namespace, the rest the
/// name, split on the first `/` of composer's `vendor/package` naming. An
/// empty `version` omits the `@` segment entirely rather than emitting a
/// trailing `@`: a composer.json requirement is a declared range, and a purl
/// carrying `^7.8` could never match an OSV/CPE record, while the version-less
/// purl still matches on name (same shape as nuget's and vcpkg's
/// version-less references).
std::string build_composer_purl(std::string_view vendor, std::string_view package_name,
                                const std::string& version)
{
  std::string purl =
      "pkg:composer/" + core::percent_encode(vendor) + "/" + core::percent_encode(package_name);
  if (!version.empty())
  {
    purl += "@" + core::percent_encode(version);
  }
  return purl;
}

/// Push one `pkg:composer` component: build the purl, attach one evidence
/// entry, canonicalize the purl, and append it. `version` is stored exactly
/// as composer.lock wrote it (its `v` prefix included): never normalized, and
/// empty for a composer.json requirement, whose declared range is not a
/// version. `confidence` is the caller's: High for a composer.lock entry
/// (composer's own resolver output), Medium for a composer.json one. Mirrors
/// maven.cpp's emit_maven_component.
void emit_composer_component(std::string_view vendor, std::string_view package_name,
                             const std::string& version, core::Scope scope,
                             core::Confidence confidence, std::string detail,
                             std::vector<core::Component>& components,
                             core::Result<std::vector<core::Component>>& result)
{
  core::Component component;
  component.name = std::string(vendor) + "/" + std::string(package_name);
  component.version = version;
  component.purl = build_composer_purl(vendor, package_name, version);
  // Composer's vendor segment IS the publisher namespace (Packagist
  // enforces one vendor per publisher account): NTIA/CRA supplier evidence
  // with no extra parsing, same reasoning as maven's groupId.
  component.supplier = std::string(vendor);
  component.scope = scope;
  component.evidence.push_back({core::Source::Manifest, std::move(detail), confidence});

  core::canonicalize_purl(component.purl, kProducerName, result.warnings);
  components.push_back(std::move(component));
}

/// Composer platform pseudo-requirements: the PHP runtime and its ABI
/// variants, PHP extensions, bundled C libraries, and composer's own plugin
/// and runtime APIs. They constrain the environment a project runs in, not
/// its dependency graph: none is a package on Packagist, so none can carry a
/// purl. composer.lock needs no such check (its `packages` array holds
/// resolved packages only, and platform requirements never reach it); a
/// composer.json `require` map lists them inline, so the fallback filters
/// them here and counts them.
bool is_platform_requirement(std::string_view requirement_name)
{
  // A platform name is never `vendor/package`. The slash test is what keeps
  // real vendors that merely start with a platform prefix (php-http/httplug,
  // php-di/php-di, php-open-source-saver/jwt-auth) from being dropped.
  if (requirement_name.find('/') != std::string_view::npos)
  {
    return false;
  }
  if (requirement_name == "php" || requirement_name == "hhvm")
  {
    return true;
  }
  // `composer-` covers composer-plugin-api and composer-runtime-api; `php-`
  // covers the ABI selectors (php-64bit, php-ipv6, php-zts, php-debug).
  return requirement_name.starts_with("php-") || requirement_name.starts_with("ext-") ||
         requirement_name.starts_with("lib-") || requirement_name.starts_with("composer-");
}

/// Decode one file's bytes into a JSON object, or return a null document
/// after warning (BOM stripped, nesting depth capped, never throws: rule 1).
/// Shared by the composer.lock and composer.json readers; a valid object is
/// never null, so `is_null()` is the failure signal.
nlohmann::json parse_json_object(const std::string& bytes, const std::string& label,
                                 core::Result<std::vector<core::Component>>& result)
{
  // The manifest walk already stripped any UTF-8 byte-order mark.
  const std::string_view json_bytes = bytes;
  if (exceeds_json_nesting_depth(json_bytes, kMaxJsonNestingDepth))
  {
    result.warn(core::WarningCode::kJsonNestingDepthExceeded,
                "composer: " + label + ": JSON nesting exceeds depth limit, skipped", "composer");
    return nullptr;
  }
  nlohmann::json document = nlohmann::json::parse(json_bytes, nullptr, /*allow_exceptions=*/false);
  if (document.is_discarded() || !document.is_object())
  {
    result.warn(core::WarningCode::kInvalidJson, "composer: " + label + ": not valid JSON, skipped",
                "composer");
    return nullptr;
  }
  return document;
}

/// Parse one `packages` / `packages-dev` array. `scope` is Excluded for the
/// dev array: the lockfile itself says dev-only, nothing is guessed.
void parse_package_array(const nlohmann::json& packages, core::Scope scope,
                         const std::string& label, std::size_t package_limit,
                         std::size_t& package_budget, std::size_t& skipped_entry_count,
                         bool& budget_exhausted, std::vector<core::Component>& components,
                         core::Result<std::vector<core::Component>>& result)
{
  for (const nlohmann::json& entry : packages)
  {
    if (!entry.is_object())
    {
      ++skipped_entry_count;
      continue;
    }
    const auto name_iterator = entry.find("name");
    const auto version_iterator = entry.find("version");
    if (name_iterator == entry.end() || !name_iterator->is_string() ||
        version_iterator == entry.end() || !version_iterator->is_string())
    {
      ++skipped_entry_count;
      continue;
    }
    const std::string full_name = core::trimmed(name_iterator->get<std::string>());
    const std::size_t slash = full_name.find('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 >= full_name.size())
    {
      ++skipped_entry_count;  // composer names are always vendor/package
      continue;
    }
    const std::string version = core::trimmed(version_iterator->get<std::string>());
    if (version.empty())
    {
      ++skipped_entry_count;
      continue;
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "composer: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "composer");
      result.complete = false;
      budget_exhausted = true;
      break;
    }
    --package_budget;

    std::optional<std::string> license;
    const auto license_iterator = entry.find("license");
    if (license_iterator != entry.end() && license_iterator->is_array() &&
        !license_iterator->empty() && license_iterator->front().is_string())
    {
      license = core::trimmed(license_iterator->front().get<std::string>());
    }

    // `dist.shasum` is sha1 (often empty): evidence, never Component::sha256.
    std::string detail = label;
    const auto dist_iterator = entry.find("dist");
    if (dist_iterator != entry.end() && dist_iterator->is_object())
    {
      const auto shasum_iterator = dist_iterator->find("shasum");
      if (shasum_iterator != dist_iterator->end() && shasum_iterator->is_string() &&
          !shasum_iterator->get<std::string>().empty())
      {
        detail += " (dist shasum " + shasum_iterator->get<std::string>() + ")";
      }
    }

    // Lock entries are composer's own resolver output -> High.
    emit_composer_component(std::string_view(full_name).substr(0, slash),
                            std::string_view(full_name).substr(slash + 1), version, scope,
                            core::Confidence::High, std::move(detail), components, result);
    if (license.has_value())
    {
      components.back().license = *license;
    }
  }
}

/// Parse one `require` / `require-dev` map. Unlike composer.lock's arrays of
/// resolved package objects, these are name -> constraint maps whose values
/// are declared ranges (`"^7.8"`), so every component lands version-less at
/// Medium confidence with the range preserved in the evidence detail.
/// `scope` is Excluded for the dev map: composer.json itself says dev-only,
/// nothing is guessed.
void parse_requirement_map(const nlohmann::json& requirements, core::Scope scope,
                           const std::string& label, std::size_t package_limit,
                           std::size_t& package_budget, std::size_t& skipped_entry_count,
                           std::size_t& skipped_platform_count, bool& budget_exhausted,
                           std::vector<core::Component>& components,
                           core::Result<std::vector<core::Component>>& result)
{
  for (const auto& requirement : requirements.items())
  {
    const std::string full_name = core::trimmed(requirement.key());
    if (is_platform_requirement(full_name))
    {
      ++skipped_platform_count;
      continue;
    }
    const std::size_t slash = full_name.find('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 >= full_name.size())
    {
      ++skipped_entry_count;  // composer names are always vendor/package
      continue;
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "composer: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "composer");
      result.complete = false;
      budget_exhausted = true;
      break;
    }
    --package_budget;

    // The constraint is evidence, never identity: it records what the project
    // asked for without claiming the resolved version is known.
    std::string detail = label;
    if (requirement.value().is_string())
    {
      const std::string range = core::trimmed(requirement.value().get<std::string>());
      if (!range.empty())
      {
        detail += " (requires " + range + ")";
      }
    }

    // A declaration, not a resolution -> Medium with no version, the same
    // tier maven.cpp gives a pom.xml dependency.
    emit_composer_component(std::string_view(full_name).substr(0, slash),
                            std::string_view(full_name).substr(slash + 1), std::string{}, scope,
                            core::Confidence::Medium, std::move(detail), components, result);
  }
}

/// Parse one composer.json's `require` and `require-dev` maps into components.
/// Only reached where no sibling composer.lock exists. `label` is the
/// root-relative path used in warnings and evidence details.
void parse_composer_json(const std::string& bytes, const std::string& label,
                         std::size_t package_limit, std::size_t& package_budget,
                         std::vector<core::Component>& components,
                         core::Result<std::vector<core::Component>>& result)
{
  const nlohmann::json manifest = parse_json_object(bytes, label, result);
  if (manifest.is_null())
  {
    return;
  }

  std::size_t skipped_entry_count = 0;
  std::size_t skipped_platform_count = 0;
  bool budget_exhausted = false;
  const auto require_iterator = manifest.find("require");
  const auto require_dev_iterator = manifest.find("require-dev");

  // Neither map present is normal, not degraded: a library can declare no
  // dependencies at all. Unlike composer.lock, that earns no warning.
  if (require_iterator != manifest.end())
  {
    if (require_iterator->is_object())
    {
      parse_requirement_map(*require_iterator, core::Scope::Required, label, package_limit,
                            package_budget, skipped_entry_count, skipped_platform_count,
                            budget_exhausted, components, result);
    }
    else
    {
      result.warn(core::WarningCode::kMalformedEntrySkipped,
                  "composer: " + label + ": require is not an object, skipped", "composer");
    }
  }
  if (!budget_exhausted && require_dev_iterator != manifest.end())
  {
    if (require_dev_iterator->is_object())
    {
      parse_requirement_map(*require_dev_iterator, core::Scope::Excluded, label, package_limit,
                            package_budget, skipped_entry_count, skipped_platform_count,
                            budget_exhausted, components, result);
    }
    else
    {
      result.warn(core::WarningCode::kMalformedEntrySkipped,
                  "composer: " + label + ": require-dev is not an object, skipped", "composer");
    }
  }

  if (skipped_platform_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "composer: " + std::to_string(skipped_platform_count) +
                    " platform requirement(s) (php/ext-*/lib-*) skipped: " + label,
                "composer");
  }
  if (skipped_entry_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "composer: " + std::to_string(skipped_entry_count) +
                    " requirement(s) not named vendor/package skipped: " + label,
                "composer");
  }
}

/// Parse one composer.lock's `packages` and `packages-dev` arrays into
/// components. `label` is the root-relative path used in warnings and
/// evidence details.
void parse_composer_lock(const std::string& bytes, const std::string& label,
                         std::size_t package_limit, std::size_t& package_budget,
                         std::vector<core::Component>& components,
                         core::Result<std::vector<core::Component>>& result)
{
  const nlohmann::json lockfile = parse_json_object(bytes, label, result);
  if (lockfile.is_null())
  {
    return;
  }

  std::size_t skipped_entry_count = 0;
  bool budget_exhausted = false;
  const auto packages_iterator = lockfile.find("packages");
  if (packages_iterator != lockfile.end() && packages_iterator->is_array())
  {
    parse_package_array(*packages_iterator, core::Scope::Required, label, package_limit,
                        package_budget, skipped_entry_count, budget_exhausted, components, result);
  }
  const auto dev_packages_iterator = lockfile.find("packages-dev");
  if (!budget_exhausted && dev_packages_iterator != lockfile.end() &&
      dev_packages_iterator->is_array())
  {
    parse_package_array(*dev_packages_iterator, core::Scope::Excluded, label, package_limit,
                        package_budget, skipped_entry_count, budget_exhausted, components, result);
  }
  if (packages_iterator == lockfile.end() && dev_packages_iterator == lockfile.end())
  {
    // Neither array present: real dependencies were likely dropped: warn so
    // the operator knows the SBOM may be incomplete.
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "composer: " + label + ": packages arrays missing, skipped", "composer");
    return;
  }

  if (skipped_entry_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "composer: " + std::to_string(skipped_entry_count) +
                    " package entrie(s) without vendor/name/version skipped: " + label,
                "composer");
  }
}

/// Drop a version-less composer.json component when the scan also holds a
/// versioned entry for the same `vendor/package`. The versioned one came from
/// a composer.lock somewhere in the tree, so it is strictly more informative:
/// a version-less purl beside it is a weaker duplicate of the same package, not
/// a second dependency, and would otherwise be listed twice (a monorepo whose
/// root lock resolves `symfony/console` while a nested lockless composer.json
/// also requires it).
///
/// Scope is the one thing a lock entry cannot stand in for. If every versioned
/// entry is dev-only (`Scope::Excluded`) and the version-less one is a runtime
/// requirement, dropping it would make the package look dev-only, so both stay.
void drop_versionless_shadowed_by_versioned(std::vector<core::Component>& components)
{
  std::set<std::string> versioned_names;           // any versioned entry
  std::set<std::string> versioned_required_names;  // ... that is not dev-only
  for (const core::Component& component : components)
  {
    if (component.version.empty())
    {
      continue;
    }
    versioned_names.insert(component.name);
    if (component.scope == core::Scope::Required)
    {
      versioned_required_names.insert(component.name);
    }
  }
  std::erase_if(components,
                [&](const core::Component& component)
                {
                  if (!component.version.empty())
                  {
                    return false;
                  }
                  if (versioned_required_names.contains(component.name))
                  {
                    return true;
                  }
                  return component.scope == core::Scope::Excluded &&
                         versioned_names.contains(component.name);
                });
}

/// The formats this producer reads.
enum class ManifestKind
{
  kComposerLock,
  kComposerJson,
};

/// The directories a composer.lock already covers. The lock is composer's own
/// resolver output, so where one sits beside a composer.json the lock is
/// authoritative and the manifest's declared ranges add nothing but a weaker
/// duplicate. Built from `file_index` alone: no stat() calls.
std::set<fs::path> directories_with_lock(const core::FileIndex& file_index)
{
  std::set<fs::path> directories;
  for (const fs::path& relative_path : file_index.files)
  {
    if (core::file_name_of(relative_path) == kComposerLockName)
    {
      directories.insert(relative_path.parent_path());
    }
  }
  return directories;
}

/// Selects composer.lock files, and composer.json files that neither sit
/// beside a lock (`locked_directories`) nor belong to an installed package
/// (vendor/acme/lib/composer.json is acme's declaration, not this project's).
/// Both skips are silent and come before the file budget is charged: neither
/// is a degraded read, just a file this producer has no reason to open. A
/// truncated JSON file cannot parse, so oversized ones are skipped.
std::optional<core::ManifestMatch<ManifestKind>> manifest_kind(
    const fs::path& relative_path, const std::set<fs::path>& locked_directories)
{
  const std::string_view file_name = core::file_name_of(relative_path);
  if (file_name == kComposerLockName)
  {
    return core::ManifestMatch<ManifestKind>{ManifestKind::kComposerLock,
                                             core::OversizedFilePolicy::kSkip};
  }
  if (file_name != kComposerJsonName || locked_directories.count(relative_path.parent_path()) > 0 ||
      core::is_inside_installed_dependencies(relative_path))
  {
    return std::nullopt;
  }
  return core::ManifestMatch<ManifestKind>{ManifestKind::kComposerJson,
                                           core::OversizedFilePolicy::kSkip};
}

/// State shared by every composer file of one scan: one package budget for all.
struct ParseState
{
  std::vector<core::Component> components;
  std::size_t package_budget = 0;
};

core::ManifestWalkOptions walk_options_for(const ParseOptions& options)
{
  return core::make_walk_options(options, kProducerName, "composer");
}

/// An additional valid entry already proved exhaustion and warned once: stop
/// opening files after that proof, but not merely because an earlier file
/// ended exactly at the configured limit.
bool package_budget_exhausted(const ParseState& state,
                              const core::Result<std::vector<core::Component>>& result)
{
  return state.package_budget == 0 && !result.complete;
}

void parse_manifest(ManifestKind kind, const core::WalkedManifestFile& file,
                    const ParseOptions& options, ParseState& state,
                    core::Result<std::vector<core::Component>>& result)
{
  switch (kind)
  {
    case ManifestKind::kComposerLock:
      parse_composer_lock(file.bytes, file.label, options.max_total_packages, state.package_budget,
                          state.components, result);
      return;
    case ManifestKind::kComposerJson:
      parse_composer_json(file.bytes, file.label, options.max_total_packages, state.package_budget,
                          state.components, result);
      return;
  }
}

core::Result<std::vector<core::Component>> finish(ParseState state,
                                                  core::Result<std::vector<core::Component>> result)
{
  // After every file is read, so a lock in one directory can shadow a
  // lockless manifest in another; before the merge, so the survivors still
  // dedupe and order by purl as before.
  drop_versionless_shadowed_by_versioned(state.components);
  result.value = core::merge_all(std::move(state.components));
  return result;
}

}  // namespace

core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                 const fs::path& root, const ParseOptions& options)
{
  core::Result<std::vector<core::Component>> result;
  ParseState state;
  state.package_budget = options.max_total_packages;
  const std::set<fs::path> locked_directories = directories_with_lock(file_index);
  core::for_each_manifest_file(
      file_index, root, walk_options_for(options), result.warnings,
      [&](const fs::path& path) { return manifest_kind(path, locked_directories); },
      [&] { return package_budget_exhausted(state, result); },
      [&](ManifestKind kind, core::WalkedManifestFile&& file)
      { parse_manifest(kind, file, options, state, result); });
  return finish(std::move(state), std::move(result));
}

core::Result<std::vector<core::Component>> parse_bytes(std::string_view file_name,
                                                       std::string_view bytes,
                                                       const ParseOptions& options)
{
  core::Result<std::vector<core::Component>> result;
  ParseState state;
  state.package_budget = options.max_total_packages;
  core::for_manifest_bytes(
      file_name, bytes, options.max_file_bytes, kProducerName, result.warnings,
      [](const fs::path& path) { return manifest_kind(path, {}); },
      [&](ManifestKind kind, core::WalkedManifestFile&& file)
      { parse_manifest(kind, file, options, state, result); });
  return finish(std::move(state), std::move(result));
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

}  // namespace bomwerk::parsers::lockfiles::composer
