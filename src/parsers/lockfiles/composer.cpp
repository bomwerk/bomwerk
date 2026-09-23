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
using core::json_utils::without_utf8_bom;

constexpr std::string_view kComposerLockName = "composer.lock";

/// Build the `pkg:composer` purl: `vendor` is the namespace, the rest the
/// name, split on the first `/` of composer's `vendor/package` naming.
std::string build_composer_purl(std::string_view vendor, std::string_view package_name,
                                const std::string& version)
{
  return "pkg:composer/" + core::percent_encode(vendor) + "/" + core::percent_encode(package_name) +
         "@" + core::percent_encode(version);
}

/// Push one `pkg:composer` component: build the purl, attach one evidence
/// entry, canonicalize the purl, and append it. `version` is stored exactly
/// as composer.lock wrote it (its `v` prefix included): never normalized.
/// composer.lock is composer's own resolver output, so every entry here is
/// Confidence::High; mirrors maven.cpp's emit_maven_component.
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

  const core::Result<core::Purl> parsed_purl = core::Purl::parse(component.purl);
  if (!parsed_purl.complete)
  {
    result.warn(core::WarningCode::kPurlValidationFailed,
                "composer: produced purl failed validation: " + component.purl, "composer");
  }
  else
  {
    component.purl = parsed_purl.value.canonical();
  }
  components.push_back(std::move(component));
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

/// Parse one composer.lock's `packages` and `packages-dev` arrays into
/// components. `label` is the root-relative path used in warnings and
/// evidence details.
void parse_composer_lock(const std::string& bytes, const std::string& label,
                         std::size_t package_limit, std::size_t& package_budget,
                         std::vector<core::Component>& components,
                         core::Result<std::vector<core::Component>>& result)
{
  const std::string_view json_bytes = without_utf8_bom(bytes);
  if (exceeds_json_nesting_depth(json_bytes, kMaxJsonNestingDepth))
  {
    result.warn(core::WarningCode::kJsonNestingDepthExceeded,
                "composer: " + label + ": JSON nesting exceeds depth limit, skipped", "composer");
    return;
  }
  const nlohmann::json lockfile =
      nlohmann::json::parse(json_bytes, nullptr, /*allow_exceptions=*/false);
  if (lockfile.is_discarded() || !lockfile.is_object())
  {
    result.warn(core::WarningCode::kInvalidJson, "composer: " + label + ": not valid JSON, skipped",
                "composer");
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

}  // namespace

core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                 const fs::path& root, const ParseOptions& options)
{
  core::Result<std::vector<core::Component>> result;
  std::vector<core::Component> components;
  std::size_t scanned_file_count = 0;
  std::size_t package_budget = options.max_total_packages;

  // composer.json is deliberately never read here: a declared `require`
  // range is not a resolved version (see `core::ecosystem_manifests`, where
  // composer.json is a loose manifest, not a supported lock): the same
  // policy `parsers::lockfiles::go` already applies to a lockfile-less
  // go.mod. A project with composer.json but no composer.lock reports zero
  // composer components plus the generic "found composer.json ... with no
  // lockfile alongside" warning from `core::find_unparsed_manifests`, not a
  // synthetic non-identity version like "^2.0".
  for (const fs::path& relative_path : file_index.files)
  {
    if (relative_path.filename().string() != kComposerLockName)
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      result.warn(core::WarningCode::kFileLimitReached,
                  "composer: file limit reached; remaining composer files skipped", "composer");
      break;
    }
    if (package_budget == 0 && !result.complete)
    {
      // An additional valid entry already proved exhaustion and warned once;
      // stop opening files after that proof, but not merely because an earlier
      // file ended exactly at the configured limit.
      break;
    }
    ++scanned_file_count;

    const std::string label = relative_path.generic_string();
    const core::BoundedFileRead file_read =
        core::read_file_bounded(root / relative_path, options.max_file_bytes);
    if (!file_read.readable)
    {
      result.warn(core::WarningCode::kUnreadableFile, "composer: unreadable file: " + label,
                  "composer");
      continue;
    }
    if (file_read.truncated)
    {
      // A truncated JSON file cannot parse; skipping beats guessing.
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "composer: file exceeds size limit, skipped: " + label, "composer");
      continue;
    }

    parse_composer_lock(file_read.bytes, label, options.max_total_packages, package_budget,
                        components, result);
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

}  // namespace bomwerk::parsers::lockfiles::composer
