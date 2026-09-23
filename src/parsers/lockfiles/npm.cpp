#include "parsers/lockfiles/npm.hpp"

#include <cstddef>
#include <filesystem>
#include <nlohmann/json.hpp>
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

namespace bomwerk::parsers::lockfiles::npm
{
namespace
{

using core::json_utils::exceeds_json_nesting_depth;
using core::json_utils::kMaxJsonNestingDepth;
using core::json_utils::without_utf8_bom;

constexpr std::string_view kPackageLockName = "package-lock.json";

/// The key prefix separating a package's install path from its name; the NAME
/// is everything after the LAST occurrence (nested installs:
/// `node_modules/a/node_modules/b` is package `b`).
constexpr std::string_view kNodeModulesSegment = "node_modules/";

/// npm 7 rewrote the lockfile around the `packages` map; version 1's nested
/// `dependencies` tree is a different format we deliberately do not parse.
constexpr int kMinSupportedLockfileVersion = 2;

/// Extract the package name from a `packages` map key. Empty result means the
/// key names the root project or a workspace path: not an installed package.
std::string package_name_from_key(std::string_view packages_key)
{
  const std::size_t last_prefix = packages_key.rfind(kNodeModulesSegment);
  if (last_prefix == std::string_view::npos)
  {
    return {};
  }
  return std::string(packages_key.substr(last_prefix + kNodeModulesSegment.size()));
}

/// An npm scope names a real registry-enforced organization/account
/// (npmjs.com), so it doubles as NTIA/CRA supplier evidence: an unscoped
/// package states no publisher at all in the lockfile, and stays empty
/// rather than guessing one.
std::string npm_supplier_from_package_name(const std::string& package_name)
{
  const std::size_t scope_separator = package_name.find('/');
  if (!package_name.empty() && package_name.front() == '@' && scope_separator != std::string::npos)
  {
    return package_name.substr(1, scope_separator - 1);
  }
  return {};
}

/// Build the `pkg:npm` purl. A scoped name `@scope/name` keeps the scope as
/// the purl namespace with the `@` percent-encoded (`pkg:npm/%40scope/name`).
std::string build_npm_purl(const std::string& package_name, const std::string& version)
{
  std::string purl = "pkg:npm/";
  const std::size_t slash = package_name.find('/');
  if (!package_name.empty() && package_name.front() == '@' && slash != std::string::npos)
  {
    purl += core::percent_encode(package_name.substr(0, slash));
    purl += "/";
    purl += core::percent_encode(package_name.substr(slash + 1));
  }
  else
  {
    purl += core::percent_encode(package_name);
  }
  purl += "@" + core::percent_encode(version);
  return purl;
}

/// Parse one package-lock.json's `packages` map into components. `label` is
/// the root-relative path used in warnings and evidence details.
void parse_package_lock(const std::string& bytes, const std::string& label,
                        std::size_t package_limit, std::size_t& package_budget,
                        std::vector<core::Component>& components,
                        core::Result<std::vector<core::Component>>& result)
{
  const std::string_view json_bytes = without_utf8_bom(bytes);
  if (exceeds_json_nesting_depth(json_bytes, kMaxJsonNestingDepth))
  {
    result.warn(core::WarningCode::kJsonNestingDepthExceeded,
                "npm: " + label + ": JSON nesting exceeds depth limit, skipped", "npm");
    return;
  }
  const nlohmann::json lockfile =
      nlohmann::json::parse(json_bytes, nullptr, /*allow_exceptions=*/false);
  if (lockfile.is_discarded() || !lockfile.is_object())
  {
    result.warn(core::WarningCode::kInvalidJson, "npm: " + label + ": not valid JSON, skipped",
                "npm");
    return;
  }

  const auto version_iterator = lockfile.find("lockfileVersion");
  const int lockfile_version =
      (version_iterator != lockfile.end() && version_iterator->is_number_integer())
          ? version_iterator->get<int>()
          : 0;
  if (lockfile_version < kMinSupportedLockfileVersion)
  {
    result.warn(
        core::WarningCode::kLockfileFormatUnsupported,
        "npm: " + label + ": lockfileVersion 1 unsupported, regenerate with npm 7+, skipped",
        "npm");
    return;
  }
  const auto packages_iterator = lockfile.find("packages");
  if (packages_iterator == lockfile.end() || !packages_iterator->is_object())
  {
    // Key present-but-wrong or absent on a v2/v3 file: real dependencies were
    // likely dropped: warn so the operator knows the SBOM may be incomplete.
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "npm: " + label + ": packages map missing or malformed, skipped", "npm");
    return;
  }

  std::size_t skipped_versionless_count = 0;
  for (const auto& [packages_key, entry] : packages_iterator->items())
  {
    if (packages_key.empty())
    {
      continue;  // the root project itself: the product, not a dependency
    }
    if (!entry.is_object())
    {
      ++skipped_versionless_count;
      continue;
    }
    if (entry.value("link", false))
    {
      ++skipped_versionless_count;  // workspace symlink: the target is first-party
      continue;
    }
    const auto entry_version_iterator = entry.find("version");
    if (entry_version_iterator == entry.end() || !entry_version_iterator->is_string())
    {
      ++skipped_versionless_count;
      continue;
    }
    const std::string package_name = package_name_from_key(packages_key);
    if (package_name.empty())
    {
      ++skipped_versionless_count;  // workspace path outside node_modules: first-party
      continue;
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "npm: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "npm");
      result.complete = false;
      break;
    }
    --package_budget;

    core::Component component;
    component.name = package_name;
    component.version = core::trimmed(entry_version_iterator->get<std::string>());
    component.purl = build_npm_purl(component.name, component.version);
    component.supplier = npm_supplier_from_package_name(component.name);
    if (entry.value("dev", false))
    {
      component.scope = core::Scope::Excluded;  // the lockfile itself says dev-only
    }
    const auto license_iterator = entry.find("license");
    if (license_iterator != entry.end() && license_iterator->is_string())
    {
      component.license = core::trimmed(license_iterator->get<std::string>());
    }

    // `integrity` is usually sha512: evidence, never Component::sha256.
    std::string detail = label;
    const auto integrity_iterator = entry.find("integrity");
    if (integrity_iterator != entry.end() && integrity_iterator->is_string())
    {
      detail += " (integrity " + integrity_iterator->get<std::string>() + ")";
    }
    component.evidence.push_back({core::Source::Manifest, detail, core::Confidence::High});

    const core::Result<core::Purl> parsed_purl = core::Purl::parse(component.purl);
    if (!parsed_purl.complete)
    {
      result.warn(core::WarningCode::kPurlValidationFailed,
                  "npm: produced purl failed validation: " + component.purl, "npm");
    }
    else
    {
      component.purl = parsed_purl.value.canonical();
    }
    components.push_back(std::move(component));
  }

  if (skipped_versionless_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "npm: " + std::to_string(skipped_versionless_count) +
                    " workspace/link entrie(s) without a resolved version skipped: " + label,
                "npm");
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

  for (const fs::path& relative_path : file_index.files)
  {
    if (relative_path.filename().string() != kPackageLockName)
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      result.warn(core::WarningCode::kFileLimitReached,
                  "npm: file limit reached; remaining package-lock.json files skipped", "npm");
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
      result.warn(core::WarningCode::kUnreadableFile, "npm: unreadable file: " + label, "npm");
      continue;
    }
    if (file_read.truncated)
    {
      // A truncated JSON lockfile cannot parse; skipping beats guessing.
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "npm: file exceeds size limit, skipped: " + label, "npm");
      continue;
    }
    parse_package_lock(file_read.bytes, label, options.max_total_packages, package_budget,
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

}  // namespace bomwerk::parsers::lockfiles::npm
