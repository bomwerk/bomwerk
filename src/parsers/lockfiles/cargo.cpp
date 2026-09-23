#include "parsers/lockfiles/cargo.hpp"

#include <toml++/toml.h>

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/exclusions.hpp"
#include "core/file_io.hpp"
#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/submodule_paths.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::lockfiles::cargo
{
namespace
{

constexpr std::string_view kCargoLockName = "Cargo.lock";

/// A registry `checksum` is the sha256 of the packaged `.crate` archive:
/// exactly this many hex characters, nothing else.
constexpr std::size_t kSha256HexLength = 64;

/// Build the `pkg:cargo` purl. Crate names have no namespace; their case is
/// preserved (crates.io treats names case-insensitively but the lockfile
/// spelling is the identity cargo itself recorded).
std::string build_cargo_purl(const std::string& crate_name, const std::string& version)
{
  return "pkg:cargo/" + core::percent_encode(crate_name) + "@" + core::percent_encode(version);
}

/// Canonicalize `component.purl` in place, warning when the produced purl is
/// somehow invalid (defensive: percent-encoding should make that impossible).
void canonicalize_purl(core::Component& component,
                       core::Result<std::vector<core::Component>>& result)
{
  const core::Result<core::Purl> parsed_purl = core::Purl::parse(component.purl);
  if (!parsed_purl.complete)
  {
    result.warn(core::WarningCode::kPurlValidationFailed,
                "cargo: produced purl failed validation: " + component.purl, "cargo");
  }
  else
  {
    component.purl = parsed_purl.value.canonical();
  }
}

/// Parse the TOML shell of a Cargo.lock. vcpkg's tomlplusplus port ships a
/// precompiled, exceptions-enabled library (see CMakeLists.txt), so
/// `toml::parse` here throws `toml::parse_error` on malformed input rather
/// than returning a `parse_result`: the throw is caught immediately, right
/// here, and never escapes this function, so hostile TOML still degrades to a
/// warning rather than crashing or propagating across the producer's boundary
/// (Hard Rule 1's actual requirement). toml++ bounds its own nesting depth
/// internally, so no separate pre-scan is needed.
std::optional<toml::table> parse_toml_or_warn(std::string_view bytes, const std::string& label,
                                              core::Result<std::vector<core::Component>>& result)
{
  try
  {
    return toml::parse(bytes, std::string_view{label});
  }
  catch (const toml::parse_error&)
  {
    result.warn(core::WarningCode::kInvalidToml, "cargo: " + label + ": not valid TOML, skipped",
                "cargo");
    return std::nullopt;
  }
}

/// Parse one Cargo.lock's `[[package]]` entries into components. `label` is
/// the root-relative path used in warnings and evidence details. Entries
/// without a `source` are workspace members (first-party) and skip silently.
void parse_cargo_lock(std::string_view bytes, const std::string& label, std::size_t package_limit,
                      std::size_t& package_budget, std::vector<core::Component>& components,
                      core::Result<std::vector<core::Component>>& result)
{
  const std::optional<toml::table> parsed = parse_toml_or_warn(bytes, label, result);
  if (!parsed.has_value())
  {
    return;
  }
  const toml::table& document = *parsed;
  const toml::array* packages = document["package"].as_array();
  if (packages == nullptr)
  {
    return;  // no [[package]]: an empty lock is a normal shape
  }

  std::size_t skipped_entry_count = 0;
  for (const toml::node& package_node : *packages)
  {
    const toml::table* package_table = package_node.as_table();
    if (package_table == nullptr)
    {
      ++skipped_entry_count;
      continue;
    }
    const std::optional<std::string> source = (*package_table)["source"].value<std::string>();
    if (!source.has_value() || source->empty())
    {
      continue;  // a workspace member: the product itself, not a dependency
    }
    const std::optional<std::string> name = (*package_table)["name"].value<std::string>();
    const std::optional<std::string> version = (*package_table)["version"].value<std::string>();
    if (!name.has_value() || name->empty() || !version.has_value() || version->empty())
    {
      ++skipped_entry_count;
      continue;
    }
    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "cargo: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "cargo");
      result.complete = false;
      break;
    }
    --package_budget;

    core::Component component;
    component.name = *name;
    component.version = core::trimmed(*version);
    component.purl = build_cargo_purl(component.name, component.version);

    std::string detail = label + " (source " + *source + ")";
    const std::optional<std::string> checksum = (*package_table)["checksum"].value<std::string>();
    if (checksum.has_value())
    {
      if (checksum->size() == kSha256HexLength && core::is_hex_digits(*checksum))
      {
        component.sha256 = core::to_lower_ascii(*checksum);
      }
      else
      {
        // Not a plausible sha256: honest evidence, never a fake hash field.
        detail += " (checksum " + *checksum + ")";
      }
    }
    // Lock entries are cargo's own resolver output -> High.
    component.evidence.push_back({core::Source::Manifest, detail, core::Confidence::High});

    canonicalize_purl(component, result);
    components.push_back(std::move(component));
  }
  if (skipped_entry_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "cargo: " + std::to_string(skipped_entry_count) +
                    " package entrie(s) without name/version skipped: " + label,
                "cargo");
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
    if (relative_path.filename().string() != kCargoLockName)
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      result.warn(core::WarningCode::kFileLimitReached,
                  "cargo: file limit reached; remaining Cargo.lock files skipped", "cargo");
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
      result.warn(core::WarningCode::kUnreadableFile, "cargo: unreadable file: " + label, "cargo");
      continue;
    }
    if (file_read.truncated)
    {
      // A truncated TOML document cannot parse; skipping beats guessing.
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "cargo: file exceeds size limit, skipped: " + label, "cargo");
      continue;
    }
    parse_cargo_lock(file_read.bytes, label, options.max_total_packages, package_budget, components,
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

}  // namespace bomwerk::parsers::lockfiles::cargo
