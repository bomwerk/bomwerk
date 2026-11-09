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
#include "core/manifest_walk.hpp"
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

constexpr std::string_view kProducerName = "cargo";
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

    core::canonicalize_purl(component.purl, kProducerName, result.warnings);
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

/// The one format this producer reads.
enum class ManifestKind
{
  kCargoLock,
};

/// Selects `Cargo.lock` files. A truncated TOML document cannot parse, so an
/// oversized one is skipped rather than guessed at.
std::optional<core::ManifestMatch<ManifestKind>> manifest_kind(const fs::path& relative_path)
{
  if (core::file_name_of(relative_path) != kCargoLockName)
  {
    return std::nullopt;
  }
  return core::ManifestMatch<ManifestKind>{ManifestKind::kCargoLock,
                                           core::OversizedFilePolicy::kSkip};
}

/// State shared by every Cargo.lock of one scan: one package budget for all.
struct ParseState
{
  std::vector<core::Component> components;
  std::size_t package_budget = 0;
};

core::ManifestWalkOptions walk_options_for(const ParseOptions& options)
{
  return core::make_walk_options(options, kProducerName, kCargoLockName);
}

/// An additional valid entry already proved exhaustion and warned once: stop
/// opening files after that proof, but not merely because an earlier file
/// ended exactly at the configured limit.
bool package_budget_exhausted(const ParseState& state,
                              const core::Result<std::vector<core::Component>>& result)
{
  return state.package_budget == 0 && !result.complete;
}

void parse_manifest(ManifestKind /*kind*/, const core::WalkedManifestFile& file,
                    const ParseOptions& options, ParseState& state,
                    core::Result<std::vector<core::Component>>& result)
{
  parse_cargo_lock(file.bytes, file.label, options.max_total_packages, state.package_budget,
                   state.components, result);
}

core::Result<std::vector<core::Component>> finish(ParseState state,
                                                  core::Result<std::vector<core::Component>> result)
{
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
  core::for_each_manifest_file(
      file_index, root, walk_options_for(options), result.warnings, manifest_kind,
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
  core::for_manifest_bytes(file_name, bytes, options.max_file_bytes, kProducerName, result.warnings,
                           manifest_kind, [&](ManifestKind kind, core::WalkedManifestFile&& file)
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

}  // namespace bomwerk::parsers::lockfiles::cargo
