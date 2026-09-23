#include "parsers/lockfiles/pub.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/exclusions.hpp"
#include "core/manifest_walk.hpp"
#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/submodule_paths.hpp"
#include "core/warning_code.hpp"
#include "core/yaml_subset.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::lockfiles::pub
{
namespace
{

constexpr std::string_view kPubspecLockName = "pubspec.lock";
constexpr std::size_t kPackagesKeyIndentation = 0;
constexpr std::string_view kPackagesKey = "packages";
constexpr std::size_t kEntryKeyIndentation = 2;
constexpr std::size_t kEntryFieldIndentation = 4;
constexpr std::size_t kDescriptionFieldIndentation = 6;
constexpr std::string_view kDescriptionKey = "description";
constexpr std::string_view kSourceKey = "source";
constexpr std::string_view kVersionKey = "version";
constexpr std::string_view kDescriptionUrlField = "url";
constexpr std::string_view kDescriptionResolvedRefField = "resolved-ref";
constexpr std::string_view kSourceHosted = "hosted";
constexpr std::string_view kSourcePath = "path";
constexpr std::string_view kSourceGit = "git";
constexpr std::string_view kSourceSdk = "sdk";

/// Sources with no registry identity are either local workspace entries or
/// future formats that must never be guessed into a purl.
enum class PubSource
{
  Unknown,
  Hosted,
  Path,
  Git,
  Sdk
};

struct SkipCounts
{
  std::size_t git_or_sdk_missing_version = 0;
  std::size_t unknown_source = 0;
  std::size_t malformed = 0;
};

/// pub's entry fields arrive on separate indentation levels. This state is
/// closed at the next entry or top-level key.
struct PendingEntry
{
  std::string_view name;
  std::string_view version;
  PubSource source = PubSource::Unknown;
  std::string_view description_url;
  std::string_view description_resolved_ref;
  bool active = false;
  bool inside_description = false;
};

PubSource parse_pub_source(std::string_view source_value)
{
  if (source_value == kSourceHosted)
  {
    return PubSource::Hosted;
  }
  if (source_value == kSourcePath)
  {
    return PubSource::Path;
  }
  if (source_value == kSourceGit)
  {
    return PubSource::Git;
  }
  if (source_value == kSourceSdk)
  {
    return PubSource::Sdk;
  }
  return PubSource::Unknown;
}

std::string build_pub_purl(const std::string& name, const std::string& version)
{
  return "pkg:pub/" + core::percent_encode(name) + "@" + core::percent_encode(version);
}

std::string evidence_detail_for(const PendingEntry& entry, const std::string& label)
{
  std::string detail = label;
  if (entry.source == PubSource::Git)
  {
    detail += " (source git";
    if (!entry.description_url.empty())
    {
      detail += ", url " + std::string(entry.description_url);
    }
    if (!entry.description_resolved_ref.empty())
    {
      detail += ", resolved-ref " + std::string(entry.description_resolved_ref);
    }
    detail += ")";
  }
  else if (entry.source == PubSource::Sdk)
  {
    detail += " (source sdk)";
  }
  else
  {
    detail += " (source hosted)";
  }
  return detail;
}

void append_pub_component(const PendingEntry& entry, const std::string& label,
                          std::vector<core::Component>& components,
                          core::Result<std::vector<core::Component>>& result)
{
  core::Component component;
  component.name = std::string(entry.name);
  component.version = std::string(entry.version);
  component.purl = build_pub_purl(component.name, component.version);
  component.evidence.push_back(
      {core::Source::Manifest, evidence_detail_for(entry, label), core::Confidence::High});
  core::canonicalize_purl(component.purl, "pub", result.warnings);
  components.push_back(std::move(component));
}

void warn_skip_counts(const SkipCounts& skips, const std::string& label,
                      core::Result<std::vector<core::Component>>& result)
{
  if (skips.unknown_source > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "pub: " + std::to_string(skips.unknown_source) +
                    " entrie(s) with an unrecognized source skipped: " + label,
                "pub");
  }
  if (skips.git_or_sdk_missing_version > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "pub: " + std::to_string(skips.git_or_sdk_missing_version) +
                    " entrie(s) without a resolved version skipped: " + label,
                "pub");
  }
  if (skips.malformed > 0)
  {
    result.warn(
        core::WarningCode::kMalformedEntrySkipped,
        "pub: " + std::to_string(skips.malformed) + " malformed entrie(s) skipped: " + label,
        "pub");
  }
}

void close_pending_entry(PendingEntry& pending, SkipCounts& skips, const std::string& label,
                         std::size_t package_limit, std::size_t& package_budget,
                         std::vector<core::Component>& components,
                         core::Result<std::vector<core::Component>>& result)
{
  if (!pending.active)
  {
    return;
  }
  const PendingEntry entry = pending;
  pending = PendingEntry{};
  if (entry.source == PubSource::Path)
  {
    return;  // local/workspace dependency, with no registry identity
  }
  if (entry.source == PubSource::Unknown)
  {
    ++skips.unknown_source;
    return;
  }
  if (entry.name.empty() || entry.version.empty())
  {
    ++skips.git_or_sdk_missing_version;
    return;
  }
  if (package_budget == 0)
  {
    result.warn(core::WarningCode::kEntryLimitReached,
                "pub: package limit " + std::to_string(package_limit) +
                    " reached; remaining entries skipped",
                "pub");
    result.complete = false;
    return;
  }
  --package_budget;
  append_pub_component(entry, label, components, result);
}

/// Parse only the packages mapping. Reader::next always advances its input
/// cursor, including when it skips unsupported hostile lines, so this loop
/// cannot become non-terminating on malformed lockfile content.
void parse_pubspec_lock(std::string_view bytes, const std::string& label, std::size_t package_limit,
                        std::size_t& package_budget, std::vector<core::Component>& components,
                        core::Result<std::vector<core::Component>>& result)
{
  core::yaml_subset::Reader reader(bytes);
  core::yaml_subset::Node node;
  SkipCounts skips;
  PendingEntry pending;
  bool inside_packages = false;

  while (reader.next(node))
  {
    // A new entry or top-level key closes the preceding entry before its
    // fields can be attributed to the next mapping.
    if (node.indentation <= kEntryKeyIndentation)
    {
      close_pending_entry(pending, skips, label, package_limit, package_budget, components, result);
      if (package_budget == 0 && !result.complete)
      {
        break;
      }
    }
    if (node.indentation == kPackagesKeyIndentation)
    {
      inside_packages = node.key == kPackagesKey;
      continue;
    }
    if (!inside_packages)
    {
      continue;
    }
    if (node.indentation == kEntryKeyIndentation)
    {
      if (node.key.empty())
      {
        ++skips.malformed;
        continue;
      }
      pending = PendingEntry{};
      pending.name = node.key;
      pending.active = true;
      continue;
    }
    if (!pending.active)
    {
      continue;
    }
    if (node.indentation == kEntryFieldIndentation)
    {
      if (node.key == kDescriptionKey)
      {
        pending.inside_description = node.opens_block;
      }
      else
      {
        pending.inside_description = false;
        if (node.key == kSourceKey)
        {
          pending.source = parse_pub_source(node.value);
        }
        else if (node.key == kVersionKey)
        {
          pending.version = node.value;
        }
      }
      continue;
    }
    if (node.indentation == kDescriptionFieldIndentation && pending.inside_description)
    {
      if (node.key == kDescriptionUrlField)
      {
        pending.description_url = node.value;
      }
      else if (node.key == kDescriptionResolvedRefField)
      {
        pending.description_resolved_ref = node.value;
      }
    }
  }

  // A lockfile may end while an entry is still pending.
  close_pending_entry(pending, skips, label, package_limit, package_budget, components, result);
  warn_skip_counts(skips, label, result);

  const std::size_t unsupported_line_count = reader.stats().unsupported_line_count;
  if (unsupported_line_count > 0)
  {
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "pub: " + std::to_string(unsupported_line_count) +
                    " line(s) outside the readable YAML subset skipped: " + label,
                "pub");
  }
}

}  // namespace

core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                 const fs::path& root, const ParseOptions& options)
{
  core::Result<std::vector<core::Component>> result;
  std::vector<core::Component> components;
  std::size_t package_budget = options.max_total_packages;

  core::ManifestWalkOptions walk_options;
  walk_options.max_scanned_files = options.max_scanned_files;
  walk_options.max_file_bytes = options.max_file_bytes;
  walk_options.producer_name = "pub";
  walk_options.file_label = std::string(kPubspecLockName);
  walk_options.truncate_at_last_newline = true;
  const core::Result<std::vector<core::WalkedManifestFile>> walked =
      core::walk_bounded_manifest_files(file_index, root, kPubspecLockName, walk_options);
  for (const core::Warning& warning : walked.warnings)
  {
    result.warn(warning);
  }
  for (const core::WalkedManifestFile& file : walked.value)
  {
    if (package_budget == 0 && !result.complete)
    {
      break;
    }
    parse_pubspec_lock(file.bytes, file.label, options.max_total_packages, package_budget,
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

}  // namespace bomwerk::parsers::lockfiles::pub
