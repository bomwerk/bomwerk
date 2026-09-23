#include "parsers/lockfiles/nuget.hpp"

#include <cstddef>
#include <filesystem>
#include <map>
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

namespace bomwerk::parsers::lockfiles::nuget
{
namespace
{

using core::json_utils::exceeds_json_nesting_depth;
using core::json_utils::kMaxJsonNestingDepth;
using core::json_utils::without_utf8_bom;

constexpr std::string_view kPackagesLockName = "packages.lock.json";
constexpr std::string_view kPackagesConfigName = "packages.config";
constexpr std::string_view kCsprojExtension = ".csproj";
constexpr std::string_view kDirectoryPackagesPropsName = "Directory.Packages.props";

/// Central Package Management's version-declaration element: one per package,
/// read the same attribute-based way as `PackageReference`/`package`.
constexpr std::string_view kPackageVersionElement = "PackageVersion";

/// The entry type marking a project reference: first-party, never a
/// dependency of the product.
constexpr std::string_view kProjectReferenceType = "Project";

/// The `.csproj` element carrying one NuGet dependency identity, and the
/// attributes that declare it.
constexpr std::string_view kPackageReferenceElement = "PackageReference";
constexpr std::string_view kIncludeAttribute = "Include";
constexpr std::string_view kVersionAttribute = "Version";

/// The `packages.config` element carrying one NuGet dependency identity, and
/// the attributes that declare it.
constexpr std::string_view kPackageElement = "package";
constexpr std::string_view kIdAttribute = "id";
constexpr std::string_view kVersionConfigAttribute = "version";

/// Build the `pkg:nuget` purl. NuGet names have no namespace; the lockfile's
/// casing is preserved.
std::string build_nuget_purl(const std::string& package_name, const std::string& version)
{
  return "pkg:nuget/" + core::percent_encode(package_name) + "@" + core::percent_encode(version);
}

/// Canonicalize `component.purl` in place, warning when it fails validation
/// (defensive: percent-encoding should make that impossible).
void canonicalize_purl(core::Component& component,
                       core::Result<std::vector<core::Component>>& result)
{
  const core::Result<core::Purl> parsed_purl = core::Purl::parse(component.purl);
  if (!parsed_purl.complete)
  {
    result.warn(core::WarningCode::kPurlValidationFailed,
                "nuget: produced purl failed validation: " + component.purl, "nuget");
  }
  else
  {
    component.purl = parsed_purl.value.canonical();
  }
}

/// Append one `pkg:nuget` component built from a declared (not resolved)
/// manifest entry: `.csproj`/`packages.config`: at `Confidence::Medium`: a
/// manifest declares a version, it does not resolve one, the same "declares,
/// doesn't resolve" shape maven.cpp's pom.xml reads at Medium confidence.
void emit_declared_nuget_component(const std::string& package_name, const std::string& version,
                                   std::string detail, std::vector<core::Component>& components,
                                   core::Result<std::vector<core::Component>>& result)
{
  core::Component component;
  component.name = package_name;
  component.version = version;
  component.purl = build_nuget_purl(component.name, component.version);
  component.evidence.push_back(
      {core::Source::Manifest, std::move(detail), core::Confidence::Medium});
  canonicalize_purl(component, result);
  components.push_back(std::move(component));
}

/// True for the ASCII whitespace XML allows inside tags.
bool is_xml_whitespace(char character)
{
  return character == ' ' || character == '\t' || character == '\r' || character == '\n';
}

/// One matched opening tag's raw attribute text (the span between the tag
/// name and the closing `>`/`/>`) and where scanning may resume after it.
/// Element bodies are not tracked: `.csproj`/`packages.config` entries carry
/// their identity entirely in attributes on the opening tag.
struct TagMatch
{
  std::string_view attribute_text;
  std::size_t resume_position = 0;
};

/// Find the next `<tag ...>` or `<tag .../>` opening at or after
/// `search_start`. Anything the scanner cannot pair: an unterminated tag :
/// degrades to "not found", never a crash (Hard Rule 1).
std::optional<TagMatch> find_next_tag(std::string_view xml, std::string_view tag_name,
                                      std::size_t search_start)
{
  std::size_t position = search_start;
  while (position < xml.size())
  {
    const std::size_t open = xml.find('<', position);
    if (open == std::string_view::npos)
    {
      return std::nullopt;
    }
    const std::size_t name_start = open + 1;
    if (xml.compare(name_start, tag_name.size(), tag_name) != 0)
    {
      position = open + 1;
      continue;
    }
    const std::size_t after_name = name_start + tag_name.size();
    if (after_name >= xml.size() ||
        (xml[after_name] != '>' && xml[after_name] != '/' && !is_xml_whitespace(xml[after_name])))
    {
      position = open + 1;  // a longer tag name that merely starts the same
      continue;
    }
    const std::size_t open_end = xml.find('>', after_name);
    if (open_end == std::string_view::npos)
    {
      return std::nullopt;
    }
    const std::size_t attribute_end = (xml[open_end - 1] == '/') ? open_end - 1 : open_end;
    return TagMatch{xml.substr(after_name, attribute_end - after_name), open_end + 1};
  }
  return std::nullopt;
}

/// First `name="value"` (or `name='value'`) attribute in `attribute_text`;
/// nullopt when absent or unterminated. `attribute_name` must sit on a word
/// boundary so `Version` never matches inside a longer attribute name.
std::optional<std::string> find_attribute_value(std::string_view attribute_text,
                                                std::string_view attribute_name)
{
  std::size_t position = 0;
  while (position < attribute_text.size())
  {
    const std::size_t name_position = attribute_text.find(attribute_name, position);
    if (name_position == std::string_view::npos)
    {
      return std::nullopt;
    }
    position = name_position + 1;
    const bool has_left_boundary =
        name_position == 0 || is_xml_whitespace(attribute_text[name_position - 1]);
    const std::size_t after_name = name_position + attribute_name.size();
    if (!has_left_boundary || after_name >= attribute_text.size() ||
        attribute_text[after_name] != '=')
    {
      continue;
    }
    const std::size_t quote_position = after_name + 1;
    if (quote_position >= attribute_text.size() ||
        (attribute_text[quote_position] != '"' && attribute_text[quote_position] != '\''))
    {
      continue;
    }
    const char quote = attribute_text[quote_position];
    const std::size_t value_start = quote_position + 1;
    const std::size_t value_end = attribute_text.find(quote, value_start);
    if (value_end == std::string_view::npos)
    {
      return std::nullopt;
    }
    return std::string(attribute_text.substr(value_start, value_end - value_start));
  }
  return std::nullopt;
}

/// One parsed `Directory.Packages.props`: the package-name-to-version map
/// Central Package Management declares for its directory and everything
/// below it, plus the file's own root-relative path for evidence detail.
/// Keys are lower-cased (NuGet package names are case-insensitive; the
/// `.csproj`'s own `Include` spelling stays the identity recorded).
struct DirectoryPackagesFile
{
  std::string label;
  std::unordered_map<std::string, std::string> versions_by_lowercase_name;
};

/// Parse one `Directory.Packages.props`'s
/// `<PackageVersion Include="Name" Version="1.2.3" />` elements into a
/// lower-cased name-to-version map. An entry missing `Include`/`Version`, or
/// with a blank `Version`, degrades to a skip counted in one summary warning
///: never a crash (Hard Rule 1).
DirectoryPackagesFile parse_directory_packages_props(
    const std::string& bytes, const std::string& label,
    core::Result<std::vector<core::Component>>& result)
{
  DirectoryPackagesFile file;
  file.label = label;
  std::size_t skipped_entry_count = 0;
  std::size_t search_position = 0;
  while (true)
  {
    const std::optional<TagMatch> tag =
        find_next_tag(bytes, kPackageVersionElement, search_position);
    if (!tag.has_value())
    {
      break;
    }
    search_position = tag->resume_position;

    const std::optional<std::string> package_name =
        find_attribute_value(tag->attribute_text, kIncludeAttribute);
    const std::optional<std::string> version =
        find_attribute_value(tag->attribute_text, kVersionAttribute);
    if (!package_name.has_value() || package_name->empty() || !version.has_value())
    {
      ++skipped_entry_count;
      continue;
    }
    const std::string trimmed_version = core::trimmed(*version);
    if (trimmed_version.empty())
    {
      ++skipped_entry_count;
      continue;
    }
    file.versions_by_lowercase_name[core::to_lower_ascii(*package_name)] = trimmed_version;
  }

  if (skipped_entry_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "nuget: " + std::to_string(skipped_entry_count) +
                    " PackageVersion entrie(s) without a resolvable version skipped: " + label,
                "nuget");
  }
  return file;
}

/// The nearest `Directory.Packages.props` at `starting_directory` or any
/// ancestor of it, or `nullptr` when none covers this directory: the same
/// directory-scoped lookup MSBuild itself performs, walking upward from a
/// `.csproj` to the nearest declaration (`core::manifest_names.cpp`'s
/// `has_covered_ancestor` is the same walk for a different purpose).
const DirectoryPackagesFile* find_nearest_directory_packages_file(
    const fs::path& starting_directory,
    const std::map<fs::path, DirectoryPackagesFile>& directory_packages_by_directory)
{
  fs::path candidate_directory = starting_directory;
  while (true)
  {
    const auto found = directory_packages_by_directory.find(candidate_directory);
    if (found != directory_packages_by_directory.end())
    {
      return &found->second;
    }
    if (candidate_directory.empty())
    {
      return nullptr;
    }
    candidate_directory = candidate_directory.parent_path();
  }
}

/// Parse one packages.lock.json's per-framework dependency maps into
/// components. `label` is the root-relative path used in warnings and
/// evidence details.
void parse_packages_lock(const std::string& bytes, const std::string& label,
                         std::size_t package_limit, std::size_t& package_budget,
                         std::vector<core::Component>& components,
                         core::Result<std::vector<core::Component>>& result)
{
  const std::string_view json_bytes = without_utf8_bom(bytes);
  if (exceeds_json_nesting_depth(json_bytes, kMaxJsonNestingDepth))
  {
    result.warn(core::WarningCode::kJsonNestingDepthExceeded,
                "nuget: " + label + ": JSON nesting exceeds depth limit, skipped", "nuget");
    return;
  }
  const nlohmann::json lockfile =
      nlohmann::json::parse(json_bytes, nullptr, /*allow_exceptions=*/false);
  if (lockfile.is_discarded() || !lockfile.is_object())
  {
    result.warn(core::WarningCode::kInvalidJson, "nuget: " + label + ": not valid JSON, skipped",
                "nuget");
    return;
  }
  const auto dependencies_iterator = lockfile.find("dependencies");
  if (dependencies_iterator == lockfile.end() || !dependencies_iterator->is_object())
  {
    // Key present-but-wrong or absent: real dependencies were likely dropped :
    // warn so the operator knows the SBOM may be incomplete.
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "nuget: " + label + ": dependencies map missing or malformed, skipped", "nuget");
    return;
  }

  std::size_t skipped_entry_count = 0;
  bool budget_exhausted = false;
  for (const auto& [framework_name, framework_packages] : dependencies_iterator->items())
  {
    if (!framework_packages.is_object())
    {
      ++skipped_entry_count;
      continue;
    }
    for (const auto& [package_name, entry] : framework_packages.items())
    {
      if (!entry.is_object() || package_name.empty())
      {
        ++skipped_entry_count;
        continue;
      }
      const auto type_iterator = entry.find("type");
      const std::string entry_type = (type_iterator != entry.end() && type_iterator->is_string())
                                         ? type_iterator->get<std::string>()
                                         : std::string{};
      if (entry_type == kProjectReferenceType)
      {
        continue;  // a project reference: first-party, not a dependency
      }
      const auto resolved_iterator = entry.find("resolved");
      if (resolved_iterator == entry.end() || !resolved_iterator->is_string())
      {
        ++skipped_entry_count;
        continue;
      }

      if (package_budget == 0)
      {
        result.warn(core::WarningCode::kEntryLimitReached,
                    "nuget: package limit " + std::to_string(package_limit) +
                        " reached; remaining entries skipped",
                    "nuget");
        result.complete = false;
        budget_exhausted = true;
        break;
      }
      --package_budget;

      core::Component component;
      component.name = package_name;
      component.version = core::trimmed(resolved_iterator->get<std::string>());
      component.purl = build_nuget_purl(component.name, component.version);

      std::string detail = label + " (" + framework_name;
      if (!entry_type.empty())
      {
        detail += ", " + entry_type;
      }
      detail += ")";
      // `contentHash` is a base64 sha512: evidence, never Component::sha256.
      const auto content_hash_iterator = entry.find("contentHash");
      if (content_hash_iterator != entry.end() && content_hash_iterator->is_string())
      {
        detail += " (contentHash " + content_hash_iterator->get<std::string>() + ")";
      }
      // Lock entries are NuGet's own resolver output -> High.
      component.evidence.push_back({core::Source::Manifest, detail, core::Confidence::High});
      canonicalize_purl(component, result);
      components.push_back(std::move(component));
    }
    if (budget_exhausted)
    {
      break;
    }
  }

  if (skipped_entry_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "nuget: " + std::to_string(skipped_entry_count) +
                    " entrie(s) without a resolved version skipped: " + label,
                "nuget");
  }
}

/// Parse one `.csproj`'s `<PackageReference Include="Name" Version="1.2.3" />`
/// elements into components. A `.csproj` declares a version, it does not
/// resolve one (no lockfile backs it) -> Confidence::Medium. Only the
/// attribute-based form is read: the rarer nested-element form
/// (`<PackageReference Include="X"><Version>1.2.3</Version></PackageReference>`)
/// degrades to a missing-Version skip rather than a crash, same as any other
/// malformed entry.
///
/// An entry with no `Version` attribute at all is Central Package
/// Management's shape (`<PackageReference Include="Name" />`): its version
/// resolves against the nearest `Directory.Packages.props` at
/// `csproj_directory` or above, same Confidence::Medium as the direct-version
/// case (the version still only declares, never resolves via a lockfile).
/// No covering file, or no matching entry in it, degrades to the same
/// missing-Version skip as before CPM support existed.
void parse_csproj(const std::string& bytes, const fs::path& csproj_directory,
                  const std::map<fs::path, DirectoryPackagesFile>& directory_packages_by_directory,
                  const std::string& label, std::size_t package_limit, std::size_t& package_budget,
                  std::vector<core::Component>& components,
                  core::Result<std::vector<core::Component>>& result)
{
  std::size_t skipped_entry_count = 0;
  std::size_t search_position = 0;
  while (true)
  {
    const std::optional<TagMatch> tag =
        find_next_tag(bytes, kPackageReferenceElement, search_position);
    if (!tag.has_value())
    {
      break;
    }
    search_position = tag->resume_position;

    const std::optional<std::string> package_name =
        find_attribute_value(tag->attribute_text, kIncludeAttribute);
    if (!package_name.has_value() || package_name->empty())
    {
      ++skipped_entry_count;
      continue;
    }

    const std::optional<std::string> version_attribute =
        find_attribute_value(tag->attribute_text, kVersionAttribute);
    std::string resolved_version;
    std::string evidence_detail = label;
    if (version_attribute.has_value())
    {
      resolved_version = core::trimmed(*version_attribute);
      if (resolved_version.empty())
      {
        ++skipped_entry_count;
        continue;
      }
    }
    else
    {
      const DirectoryPackagesFile* directory_packages_file =
          find_nearest_directory_packages_file(csproj_directory, directory_packages_by_directory);
      std::optional<std::string> central_version;
      if (directory_packages_file != nullptr)
      {
        const auto found = directory_packages_file->versions_by_lowercase_name.find(
            core::to_lower_ascii(*package_name));
        if (found != directory_packages_file->versions_by_lowercase_name.end())
        {
          central_version = found->second;
        }
      }
      if (!central_version.has_value())
      {
        ++skipped_entry_count;
        continue;
      }
      resolved_version = *central_version;
      evidence_detail = label + " (version from " + directory_packages_file->label + ")";
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "nuget: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "nuget");
      result.complete = false;
      break;
    }
    --package_budget;

    emit_declared_nuget_component(*package_name, resolved_version, evidence_detail, components,
                                  result);
  }

  if (skipped_entry_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "nuget: " + std::to_string(skipped_entry_count) +
                    " entrie(s) without a resolvable version skipped: " + label,
                "nuget");
  }
}

/// Parse one `packages.config`'s `<package id="Name" version="1.2.3" .../>`
/// elements into components. Same "declares, does not resolve" shape as
/// `.csproj` -> Confidence::Medium. `targetFramework` is read only as evidence
/// context, never as identity.
void parse_packages_config(const std::string& bytes, const std::string& label,
                           std::size_t package_limit, std::size_t& package_budget,
                           std::vector<core::Component>& components,
                           core::Result<std::vector<core::Component>>& result)
{
  std::size_t skipped_entry_count = 0;
  std::size_t search_position = 0;
  while (true)
  {
    const std::optional<TagMatch> tag = find_next_tag(bytes, kPackageElement, search_position);
    if (!tag.has_value())
    {
      break;
    }
    search_position = tag->resume_position;

    const std::optional<std::string> package_name =
        find_attribute_value(tag->attribute_text, kIdAttribute);
    const std::optional<std::string> version =
        find_attribute_value(tag->attribute_text, kVersionConfigAttribute);
    if (!package_name.has_value() || package_name->empty() || !version.has_value())
    {
      ++skipped_entry_count;
      continue;
    }
    const std::string trimmed_version = core::trimmed(*version);
    if (trimmed_version.empty())
    {
      ++skipped_entry_count;
      continue;
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "nuget: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "nuget");
      result.complete = false;
      break;
    }
    --package_budget;

    emit_declared_nuget_component(*package_name, trimmed_version, label, components, result);
  }

  if (skipped_entry_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "nuget: " + std::to_string(skipped_entry_count) +
                    " entrie(s) without a resolvable version skipped: " + label,
                "nuget");
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
  bool file_limit_warned = false;

  // Shared across both phases below: once max_scanned_files manifest files
  // have been opened (Directory.Packages.props included: it is read the same
  // as any other manifest, so it is bounded the same way), no further file is
  // opened, with exactly one warning regardless of which phase trips it.
  auto file_limit_reached = [&]()
  {
    if (scanned_file_count < options.max_scanned_files)
    {
      return false;
    }
    if (!file_limit_warned)
    {
      result.warn(core::WarningCode::kFileLimitReached,
                  "nuget: file limit reached; remaining manifest files skipped", "nuget");
      file_limit_warned = true;
    }
    return true;
  };

  // Phase 1: every Directory.Packages.props first, so CPM resolution in phase
  // 2 sees the complete directory->version map regardless of how a props file
  // happens to sort relative to the .csproj files that reference it.
  std::map<fs::path, DirectoryPackagesFile> directory_packages_by_directory;
  for (const fs::path& relative_path : file_index.files)
  {
    if (relative_path.filename().string() != kDirectoryPackagesPropsName)
    {
      continue;
    }
    if (file_limit_reached())
    {
      break;
    }
    ++scanned_file_count;

    const std::string label = relative_path.generic_string();
    const core::BoundedFileRead file_read =
        core::read_file_bounded(root / relative_path, options.max_file_bytes);
    if (!file_read.readable)
    {
      result.warn(core::WarningCode::kUnreadableFile, "nuget: unreadable file: " + label, "nuget");
      continue;
    }
    if (file_read.truncated)
    {
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "nuget: file exceeds size limit, skipped: " + label, "nuget");
      continue;
    }
    directory_packages_by_directory[relative_path.parent_path()] =
        parse_directory_packages_props(file_read.bytes, label, result);
  }

  // Phase 2: packages.lock.json, packages.config and .csproj, same order and
  // limits nuget.cpp used before Directory.Packages.props support landed.
  for (const fs::path& relative_path : file_index.files)
  {
    const std::string filename = relative_path.filename().string();
    const bool is_packages_lock = filename == kPackagesLockName;
    const bool is_packages_config = filename == kPackagesConfigName;
    const bool is_csproj = relative_path.extension().string() == kCsprojExtension;
    if (!is_packages_lock && !is_packages_config && !is_csproj)
    {
      continue;
    }
    if (file_limit_reached())
    {
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
      result.warn(core::WarningCode::kUnreadableFile, "nuget: unreadable file: " + label, "nuget");
      continue;
    }
    if (file_read.truncated)
    {
      // A truncated manifest cannot parse reliably: skipping beats guessing.
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "nuget: file exceeds size limit, skipped: " + label, "nuget");
      continue;
    }

    if (is_packages_lock)
    {
      parse_packages_lock(file_read.bytes, label, options.max_total_packages, package_budget,
                          components, result);
    }
    else if (is_packages_config)
    {
      parse_packages_config(file_read.bytes, label, options.max_total_packages, package_budget,
                            components, result);
    }
    else
    {
      parse_csproj(file_read.bytes, relative_path.parent_path(), directory_packages_by_directory,
                   label, options.max_total_packages, package_budget, components, result);
    }
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

}  // namespace bomwerk::parsers::lockfiles::nuget
