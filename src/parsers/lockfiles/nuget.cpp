#include "parsers/lockfiles/nuget.hpp"

#include <cstddef>
#include <filesystem>
#include <functional>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/build_variables.hpp"
#include "core/exclusions.hpp"
#include "core/file_io.hpp"
#include "core/json_utils.hpp"
#include "core/manifest_walk.hpp"
#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/submodule_paths.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"
#include "core/xml_scan.hpp"
#include "parsers/lockfiles/msbuild_properties.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::lockfiles::nuget
{
namespace
{

using core::json_utils::exceeds_json_nesting_depth;
using core::json_utils::kMaxJsonNestingDepth;

constexpr std::string_view kProducerName = "nuget";
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
/// casing is preserved. An empty version (a declared version that is an
/// unresolved MSBuild property) leaves the purl without `@version`.
std::string build_nuget_purl(const std::string& package_name, const std::string& version)
{
  std::string purl = "pkg:nuget/" + core::percent_encode(package_name);
  if (!version.empty())
  {
    purl += "@" + core::percent_encode(version);
  }
  return purl;
}

/// Append one `pkg:nuget` component built from a declared (not resolved)
/// manifest entry: `.csproj`/`packages.config`: at `Confidence::Medium`: a
/// manifest declares a version, it does not resolve one, the same "declares,
/// doesn't resolve" shape maven.cpp's pom.xml reads at Medium confidence. A
/// declaration whose version stayed an unresolved property is emitted without
/// a version, at `Confidence::Low`.
void emit_declared_nuget_component(const std::string& package_name, const std::string& version,
                                   std::string detail, core::Confidence confidence,
                                   std::vector<core::Component>& components,
                                   core::Result<std::vector<core::Component>>& result)
{
  core::Component component;
  component.name = package_name;
  component.version = version;
  component.purl = build_nuget_purl(component.name, component.version);
  component.evidence.push_back({core::Source::Manifest, std::move(detail), confidence});
  core::canonicalize_purl(component.purl, kProducerName, result.warnings);
  components.push_back(std::move(component));
}

using core::xml_scan::find_attribute_value;
using core::xml_scan::find_next_tag;
using core::xml_scan::TagMatch;

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
  // The manifest walk already stripped any UTF-8 byte-order mark.
  const std::string_view json_bytes = bytes;
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
      core::canonicalize_purl(component.purl, kProducerName, result.warnings);
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

/// NuGet's exact-version notation `[1.2.3]` names exactly that version; any
/// other bracket or comma form is a range and stays as written.
/// Example: `without_exact_version_brackets("[11.3.0]")` -> `"11.3.0"`.
std::string without_exact_version_brackets(const std::string& version)
{
  constexpr std::size_t kBracketPairLength = 2;
  if (version.size() > kBracketPairLength && version.front() == '[' && version.back() == ']' &&
      version.find(',') == std::string::npos)
  {
    return core::trimmed(std::string_view(version).substr(1, version.size() - kBracketPairLength));
  }
  return version;
}

/// The property a whole-value `$(Name)` reference names, or an empty string
/// when `text` is anything else.
/// Example: `single_property_name("$(AzureIdentityVersion)")` -> `"AzureIdentityVersion"`.
std::string single_property_name(std::string_view text)
{
  constexpr std::string_view kReferenceOpen = "$(";
  constexpr std::string_view kReferenceClose = ")";
  if (text.size() <= kReferenceOpen.size() + kReferenceClose.size() ||
      !text.starts_with(kReferenceOpen) || !text.ends_with(kReferenceClose) ||
      text.find(kReferenceClose) != text.size() - kReferenceClose.size())
  {
    return {};
  }
  return std::string(text.substr(kReferenceOpen.size(),
                                 text.size() - kReferenceOpen.size() - kReferenceClose.size()));
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
///
/// A name or version written as an MSBuild property (`$(Name)`) is expanded
/// from the properties in scope (`msbuild::PropertyScopes`). A purl never
/// carries an unexpanded reference: a name that stays unresolved drops the
/// entry, a version that stays unresolved keeps it without a version at
/// Confidence::Low, and each case warns with the file and line.
void parse_csproj(const std::string& bytes, const fs::path& csproj_directory,
                  const std::map<fs::path, DirectoryPackagesFile>& directory_packages_by_directory,
                  msbuild::PropertyScopes& property_scopes, const std::string& label,
                  std::size_t package_limit, std::size_t& package_budget,
                  std::vector<core::Component>& components,
                  core::Result<std::vector<core::Component>>& result)
{
  std::size_t skipped_entry_count = 0;
  std::size_t search_position = 0;

  // The project's property table is built the first time an entry needs one:
  // most projects spell every name and version literally.
  std::optional<core::VariableTable> project_properties;
  const auto expand = [&](const std::string& text)
  {
    if (text.find('$') == std::string::npos)
    {
      return text;
    }
    if (!project_properties.has_value())
    {
      project_properties = property_scopes.table_for_project(csproj_directory, bytes);
    }
    return core::expand_variables(text, *project_properties, core::kMsbuildVariableDialect);
  };

  // PackageReference tags are met in document order, so line numbers are
  // counted incrementally: recounting from the start for each one was
  // quadratic.
  core::xml_scan::LineCounter line_counter(bytes);
  while (true)
  {
    const std::optional<TagMatch> tag =
        find_next_tag(bytes, kPackageReferenceElement, search_position);
    if (!tag.has_value())
    {
      break;
    }
    search_position = tag->resume_position;
    const auto location = [&]()
    {
      const std::size_t tag_offset =
          static_cast<std::size_t>(tag->attribute_text.data() - bytes.data());
      return label + ":" + std::to_string(line_counter.line_number_at(tag_offset));
    };

    const std::optional<std::string> declared_name =
        find_attribute_value(tag->attribute_text, kIncludeAttribute);
    if (!declared_name.has_value() || declared_name->empty())
    {
      ++skipped_entry_count;
      continue;
    }

    const std::optional<std::string> version_attribute =
        find_attribute_value(tag->attribute_text, kVersionAttribute);
    std::string declared_version;
    std::string evidence_detail = label;
    if (version_attribute.has_value())
    {
      declared_version = core::trimmed(*version_attribute);
      if (declared_version.empty())
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
            core::to_lower_ascii(*declared_name));
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
      declared_version = *central_version;
      evidence_detail = label + " (version from " + directory_packages_file->label + ")";
    }

    const std::string package_name = expand(*declared_name);
    if (core::contains_unexpanded_variable(package_name))
    {
      result.warn(core::WarningCode::kUnresolvedVariableOrInterpolation,
                  "nuget: " + location() + ": PackageReference '" +
                      core::escaped_for_diagnostic(*declared_name) +
                      "' has an unresolved name; skipped",
                  "nuget", fs::path(label));
      continue;
    }

    std::string resolved_version = expand(declared_version);
    const bool version_unresolved = core::contains_unexpanded_variable(resolved_version);
    if (version_unresolved)
    {
      result.warn(core::WarningCode::kUnresolvedVariableOrInterpolation,
                  "nuget: " + location() + ": PackageReference '" +
                      core::escaped_for_diagnostic(package_name) + "' has an unresolved version '" +
                      core::escaped_for_diagnostic(declared_version) +
                      "'; kept without a version at low confidence",
                  "nuget", fs::path(label));
      resolved_version.clear();
    }
    else if (resolved_version != declared_version)
    {
      const std::string property_name = single_property_name(declared_version);
      evidence_detail += property_name.empty() ? " (version expanded from MSBuild properties)"
                                               : " (version-from-property " + property_name + ")";
    }
    resolved_version = without_exact_version_brackets(resolved_version);

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

    emit_declared_nuget_component(
        package_name, resolved_version, evidence_detail,
        version_unresolved ? core::Confidence::Low : core::Confidence::Medium, components, result);
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

    emit_declared_nuget_component(*package_name, trimmed_version, label, core::Confidence::Medium,
                                  components, result);
  }

  if (skipped_entry_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "nuget: " + std::to_string(skipped_entry_count) +
                    " entrie(s) without a resolvable version skipped: " + label,
                "nuget");
  }
}

/// The formats this producer reads. Every one is a whole document (JSON or
/// XML), so an oversized file is skipped rather than parsed from a prefix.
enum class ManifestKind
{
  kPackagesLock,
  kPackagesConfig,
  kCsproj,
  kDirectoryPackagesProps,
};

/// True for `<name>.csproj`, matching `path::extension()`: a file named just
/// `.csproj` is a dotfile with no extension.
bool has_csproj_extension(std::string_view file_name)
{
  return file_name.size() > kCsprojExtension.size() && file_name.ends_with(kCsprojExtension);
}

std::optional<core::ManifestMatch<ManifestKind>> manifest_kind(const fs::path& relative_path)
{
  const std::string_view file_name = core::file_name_of(relative_path);
  std::optional<ManifestKind> kind;
  if (file_name == kDirectoryPackagesPropsName)
  {
    kind = ManifestKind::kDirectoryPackagesProps;
  }
  else if (file_name == kPackagesLockName)
  {
    kind = ManifestKind::kPackagesLock;
  }
  else if (file_name == kPackagesConfigName)
  {
    kind = ManifestKind::kPackagesConfig;
  }
  else if (has_csproj_extension(file_name))
  {
    kind = ManifestKind::kCsproj;
  }
  if (!kind.has_value())
  {
    return std::nullopt;
  }
  return core::ManifestMatch<ManifestKind>{*kind, core::OversizedFilePolicy::kSkip};
}

/// State shared by every NuGet file of one scan: one package budget, the
/// central package versions each Directory.Packages.props declares (keyed by
/// its directory), and the MSBuild property tables `$(Name)` references
/// resolve against.
struct ParseState
{
  ParseState(const core::FileIndex& file_index, const fs::path& root, std::size_t max_file_bytes,
             std::function<bool()> try_open_file, std::size_t initial_package_budget)
      : package_budget(initial_package_budget),
        property_scopes(file_index, root, max_file_bytes, std::move(try_open_file))
  {
  }

  std::vector<core::Component> components;
  std::size_t package_budget = 0;
  std::map<fs::path, DirectoryPackagesFile> directory_packages_by_directory;
  msbuild::PropertyScopes property_scopes;
};

core::ManifestWalkOptions walk_options_for(const ParseOptions& options)
{
  return core::make_walk_options(options, kProducerName, "manifest");
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
  const fs::path directory = fs::path(file.label).parent_path();
  switch (kind)
  {
    case ManifestKind::kDirectoryPackagesProps:
      state.directory_packages_by_directory[directory] =
          parse_directory_packages_props(file.bytes, file.label, result);
      return;
    case ManifestKind::kPackagesLock:
      parse_packages_lock(file.bytes, file.label, options.max_total_packages, state.package_budget,
                          state.components, result);
      return;
    case ManifestKind::kPackagesConfig:
      parse_packages_config(file.bytes, file.label, options.max_total_packages,
                            state.package_budget, state.components, result);
      return;
    case ManifestKind::kCsproj:
      parse_csproj(file.bytes, directory, state.directory_packages_by_directory,
                   state.property_scopes, file.label, options.max_total_packages,
                   state.package_budget, state.components, result);
      return;
  }
}

/// Takes the state by reference: it holds the MSBuild property tables, which
/// refer into the caller's file index, so it is finished in place.
core::Result<std::vector<core::Component>> finish(ParseState& state,
                                                  core::Result<std::vector<core::Component>> result)
{
  for (const core::Warning& warning : state.property_scopes.warnings())
  {
    result.warn(warning);
  }
  result.value = core::merge_all(std::move(state.components));
  return result;
}

}  // namespace

core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                 const fs::path& root, const ParseOptions& options)
{
  core::Result<std::vector<core::Component>> result;
  const core::ManifestWalkOptions walk_options = walk_options_for(options);
  std::size_t scanned_file_count = 0;
  bool file_limit_warned = false;

  // Discovery is this producer's own, not `core::for_each_manifest_file`:
  // the MSBuild property files `PropertyScopes` opens lazily count against the
  // same file budget as the manifests, and Directory.Packages.props must all
  // be read before any project. Each file still goes through the shared
  // per-file read (`core::read_manifest_file`) and `parse_manifest`.
  //
  // Once max_scanned_files files have been opened, no further file is opened,
  // with exactly one warning regardless of which phase trips it.
  auto file_limit_reached = [&]()
  {
    if (scanned_file_count < options.max_scanned_files)
    {
      return false;
    }
    if (!file_limit_warned)
    {
      result.warnings.push_back(core::file_limit_warning(walk_options));
      file_limit_warned = true;
    }
    return true;
  };

  // A file that is both a property source and a Directory.Packages.props is
  // read once by the property tables and once by phase 1: the budget is
  // generous, the double count is harmless.
  ParseState state(
      file_index, root, options.max_file_bytes,
      [&]()
      {
        if (file_limit_reached())
        {
          return false;
        }
        ++scanned_file_count;
        return true;
      },
      options.max_total_packages);

  // Phase 1 reads every Directory.Packages.props, so CPM resolution in phase
  // 2 sees the complete directory->version map regardless of how a props file
  // happens to sort relative to the .csproj files that reference it. Phase 2
  // reads packages.lock.json, packages.config and .csproj.
  for (const bool central_versions_phase : {true, false})
  {
    for (const fs::path& relative_path : file_index.files)
    {
      const std::optional<core::ManifestMatch<ManifestKind>> match = manifest_kind(relative_path);
      if (!match.has_value() ||
          (match->kind == ManifestKind::kDirectoryPackagesProps) != central_versions_phase)
      {
        continue;
      }
      if (file_limit_reached())
      {
        break;
      }
      if (!central_versions_phase && package_budget_exhausted(state, result))
      {
        break;
      }
      ++scanned_file_count;

      const std::optional<core::WalkedManifestFile> file =
          core::read_manifest_file(root, relative_path, options.max_file_bytes, kProducerName,
                                   match->oversized, result.warnings);
      if (file.has_value())
      {
        parse_manifest(match->kind, *file, options, state, result);
      }
    }
  }
  return finish(state, std::move(result));
}

core::Result<std::vector<core::Component>> parse_bytes(std::string_view file_name,
                                                       std::string_view bytes,
                                                       const ParseOptions& options)
{
  core::Result<std::vector<core::Component>> result;
  // An empty index: `PropertyScopes` then never finds a property file to
  // open, so `$(Name)` references resolve only against the project itself.
  const core::FileIndex no_other_files;
  ParseState state(
      no_other_files, fs::path(), options.max_file_bytes, [] { return false; },
      options.max_total_packages);
  core::for_manifest_bytes(file_name, bytes, options.max_file_bytes, kProducerName, result.warnings,
                           manifest_kind, [&](ManifestKind kind, core::WalkedManifestFile&& file)
                           { parse_manifest(kind, file, options, state, result); });
  return finish(state, std::move(result));
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
