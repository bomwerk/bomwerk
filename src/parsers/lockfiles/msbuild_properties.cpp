#include "parsers/lockfiles/msbuild_properties.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/build_variables.hpp"
#include "core/file_io.hpp"
#include "core/warning_code.hpp"
#include "core/xml_scan.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::lockfiles::msbuild
{
namespace
{

constexpr std::size_t kMaxImportDepth = 16;

constexpr std::string_view kEcosystem = "nuget";

constexpr std::string_view kPropertyGroupElement = "PropertyGroup";
constexpr std::string_view kImportElement = "Import";
constexpr std::string_view kProjectAttribute = "Project";
constexpr std::string_view kSdkAttribute = "Sdk";

constexpr std::string_view kDirectoryBuildPropsName = "Directory.Build.props";
constexpr std::string_view kDirectoryPackagesPropsName = "Directory.Packages.props";
constexpr std::string_view kArcadeVersionFiles[] = {"eng/Versions.props",
                                                    "eng/Version.Details.props"};

constexpr std::string_view kThisFileDirectoryPrefix = "$(MSBuildThisFileDirectory)";
constexpr std::string_view kRepoRootPrefix = "$(RepoRoot)";
constexpr std::string_view kEngineeringDirectoryPrefix = "$(RepositoryEngineeringDir)";
constexpr std::string_view kEngineeringDirectory = "eng";

constexpr std::string_view kUnresolvableImportMarkers[] = {"$(", "@(", "%(", "*"};

}  // namespace

core::VariableTable parse_property_groups(std::string_view xml)
{
  const std::string cleaned = core::xml_scan::strip_comments_and_unwrap_cdata(xml);
  core::VariableTable table;
  std::size_t position = 0;
  while (true)
  {
    const std::optional<core::xml_scan::ElementMatch> block =
        core::xml_scan::find_element(cleaned, kPropertyGroupElement, position);
    if (!block.has_value())
    {
      break;
    }
    position = block->resume_position;
    for (const core::xml_scan::ChildElement& child :
         core::xml_scan::child_elements(block->inner_text))
    {
      if (child.text.find('<') != std::string::npos)
      {
        core::mark_variable_ambiguous(table, core::kMsbuildVariableDialect, child.name);
        continue;
      }
      core::record_variable_definition(table, core::kMsbuildVariableDialect, child.name,
                                       child.text);
    }
  }
  return table;
}

std::vector<std::string> parse_import_projects(std::string_view xml)
{
  const std::string cleaned = core::xml_scan::strip_comments_and_unwrap_cdata(xml);
  std::vector<std::string> projects;
  std::size_t position = 0;
  while (true)
  {
    const std::optional<core::xml_scan::TagMatch> tag =
        core::xml_scan::find_next_tag(cleaned, kImportElement, position);
    if (!tag.has_value())
    {
      break;
    }
    position = tag->resume_position;
    if (core::xml_scan::find_attribute_value(tag->attribute_text, kSdkAttribute).has_value())
    {
      continue;
    }
    std::optional<std::string> project =
        core::xml_scan::find_attribute_value(tag->attribute_text, kProjectAttribute);
    if (project.has_value() && !project->empty())
    {
      projects.push_back(std::move(*project));
    }
  }
  return projects;
}

std::optional<fs::path> resolve_import_path(const fs::path& importing_directory,
                                            std::string_view project_value)
{
  std::string value(project_value);
  std::replace(value.begin(), value.end(), '\\', '/');

  fs::path base_directory = importing_directory;
  bool has_known_prefix = true;
  if (value.starts_with(kThisFileDirectoryPrefix))
  {
    value.erase(0, kThisFileDirectoryPrefix.size());
  }
  else if (value.starts_with(kRepoRootPrefix))
  {
    value.erase(0, kRepoRootPrefix.size());
    base_directory.clear();
  }
  else if (value.starts_with(kEngineeringDirectoryPrefix))
  {
    value.erase(0, kEngineeringDirectoryPrefix.size());
    base_directory = fs::path(std::string(kEngineeringDirectory));
  }
  else
  {
    has_known_prefix = false;
  }

  if (has_known_prefix)
  {
    value.erase(0, value.find_first_not_of('/'));
  }
  if (value.empty() || value.front() == '/')
  {
    return std::nullopt;
  }
  for (const std::string_view marker : kUnresolvableImportMarkers)
  {
    if (value.find(marker) != std::string::npos)
    {
      return std::nullopt;
    }
  }

  const fs::path resolved = (base_directory / value).lexically_normal();
  if (resolved.empty() || !resolved.has_filename() || *resolved.begin() == "..")
  {
    return std::nullopt;
  }
  return resolved;
}

PropertyScopes::PropertyScopes(const core::FileIndex& file_index, fs::path root,
                               std::size_t max_file_bytes, std::function<bool()> try_open_file)
    : indexed_files_(file_index.files),
      root_(std::move(root)),
      max_file_bytes_(max_file_bytes),
      try_open_file_(std::move(try_open_file))
{
}

bool PropertyScopes::is_indexed(const fs::path& relative_path) const
{
  return std::binary_search(indexed_files_.begin(), indexed_files_.end(), relative_path);
}

const PropertyScopes::LoadedFile* PropertyScopes::load(const fs::path& relative_path)
{
  const auto cached = loaded_files_.find(relative_path);
  if (cached != loaded_files_.end())
  {
    return cached->second.has_value() ? &*cached->second : nullptr;
  }
  if (!is_indexed(relative_path) || !try_open_file_())
  {
    return nullptr;
  }

  const std::string label = relative_path.generic_string();
  const core::BoundedFileRead file_read =
      core::read_file_bounded(root_ / relative_path, max_file_bytes_);
  if (!file_read.readable || file_read.truncated)
  {
    const bool is_unreadable = !file_read.readable;
    warnings_.push_back(core::Warning{is_unreadable ? core::WarningCode::kUnreadableFile
                                                    : core::WarningCode::kFileSizeLimitExceeded,
                                      is_unreadable
                                          ? "nuget: unreadable file: " + label
                                          : "nuget: file exceeds size limit, skipped: " + label,
                                      std::string(kEcosystem), relative_path});
    loaded_files_.emplace(relative_path, std::nullopt);
    return nullptr;
  }

  LoadedFile loaded;
  loaded.properties = parse_property_groups(file_read.bytes);
  loaded.imports = parse_import_projects(file_read.bytes);
  const auto inserted = loaded_files_.emplace(relative_path, std::move(loaded));
  return &*inserted.first->second;
}

void PropertyScopes::merge_file_closure(core::VariableTable& table, const fs::path& relative_path,
                                        std::set<fs::path>& visited, std::size_t depth)
{
  if (depth > kMaxImportDepth || !visited.insert(relative_path).second)
  {
    return;
  }
  const LoadedFile* loaded = load(relative_path);
  if (loaded == nullptr)
  {
    return;
  }
  core::merge_variable_tables(table, core::kMsbuildVariableDialect, loaded->properties);
  merge_imports(table, relative_path.parent_path(), loaded->imports, visited, depth + 1);
}

void PropertyScopes::merge_imports(core::VariableTable& table, const fs::path& importing_directory,
                                   const std::vector<std::string>& imports,
                                   std::set<fs::path>& visited, std::size_t depth)
{
  for (const std::string& project_value : imports)
  {
    const std::optional<fs::path> resolved =
        resolve_import_path(importing_directory, project_value);
    if (resolved.has_value())
    {
      merge_file_closure(table, *resolved, visited, depth);
    }
  }
}

bool PropertyScopes::has_directory_files(const fs::path& directory) const
{
  return is_indexed(directory / std::string(kDirectoryBuildPropsName)) ||
         is_indexed(directory / std::string(kDirectoryPackagesPropsName));
}

const core::VariableTable& PropertyScopes::table_at(const fs::path& directory)
{
  const auto cached = tables_by_directory_.find(directory);
  if (cached != tables_by_directory_.end())
  {
    return *cached->second;
  }

  auto table = std::make_unique<core::VariableTable>();
  if (!directory.empty())
  {
    *table = table_for_directory(directory.parent_path());
  }
  std::set<fs::path> visited;
  if (directory.empty())
  {
    for (const std::string_view arcade_file : kArcadeVersionFiles)
    {
      merge_file_closure(*table, fs::path(std::string(arcade_file)), visited, 0);
    }
  }
  merge_file_closure(*table, directory / std::string(kDirectoryBuildPropsName), visited, 0);
  merge_file_closure(*table, directory / std::string(kDirectoryPackagesPropsName), visited, 0);
  return *tables_by_directory_.emplace(directory, std::move(table)).first->second;
}

const core::VariableTable& PropertyScopes::table_for_directory(const fs::path& directory)
{
  fs::path nearest_directory = directory;
  while (!nearest_directory.empty() && !has_directory_files(nearest_directory))
  {
    nearest_directory = nearest_directory.parent_path();
  }
  return table_at(nearest_directory);
}

core::VariableTable PropertyScopes::table_for_project(const fs::path& directory,
                                                      std::string_view project_xml)
{
  core::VariableTable table = table_for_directory(directory);
  core::merge_variable_tables(table, core::kMsbuildVariableDialect,
                              parse_property_groups(project_xml));
  std::set<fs::path> visited;
  merge_imports(table, directory, parse_import_projects(project_xml), visited, 0);
  return table;
}

}  // namespace bomwerk::parsers::lockfiles::msbuild
