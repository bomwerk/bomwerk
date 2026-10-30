#pragma once
#include <cstddef>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "core/build_variables.hpp"
#include "core/file_index.hpp"
#include "core/warning.hpp"

namespace bomwerk::parsers::lockfiles::msbuild
{

/// Every `<PropertyGroup>` child of one MSBuild file (`.props`, `.targets` or a
/// project) as a property table. A property defined twice with different
/// values, or with an empty value or nested markup, is ambiguous. A `Condition`
/// attribute is not evaluated: a conditional definition counts like any other,
/// and the ambiguity rule is what protects the common "default unless
/// overridden" pair.
/// Example: `<PropertyGroup><V>1.2</V></PropertyGroup>` -> `{v: "1.2"}`
/// (names compare case-insensitively, so keys are lower-case).
[[nodiscard]] core::VariableTable parse_property_groups(std::string_view xml);

/// The `Project` attribute of every `<Import>` element that names a file
/// (an `Sdk` import names an SDK, never a file in the scanned tree).
/// Example: `<Import Project="..\eng\Versions.props" />` -> `"..\eng\Versions.props"`.
[[nodiscard]] std::vector<std::string> parse_import_projects(std::string_view xml);

/// The scanned-tree path an `<Import Project="...">` value names, relative to
/// the scan root and lexically normal, or nullopt when it cannot be named
/// statically: an unknown `$(...)`, a wildcard, an absolute path, or a path
/// that climbs out of the scan root. Understood prefixes are
/// `$(MSBuildThisFileDirectory)` (the importing file's directory),
/// `$(RepoRoot)` and `$(RepositoryEngineeringDir)` (`eng/`). Backslashes count
/// as separators.
/// Example: from `src/Directory.Build.props`, `$(MSBuildThisFileDirectory)..\eng\x.props`
/// -> `eng/x.props`.
[[nodiscard]] std::optional<std::filesystem::path> resolve_import_path(
    const std::filesystem::path& importing_directory, std::string_view project_value);

/// MSBuild property tables for the directories of a scanned tree, built from
/// the files MSBuild itself would pull in: `Directory.Build.props` and
/// `Directory.Packages.props` of every ancestor directory, everything they
/// `<Import>` (when the imported file is inside the scan root), and, for a
/// project, its own property groups and imports.
///
/// Two conventions beyond MSBuild's own rules, both read-only guesses at where
/// a repository keeps its versions: the root's `eng/Versions.props` and
/// `eng/Version.Details.props` (the .NET Arcade layout) are always part of the
/// root table, because repositories that use Arcade import them from an SDK
/// that lives outside the tree.
///
/// Definitions from all files in scope are merged without precedence: a
/// property with two different values is ambiguous and never expands, so a
/// version is never taken from the wrong file. Never runs MSBuild or dotnet
/// (hard rule 9); a hostile tree degrades to missing properties.
class PropertyScopes
{
 public:
  /// `try_open_file` is asked before every file read and returns false once the
  /// caller's file budget is spent (the caller owns the warning for that).
  PropertyScopes(const core::FileIndex& file_index, std::filesystem::path root,
                 std::size_t max_file_bytes, std::function<bool()> try_open_file);

  /// Properties in scope for any project in `directory` (root-relative).
  /// The returned reference stays valid for the life of this object.
  [[nodiscard]] const core::VariableTable& table_for_directory(
      const std::filesystem::path& directory);

  /// `table_for_directory(directory)` plus the project's own property groups
  /// and imports. `project_xml` is the project file's text.
  [[nodiscard]] core::VariableTable table_for_project(const std::filesystem::path& directory,
                                                      std::string_view project_xml);

  /// Warnings raised while reading files (unreadable, over the size cap), for
  /// the caller to forward.
  [[nodiscard]] const std::vector<core::Warning>& warnings() const { return warnings_; }

 private:
  struct LoadedFile
  {
    core::VariableTable properties;
    std::vector<std::string> imports;
  };

  [[nodiscard]] bool is_indexed(const std::filesystem::path& relative_path) const;
  [[nodiscard]] const LoadedFile* load(const std::filesystem::path& relative_path);
  void merge_file_closure(core::VariableTable& table, const std::filesystem::path& relative_path,
                          std::set<std::filesystem::path>& visited, std::size_t depth);
  void merge_imports(core::VariableTable& table, const std::filesystem::path& importing_directory,
                     const std::vector<std::string>& imports,
                     std::set<std::filesystem::path>& visited, std::size_t depth);
  [[nodiscard]] bool has_directory_files(const std::filesystem::path& directory) const;
  [[nodiscard]] const core::VariableTable& table_at(const std::filesystem::path& directory);

  const std::vector<std::filesystem::path>& indexed_files_;
  std::filesystem::path root_;
  std::size_t max_file_bytes_;
  std::function<bool()> try_open_file_;
  std::map<std::filesystem::path, std::optional<LoadedFile>> loaded_files_;
  std::map<std::filesystem::path, std::unique_ptr<core::VariableTable>> tables_by_directory_;
  std::vector<core::Warning> warnings_;
};

}  // namespace bomwerk::parsers::lockfiles::msbuild
