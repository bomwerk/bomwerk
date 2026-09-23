#include "core/manifest_names.hpp"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <utility>

#include "core/name_list.hpp"

namespace fs = std::filesystem;

namespace bomwerk::core
{
namespace
{

constexpr std::string_view kRequirementsManifestName = "requirements.txt";
constexpr std::string_view kTextFileExtension = ".txt";

/// `.csproj` files are named after the project (`MyApp.csproj`,
/// `Foo.Bar.csproj`, ...), not a fixed literal like every other table entry,
/// so this manifest name is matched by extension rather than exact filename.
constexpr std::string_view kCsprojManifestName = ".csproj";

/// Prefix-position family markers: "requirements<separator><qualifier>.txt".
/// Add a new literal here (not new branching in matches_manifest_name) when a
/// future round finds another prefix-position convention.
constexpr std::string_view kRequirementsPrefixFamilyMarkers[] = {"requirements-", "requirements_",
                                                                 "requirements."};

/// Suffix-position family markers: "<qualifier><marker>", where the marker
/// itself already ends in ".txt". Scoped to the dot convention alone --
/// "driver.requirements.txt", "ci.requirements.txt" -- deliberately NOT
/// hyphen/underscore ("dev-requirements.txt" stays unmatched; see the
/// negative test below). Add a new literal here for a future suffix convention.
constexpr std::string_view kRequirementsSuffixFamilyMarkers[] = {".requirements.txt"};

/// True when `directory` itself, or any directory above it, is in
/// `covered_directories`. Paths are root-relative, so walking `parent_path()`
/// upward terminates at the empty path, which is the scanned root itself.
bool has_covered_ancestor(const fs::path& directory, const std::set<fs::path>& covered_directories)
{
  fs::path candidate_directory = directory;
  while (true)
  {
    if (covered_directories.contains(candidate_directory))
    {
      return true;
    }
    if (candidate_directory.empty())
    {
      return false;
    }
    candidate_directory = candidate_directory.parent_path();
  }
}

/// Directories holding INSTALLED third-party trees. A manifest inside one
/// belongs to a dependency, not to the scanned project, so reporting it would
/// blame the operator for someone else's file: and an installed tree carries
/// thousands of them. The scan walk itself does not skip these names (see
/// `default_excluded_dir_names`, which deliberately avoids collision-prone
/// directory names), so this reporting path filters them for itself.
constexpr std::string_view kInstalledDependencyDirNames[] = {"node_modules", "vendor", "venv",
                                                             ".venv", "bower_components"};

/// True when any component of `relative_path` names an installed dependency
/// tree.
bool is_inside_installed_dependencies(const fs::path& relative_path)
{
  for (const fs::path& path_component : relative_path)
  {
    const std::string component_name = path_component.string();
    const bool is_dependency_directory = std::any_of(
        std::begin(kInstalledDependencyDirNames), std::end(kInstalledDependencyDirNames),
        [&component_name](std::string_view name) { return name == component_name; });
    if (is_dependency_directory)
    {
      return true;
    }
  }
  return false;
}

/// Every path in `files` whose filename is one of `names`, skipping installed
/// dependency trees. `files` is already sorted, so filtering it preserves that
/// order (rule 3).
std::vector<fs::path> matching_paths(const std::vector<fs::path>& files,
                                     const std::vector<std::string_view>& names)
{
  std::vector<fs::path> matches;
  for (const fs::path& relative_path : files)
  {
    const std::string filename = relative_path.filename().string();
    const bool is_match = std::any_of(names.begin(), names.end(), [&filename](std::string_view name)
                                      { return matches_manifest_name(filename, name); });
    if (is_match && !is_inside_installed_dependencies(relative_path))
    {
      matches.push_back(relative_path);
    }
  }
  return matches;
}

/// The single finding for one tier of `ecosystem`'s manifests, or nullopt when
/// every candidate is already covered by a supported lockfile at or above it.
/// When several filenames in the tier are present, the most frequent one wins
/// (ties broken alphabetically), so the sentence names the manifest that
/// dominates the repo and two runs over the same tree always name the same one.
std::optional<UnparsedManifestReport> report_for_tier(
    const std::vector<fs::path>& files, const EcosystemManifests& ecosystem,
    const std::vector<std::string_view>& tier_names, const std::set<fs::path>& covered_directories,
    bool is_lockfile)
{
  std::map<std::string, std::vector<fs::path>> paths_by_filename;
  for (const fs::path& candidate_path : matching_paths(files, tier_names))
  {
    if (has_covered_ancestor(candidate_path.parent_path(), covered_directories))
    {
      continue;
    }
    paths_by_filename[candidate_path.filename().string()].push_back(candidate_path);
  }
  if (paths_by_filename.empty())
  {
    return std::nullopt;
  }

  // std::map iterates alphabetically and the comparison is strictly greater,
  // so an alphabetical tie keeps the first filename seen.
  const std::pair<const std::string, std::vector<fs::path>>* winning_entry =
      &*paths_by_filename.begin();
  for (const std::pair<const std::string, std::vector<fs::path>>& entry : paths_by_filename)
  {
    if (entry.second.size() > winning_entry->second.size())
    {
      winning_entry = &entry;
    }
  }

  UnparsedManifestReport report;
  report.ecosystem = std::string(ecosystem.ecosystem);
  report.filename = winning_entry->first;
  report.paths = winning_entry->second;
  report.is_lockfile = is_lockfile;
  return report;
}

}  // namespace

bool matches_manifest_name(std::string_view actual_filename, std::string_view manifest_name)
{
  if (actual_filename == manifest_name)
  {
    return true;
  }
  if (manifest_name == kCsprojManifestName)
  {
    return actual_filename.size() > kCsprojManifestName.size() &&
           actual_filename.ends_with(kCsprojManifestName);
  }
  if (manifest_name != kRequirementsManifestName)
  {
    return false;
  }

  for (const std::string_view prefix_marker : kRequirementsPrefixFamilyMarkers)
  {
    const bool has_non_empty_qualifier =
        actual_filename.size() > prefix_marker.size() + kTextFileExtension.size();
    if (actual_filename.starts_with(prefix_marker) && has_non_empty_qualifier &&
        actual_filename.ends_with(kTextFileExtension))
    {
      return true;
    }
  }
  for (const std::string_view suffix_marker : kRequirementsSuffixFamilyMarkers)
  {
    if (actual_filename.ends_with(suffix_marker) && actual_filename.size() > suffix_marker.size())
    {
      return true;
    }
  }
  return false;
}

const std::set<std::string>& default_manifest_names()
{
  static const std::set<std::string> kDefaultNames = {".gitmodules",
                                                      "CMakeLists.txt",
                                                      "conanfile.txt",
                                                      "conanfile.py",
                                                      "conan.lock",
                                                      "vcpkg.json",
                                                      "package-lock.json",
                                                      "go.sum",
                                                      "Cargo.lock",
                                                      "requirements.txt",
                                                      "pom.xml",
                                                      "uv.lock",
                                                      "poetry.lock",
                                                      "gradle.lockfile",
                                                      "packages.lock.json",
                                                      "composer.lock",
                                                      "Gemfile.lock",
                                                      "yarn.lock",
                                                      "pnpm-lock.yaml",
                                                      "pubspec.lock",
                                                      "packages.config",
                                                      ".csproj",
                                                      "Directory.Packages.props"};
  return kDefaultNames;
}

Result<std::set<std::string>> load_manifest_names(const std::filesystem::path& list_path)
{
  return load_name_list(list_path, "manifest list", default_manifest_names());
}

const std::vector<EcosystemManifests>& ecosystem_manifests()
{
  // Ordered by ecosystem name so `find_unparsed_manifests` reports in a stable
  // order without depending on this table's layout.
  static const std::vector<EcosystemManifests> kEcosystemManifests = {
      {"cargo", {"Cargo.lock"}, {}, {"Cargo.toml"}},
      {"composer", {"composer.lock"}, {}, {"composer.json"}},
      {"go", {"go.sum"}, {}, {"go.mod"}},
      {"maven", {"pom.xml", "gradle.lockfile"}, {}, {"build.gradle", "build.gradle.kts"}},
      {"npm",
       {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
       {"bun.lock", "bun.lockb", "npm-shrinkwrap.json"},
       {"package.json"}},
      {"nuget",
       {"packages.lock.json", "packages.config", ".csproj", "Directory.Packages.props"},
       {},
       {}},
      {"pub", {"pubspec.lock"}, {}, {"pubspec.yaml"}},
      {"python",
       {"poetry.lock", "requirements.txt", "uv.lock"},
       {"Pipfile.lock"},
       {"Pipfile", "pyproject.toml"}},
      {"rubygems", {"Gemfile.lock"}, {}, {"Gemfile"}}};
  return kEcosystemManifests;
}

std::vector<UnparsedManifestReport> find_unparsed_manifests(const std::vector<fs::path>& files)
{
  std::vector<UnparsedManifestReport> reports;
  for (const EcosystemManifests& ecosystem : ecosystem_manifests())
  {
    std::set<fs::path> covered_directories;
    for (const fs::path& supported_path : matching_paths(files, ecosystem.supported_locks))
    {
      covered_directories.insert(supported_path.parent_path());
    }

    // A real lockfile bomwerk cannot read outranks a loose manifest: a repo
    // holding both yarn.lock and package.json has one gap to report, not two.
    std::optional<UnparsedManifestReport> report =
        report_for_tier(files, ecosystem, ecosystem.unsupported_locks, covered_directories, true);
    if (!report.has_value())
    {
      report =
          report_for_tier(files, ecosystem, ecosystem.loose_manifests, covered_directories, false);
    }
    if (report.has_value())
    {
      reports.push_back(std::move(*report));
    }
  }

  std::sort(reports.begin(), reports.end(),
            [](const UnparsedManifestReport& left, const UnparsedManifestReport& right)
            { return left.ecosystem < right.ecosystem; });
  return reports;
}

}  // namespace bomwerk::core
