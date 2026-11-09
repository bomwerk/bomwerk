#include "parsers/embedded/west.hpp"

#include <array>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/exclusions.hpp"
#include "core/git_url.hpp"
#include "core/manifest_walk.hpp"
#include "core/purl.hpp"
#include "core/submodule_paths.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"
#include "core/yaml_subset.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::embedded::west
{
namespace
{

constexpr std::array<std::string_view, 2> kWestManifestNames = {"west.yml", "west.yaml"};
constexpr std::string_view kProducerName = "west";

constexpr std::string_view kManifestKey = "manifest";
constexpr std::string_view kDefaultsKey = "defaults";
constexpr std::string_view kRemotesKey = "remotes";
constexpr std::string_view kProjectsKey = "projects";
constexpr std::string_view kSelfKey = "self";
constexpr std::string_view kNameKey = "name";
constexpr std::string_view kUrlKey = "url";
constexpr std::string_view kUrlBaseKey = "url-base";
constexpr std::string_view kRemoteKey = "remote";
constexpr std::string_view kRepoPathKey = "repo-path";
constexpr std::string_view kRevisionKey = "revision";
constexpr std::string_view kPathKey = "path";
constexpr std::string_view kImportKey = "import";

/// Stack depth of a node directly under `manifest:` and of a field inside one
/// of its sections (`defaults:`, a `remotes:` item, a `projects:` item).
constexpr std::size_t kManifestChildDepth = 1;
constexpr std::size_t kSectionFieldDepth = 2;

/// How many names a warning lists before it says "and N more".
constexpr std::size_t kMaxNamesInWarning = 10;

/// One enclosing block, by the indentation and key that opened it.
struct Frame
{
  std::size_t indentation = 0;
  std::string_view key;
};

struct Remote
{
  std::string_view name;
  std::string_view url_base;
};

struct Project
{
  std::string_view name;
  std::string_view url;
  std::string_view remote;
  std::string_view repo_path;
  std::string_view revision;
  std::string_view path;
  bool imports = false;
};

/// Everything one manifest declares, collected before anything is resolved:
/// west allows `defaults:` and `remotes:` after `projects:`.
struct Manifest
{
  bool found = false;
  std::string_view default_remote;
  std::string_view default_revision;
  std::vector<Remote> remotes;
  /// First remote of each name, built once `remotes` is complete (see
  /// `index_remotes`): a per-project linear search was O(projects x remotes).
  std::map<std::string_view, const Remote*, std::less<>> remote_by_name;
  std::vector<Project> projects;
  bool self_imports = false;
  std::size_t malformed = 0;
};

struct ResolveCounts
{
  std::vector<std::string> missing_source;
  std::vector<std::string> unpinned;
  std::vector<std::string> imports;
};

/// `import: false` is west's explicit "do not import"; every other value (true,
/// a path, a mapping) pulls in projects bomwerk does not follow.
bool import_value_pulls_projects(const core::yaml_subset::Node& node)
{
  return node.opens_block ||
         (node.value != "false" && node.value != "False" && !node.value.empty());
}

std::string names_for_warning(const std::vector<std::string>& names)
{
  std::string text;
  for (std::size_t index = 0; index < names.size() && index < kMaxNamesInWarning; ++index)
  {
    text += (index == 0 ? "'" : ", '") + names[index] + "'";
  }
  if (names.size() > kMaxNamesInWarning)
  {
    text += " and " + std::to_string(names.size() - kMaxNamesInWarning) + " more";
  }
  return text;
}

void read_remote_field(const core::yaml_subset::Node& node, Manifest& manifest)
{
  if (node.starts_sequence_item)
  {
    manifest.remotes.emplace_back();
  }
  else if (manifest.remotes.empty())
  {
    ++manifest.malformed;  // a field before any `- ` item
    return;
  }
  Remote& remote = manifest.remotes.back();
  if (node.key == kNameKey)
  {
    remote.name = node.value;
  }
  else if (node.key == kUrlBaseKey)
  {
    remote.url_base = node.value;
  }
  else if (node.key.empty() && !node.value.empty())
  {
    ++manifest.malformed;  // a bare `- scalar` where a mapping belongs
  }
}

void read_project_field(const core::yaml_subset::Node& node, Manifest& manifest)
{
  if (node.starts_sequence_item)
  {
    manifest.projects.emplace_back();
  }
  else if (manifest.projects.empty())
  {
    ++manifest.malformed;
    return;
  }
  Project& project = manifest.projects.back();
  if (node.key == kNameKey)
  {
    project.name = node.value;
  }
  else if (node.key == kUrlKey)
  {
    project.url = node.value;
  }
  else if (node.key == kRemoteKey)
  {
    project.remote = node.value;
  }
  else if (node.key == kRepoPathKey)
  {
    project.repo_path = node.value;
  }
  else if (node.key == kRevisionKey)
  {
    project.revision = node.value;
  }
  else if (node.key == kPathKey)
  {
    project.path = node.value;
  }
  else if (node.key == kImportKey)
  {
    project.imports = import_value_pulls_projects(node);
  }
  else if (node.key.empty() && !node.value.empty())
  {
    ++manifest.malformed;
  }
}

/// Route one node by the blocks that enclose it. Only `manifest.defaults`,
/// `manifest.remotes[]`, `manifest.projects[]` and `manifest.self.import` are
/// read; deeper blocks (an import's allowlists, `userdata`) are read past.
void read_node(const core::yaml_subset::Node& node, const std::vector<Frame>& stack,
               Manifest& manifest)
{
  if (stack.empty())
  {
    if (node.key == kManifestKey && node.opens_block)
    {
      manifest.found = true;
    }
    return;
  }
  if (stack.front().key != kManifestKey || stack.size() != kSectionFieldDepth)
  {
    return;
  }
  const std::string_view section = stack[kManifestChildDepth].key;
  if (section == kDefaultsKey)
  {
    if (node.key == kRemoteKey)
    {
      manifest.default_remote = node.value;
    }
    else if (node.key == kRevisionKey)
    {
      manifest.default_revision = node.value;
    }
  }
  else if (section == kRemotesKey)
  {
    read_remote_field(node, manifest);
  }
  else if (section == kProjectsKey)
  {
    read_project_field(node, manifest);
  }
  else if (section == kSelfKey && node.key == kImportKey)
  {
    manifest.self_imports = import_value_pulls_projects(node);
  }
}

Manifest read_manifest(std::string_view bytes, std::size_t& unsupported_line_count)
{
  core::yaml_subset::ReaderOptions reader_options;
  reader_options.sequence_items = true;
  core::yaml_subset::Reader reader(bytes, reader_options);
  core::yaml_subset::Node node;
  Manifest manifest;
  std::vector<Frame> stack;

  // Reader::next always advances its cursor, including over skipped hostile
  // lines, so this loop terminates on any input.
  while (reader.next(node))
  {
    while (!stack.empty() && stack.back().indentation >= node.indentation)
    {
      stack.pop_back();
    }
    read_node(node, stack, manifest);
    // A lone `-` opens its item's mapping, not a nested block: its fields
    // belong to the enclosing section, so it is never pushed.
    if (node.opens_block && !node.key.empty())
    {
      stack.push_back({node.indentation, node.key});
    }
  }
  unsupported_line_count = reader.stats().unsupported_line_count;
  return manifest;
}

/// Fill `remote_by_name` once `remotes` will no longer grow. `emplace` keeps
/// the first remote of a repeated name, as the earlier linear search did.
void index_remotes(Manifest& manifest)
{
  for (const Remote& remote : manifest.remotes)
  {
    manifest.remote_by_name.emplace(remote.name, &remote);
  }
}

const Remote* find_remote(const Manifest& manifest, std::string_view name)
{
  const auto found = manifest.remote_by_name.find(name);
  return found == manifest.remote_by_name.end() ? nullptr : found->second;
}

/// The project's clone url by west's rules, or empty when nothing resolves.
std::string resolve_url(const Manifest& manifest, const Project& project)
{
  if (!project.url.empty())
  {
    return std::string(project.url);
  }
  std::string_view remote_name = project.remote;
  if (remote_name.empty())
  {
    remote_name = manifest.default_remote;
  }
  if (remote_name.empty() && manifest.remotes.size() == 1)
  {
    remote_name = manifest.remotes.front().name;
  }
  const Remote* remote = remote_name.empty() ? nullptr : find_remote(manifest, remote_name);
  if (remote == nullptr || remote->url_base.empty())
  {
    return {};
  }
  std::string url(remote->url_base);
  while (!url.empty() && url.back() == '/')
  {
    url.pop_back();
  }
  url += '/';
  url += project.repo_path.empty() ? project.name : project.repo_path;
  return url;
}

/// The workspace top directory is the parent of the manifest repository, i.e.
/// two levels above `zephyr/west.yml`. Project paths are relative to it, so
/// they can be mapped into the scan only when that directory is inside it.
fs::path checkout_root(const std::string& manifest_label, const Project& project)
{
  const fs::path manifest_dir = fs::path(manifest_label).parent_path();
  if (manifest_dir.empty())
  {
    return {};  // the workspace top directory lies above the scan root
  }
  const std::string_view checkout = project.path.empty() ? project.name : project.path;
  const fs::path candidate = fs::path(std::string(checkout));
  // `path:` is attacker-controlled text: an absolute path, a `..` climb or a
  // bare `.` would make the project own files outside its checkout (or the
  // whole tree) when `observe` attributes compiled sources to it.
  if (candidate.is_absolute() || candidate.has_root_name())
  {
    return {};
  }
  const fs::path root = (manifest_dir.parent_path() / candidate).lexically_normal();
  if (root.empty() || root == "." || *root.begin() == "..")
  {
    return {};
  }
  return root;
}

core::Component build_component(const Project& project, const std::string& url,
                                const std::string& revision, const std::string& label,
                                core::Result<std::vector<core::Component>>& result)
{
  core::Component component;
  component.name = std::string(project.name);
  component.version = revision;
  component.supplier = core::parse_git_remote(url).owner;
  component.purl = core::build_git_purl(url, revision, component.name);
  component.root = checkout_root(label, project);
  core::Confidence confidence = core::Confidence::Medium;
  if (revision.empty())
  {
    confidence = core::Confidence::Low;
  }
  else if (core::is_hex_object_id(revision))
  {
    confidence = core::Confidence::High;
  }
  component.evidence.push_back(
      {core::Source::Manifest, label + " -> " + component.name, confidence});
  core::canonicalize_purl(component.purl, kProducerName, result.warnings);
  return component;
}

void warn_resolve_counts(const ResolveCounts& counts, const Manifest& manifest,
                         const std::string& label, std::size_t unsupported_line_count,
                         core::Result<std::vector<core::Component>>& result)
{
  const std::string producer(kProducerName);
  if (!counts.missing_source.empty())
  {
    result.warn(core::WarningCode::kDependencyMissingSource,
                "west: " + std::to_string(counts.missing_source.size()) +
                    " project(s) with no resolvable url or remote skipped (" +
                    names_for_warning(counts.missing_source) + "): " + label,
                producer, label);
  }
  if (!counts.unpinned.empty())
  {
    result.warn(core::WarningCode::kUnpinnedOrUnresolvedRef,
                "west: " + std::to_string(counts.unpinned.size()) +
                    " project(s) with no revision and no defaults.revision reported "
                    "without a version (" +
                    names_for_warning(counts.unpinned) + "): " + label,
                producer, label);
  }
  if (!counts.imports.empty() || manifest.self_imports)
  {
    std::vector<std::string> importers = counts.imports;
    if (manifest.self_imports)
    {
      importers.insert(importers.begin(), "self");
    }
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "west: import: not followed, projects it pulls in are not listed (from " +
                    names_for_warning(importers) + "): " + label,
                producer, label);
  }
  if (manifest.malformed > 0)
  {
    result.warn(
        core::WarningCode::kMalformedEntrySkipped,
        "west: " + std::to_string(manifest.malformed) + " malformed entrie(s) skipped: " + label,
        producer, label);
  }
  if (unsupported_line_count > 0)
  {
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "west: " + std::to_string(unsupported_line_count) +
                    " line(s) outside the readable YAML subset skipped: " + label,
                producer, label);
  }
}

void parse_west_manifest(const core::WalkedManifestFile& file, std::size_t project_limit,
                         std::size_t& project_budget, std::vector<core::Component>& components,
                         core::Result<std::vector<core::Component>>& result)
{
  std::size_t unsupported_line_count = 0;
  Manifest manifest = read_manifest(file.bytes, unsupported_line_count);
  if (!manifest.found)
  {
    return;  // a file named west.yml that is not a west manifest
  }
  index_remotes(manifest);

  ResolveCounts counts;
  for (const Project& project : manifest.projects)
  {
    if (project.name.empty())
    {
      ++manifest.malformed;
      continue;
    }
    // Reported before the url check: a project we cannot place still pulls
    // in projects we do not list, and that gap must be named.
    if (project.imports)
    {
      counts.imports.emplace_back(project.name);
    }
    const std::string url = resolve_url(manifest, project);
    if (url.empty())
    {
      counts.missing_source.emplace_back(project.name);
      continue;
    }
    const std::string revision(project.revision.empty() ? manifest.default_revision
                                                        : project.revision);
    if (revision.empty())
    {
      counts.unpinned.emplace_back(project.name);
    }
    if (project_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "west: project limit " + std::to_string(project_limit) +
                      " reached; remaining projects skipped",
                  std::string(kProducerName));
      result.complete = false;
      break;
    }
    --project_budget;
    components.push_back(build_component(project, url, revision, file.label, result));
  }
  warn_resolve_counts(counts, manifest, file.label, unsupported_line_count, result);
}

/// The one format this producer reads, under either of its names.
enum class ManifestKind
{
  kWestManifest,
};

/// Selects `west.yml` and `west.yaml`. A truncated prefix could drop the
/// `remotes:` or `defaults:` that later projects resolve against, so an
/// oversized manifest is skipped rather than half-read.
std::optional<core::ManifestMatch<ManifestKind>> manifest_kind(const fs::path& relative_path)
{
  const std::string_view file_name = core::file_name_of(relative_path);
  for (const std::string_view manifest_name : kWestManifestNames)
  {
    if (file_name == manifest_name)
    {
      return core::ManifestMatch<ManifestKind>{ManifestKind::kWestManifest,
                                               core::OversizedFilePolicy::kSkip};
    }
  }
  return std::nullopt;
}

/// State shared by every west manifest of one scan: one project budget for all.
struct ParseState
{
  std::vector<core::Component> components;
  std::size_t project_budget = 0;
};

core::ManifestWalkOptions walk_options_for(const ParseOptions& options)
{
  return core::make_walk_options(options, kProducerName, "west manifest");
}

void parse_manifest(ManifestKind /*kind*/, const core::WalkedManifestFile& file,
                    const ParseOptions& options, ParseState& state,
                    core::Result<std::vector<core::Component>>& result)
{
  parse_west_manifest(file, options.max_total_projects, state.project_budget, state.components,
                      result);
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
  state.project_budget = options.max_total_projects;
  core::for_each_manifest_file(
      file_index, root, walk_options_for(options), result.warnings, manifest_kind,
      [&] { return !result.complete; }, [&](ManifestKind kind, core::WalkedManifestFile&& file)
      { parse_manifest(kind, file, options, state, result); });
  return finish(std::move(state), std::move(result));
}

core::Result<std::vector<core::Component>> parse_bytes(std::string_view file_name,
                                                       std::string_view bytes,
                                                       const ParseOptions& options)
{
  core::Result<std::vector<core::Component>> result;
  ParseState state;
  state.project_budget = options.max_total_projects;
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

}  // namespace bomwerk::parsers::embedded::west
