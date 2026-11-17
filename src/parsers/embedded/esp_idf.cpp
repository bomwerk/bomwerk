#include "parsers/embedded/esp_idf.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/exclusions.hpp"
#include "core/file_index.hpp"
#include "core/git_url.hpp"
#include "core/manifest_names.hpp"
#include "core/manifest_walk.hpp"
#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/submodule_paths.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"
#include "core/yaml_subset.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::embedded::esp_idf
{
namespace
{

constexpr std::string_view kProducerName = "esp-idf";
constexpr std::string_view kLockName = "dependencies.lock";
constexpr std::string_view kManifestName = "idf_component.yml";
/// Where the component manager unpacks registry components. Each one carries
/// its own `idf_component.yml`, which is that component's declaration, not
/// this project's.
constexpr std::string_view kManagedComponentsDir = "managed_components";

/// The component manager's namespace for a name written without one.
constexpr std::string_view kDefaultNamespace = "espressif";
/// The framework pseudo-component, and the name it is reported under: NVD
/// files ESP-IDF as product `esp-idf`, which is what the CPE fallback builds
/// from the purl name.
constexpr std::string_view kIdfName = "idf";
constexpr std::string_view kIdfReportedName = "esp-idf";

constexpr std::string_view kDependenciesKey = "dependencies";
constexpr std::string_view kManifestHashKey = "manifest_hash";
constexpr std::string_view kVersionKey = "version";
constexpr std::string_view kComponentHashKey = "component_hash";
constexpr std::string_view kSourceKey = "source";
constexpr std::string_view kTypeKey = "type";
constexpr std::string_view kGitKey = "git";
constexpr std::string_view kPathKey = "path";
constexpr std::string_view kOverridePathKey = "override_path";
constexpr std::string_view kRegistryUrlKey = "registry_url";
constexpr std::string_view kServiceUrlKey = "service_url";
constexpr std::string_view kRulesKey = "rules";
constexpr std::string_view kMatchesKey = "matches";

constexpr std::string_view kSourceTypeRegistry = "service";
constexpr std::string_view kSourceTypeIdf = "idf";
constexpr std::string_view kSourceTypeGit = "git";
constexpr std::string_view kSourceTypeLocal = "local";

/// Lock format majors this reader knows: component manager 1.x writes
/// `version: 1.0.0`, 2.x writes `version: 2.0.0`.
constexpr std::array<std::string_view, 2> kSupportedLockMajors = {"1", "2"};

/// Hosts of Espressif's own registry (2.x `registry_url`, 1.x `service_url`).
/// A component from any other registry is noted in its evidence detail.
constexpr std::array<std::string_view, 2> kDefaultRegistryHosts = {"components.espressif.com",
                                                                   "api.components.espressif.com"};

/// A component manager `component_hash` is a SHA-256 in hex.
constexpr std::size_t kSha256HexLength = 64;

/// Stack positions: `dependencies` is frame 0, an entry is frame 1, and a lock
/// entry's `source` block is frame 2. A node's depth is the stack size.
constexpr std::size_t kEntryDepth = 1;
constexpr std::size_t kFieldDepth = 2;
constexpr std::size_t kSourceFieldDepth = 3;
constexpr std::size_t kEntryFrame = 1;
constexpr std::size_t kSourceFrame = 2;

/// How many names a warning lists before it says "and N more".
constexpr std::size_t kMaxNamesInWarning = 10;

/// The marker of an unexpanded variable, such as `${IDF_PATH}`.
constexpr std::string_view kVariableMarker = "${";

/// Sentinel for `EntryListGuard::item_indentation`: no list item is open.
constexpr std::size_t kNoListItem = static_cast<std::size_t>(-1);

/// One enclosing block, by the indentation and key that opened it.
struct Frame
{
  std::size_t indentation = 0;
  std::string_view key;
};

using Node = core::yaml_subset::Node;
using ComponentsResult = core::Result<std::vector<core::Component>>;

/// Both formats key `dependencies:` by name; a list there is malformed. A
/// `- name: x` item's following fields share its indentation, so without this
/// they would read as entries of their own (`version: "^3"` as a dependency
/// named `version`). The guard counts the item once and swallows its fields.
struct EntryListGuard
{
  std::size_t item_indentation = kNoListItem;

  /// True when `node`, at entry depth, is a list item or one of its fields:
  /// the caller must not read it as an entry. A new item counts as malformed.
  bool swallow(const Node& node, std::size_t& malformed)
  {
    if (node.starts_sequence_item)
    {
      item_indentation = node.indentation;
      ++malformed;
      return true;
    }
    if (node.indentation == item_indentation)
    {
      return true;
    }
    item_indentation = kNoListItem;
    return false;
  }
};

/// One `dependencies:` entry of a `dependencies.lock`.
struct LockEntry
{
  std::string_view name;
  std::string_view version;
  std::string_view component_hash;
  std::string_view source_type;
  std::string_view git_url;
  std::string_view repo_path;  ///< `source.path`: a subdirectory for git, a directory for local
  std::string_view registry_url;
};

struct LockFile
{
  bool has_dependencies = false;
  bool has_manifest_hash = false;
  std::string_view format_version;
  std::vector<LockEntry> entries;
  std::size_t malformed = 0;
  EntryListGuard list_guard;
};

/// One `dependencies:` entry of an `idf_component.yml`.
struct ManifestDependency
{
  std::string_view name;
  std::string_view constraint;
  std::string_view git_url;
  std::string_view repo_path;  ///< `path:`: a local directory, or a subdirectory with `git:`
  std::string_view registry_url;
  bool has_git = false;
  bool has_path = false;
  bool has_override_path = false;
  bool conditional = false;
};

struct ManifestFile
{
  std::vector<ManifestDependency> dependencies;
  std::size_t malformed = 0;
  EntryListGuard list_guard;
};

/// What one file could not report, gathered so each cause warns once per file.
struct FileCounts
{
  std::vector<std::string> unversioned;     ///< lock entries with no version
  std::vector<std::string> missing_source;  ///< git sources with no url
  std::vector<std::string> unpinned;        ///< manifest git sources with no version
  std::vector<std::string> unresolved;      ///< names or urls holding `${...}`
  std::size_t malformed = 0;
  std::size_t unsupported_lines = 0;
};

/// State shared by every file of one scan: one component budget for all.
struct ParseState
{
  std::vector<core::Component> components;
  std::size_t component_budget = 0;
};

// ---------------------------------------------------------------------------
// YAML reading
// ---------------------------------------------------------------------------

/// Walk `bytes` with the subset reader, handing each node and the blocks that
/// enclose it to `visit`. Returns the count of lines outside the subset.
template <typename Visit>
std::size_t walk_yaml(std::string_view bytes, Visit&& visit)
{
  core::yaml_subset::ReaderOptions reader_options;
  reader_options.sequence_items = true;  // nested `dependencies:` lists, `rules:`, `targets:`
  core::yaml_subset::Reader reader(bytes, reader_options);
  Node node;
  std::vector<Frame> stack;

  // Reader::next always advances its cursor, including over skipped hostile
  // lines, so this loop terminates on any input.
  while (reader.next(node))
  {
    while (!stack.empty() && stack.back().indentation >= node.indentation)
    {
      stack.pop_back();
    }
    visit(node, stack);
    // A lone `-` opens its item's mapping, not a nested block, so it is never
    // pushed.
    if (node.opens_block && !node.key.empty())
    {
      stack.push_back({node.indentation, node.key});
    }
  }
  return reader.stats().unsupported_line_count;
}

/// A scalar with one pair of surrounding quotes removed. The subset reader
/// unquotes a node's value, but not the fields inside a flow mapping.
std::string_view unquoted(std::string_view text)
{
  text = core::trimmed_view(text);
  if (text.size() >= 2 && (text.front() == '"' || text.front() == '\'') &&
      text.back() == text.front())
  {
    return text.substr(1, text.size() - 2);
  }
  return text;
}

/// Offset of the first `,` outside quotes in `text`, or `text.size()`.
std::size_t unquoted_comma_offset(std::string_view text)
{
  char open_quote = '\0';
  for (std::size_t index = 0; index < text.size(); ++index)
  {
    const char character = text[index];
    if (open_quote != '\0')
    {
      if (character == '\\' && open_quote == '"')
      {
        ++index;  // an escaped byte never closes the region
      }
      else if (character == open_quote)
      {
        open_quote = '\0';
      }
      continue;
    }
    if (character == '"' || character == '\'')
    {
      open_quote = character;
    }
    else if (character == ',')
    {
      return index;
    }
  }
  return text.size();
}

/// Call `visit(key, value)` for each `key: value` field of a flow mapping's
/// interior text (`Node::value` when `is_flow_mapping`). The split is
/// quote-aware, so a comma inside a quoted value is not a separator.
template <typename Visit>
void for_each_flow_field(std::string_view interior_text, Visit&& visit)
{
  std::size_t segment_start = 0;
  while (segment_start <= interior_text.size())
  {
    const std::string_view remaining = interior_text.substr(segment_start);
    const std::size_t comma = unquoted_comma_offset(remaining);
    const std::string_view segment = core::trimmed_view(remaining.substr(0, comma));
    segment_start += (comma == remaining.size()) ? remaining.size() + 1 : comma + 1;

    const std::size_t colon = segment.find(':');
    if (colon == std::string_view::npos)
    {
      continue;
    }
    visit(unquoted(segment.substr(0, colon)), unquoted(segment.substr(colon + 1)));
  }
}

void read_lock_source_field(std::string_view key, std::string_view value, LockEntry& entry)
{
  if (key == kTypeKey)
  {
    entry.source_type = value;
  }
  else if (key == kGitKey)
  {
    entry.git_url = value;
  }
  else if (key == kPathKey)
  {
    entry.repo_path = value;
  }
  else if (key == kRegistryUrlKey || key == kServiceUrlKey)
  {
    entry.registry_url = value;
  }
}

/// Route one lock node by the blocks that enclose it. Only the top-level keys,
/// each entry's `version`/`component_hash`, and its `source` fields are read;
/// an entry's own `dependencies:` list is read past.
void read_lock_node(const Node& node, const std::vector<Frame>& stack, LockFile& lock)
{
  if (stack.empty())
  {
    if (node.key == kDependenciesKey)
    {
      lock.has_dependencies = true;
    }
    else if (node.key == kManifestHashKey)
    {
      lock.has_manifest_hash = true;
    }
    else if (node.key == kVersionKey)
    {
      lock.format_version = node.value;
    }
    return;
  }
  if (stack.front().key != kDependenciesKey)
  {
    return;
  }
  if (stack.size() == kEntryDepth)
  {
    if (lock.list_guard.swallow(node, lock.malformed))
    {
      return;
    }
    if (node.opens_block && !node.key.empty())
    {
      LockEntry entry;
      entry.name = node.key;
      lock.entries.push_back(entry);
    }
    else
    {
      ++lock.malformed;  // a scalar, flow or list item where an entry mapping belongs
    }
    return;
  }
  // Fields belong to the last entry only while it is the block they sit in.
  if (lock.entries.empty() || stack[kEntryFrame].key != lock.entries.back().name)
  {
    return;
  }
  LockEntry& entry = lock.entries.back();
  if (stack.size() == kFieldDepth)
  {
    if (node.key == kVersionKey)
    {
      entry.version = node.value;
    }
    else if (node.key == kComponentHashKey)
    {
      entry.component_hash = node.value;
    }
    else if (node.key == kSourceKey && node.is_flow_mapping)
    {
      for_each_flow_field(node.value, [&entry](std::string_view key, std::string_view value)
                          { read_lock_source_field(key, value, entry); });
    }
    return;
  }
  if (stack.size() == kSourceFieldDepth && stack[kSourceFrame].key == kSourceKey &&
      !node.starts_sequence_item)
  {
    read_lock_source_field(node.key, node.value, entry);
  }
}

void read_dependency_field(std::string_view key, std::string_view value,
                           ManifestDependency& dependency)
{
  if (key == kVersionKey)
  {
    dependency.constraint = value;
  }
  else if (key == kGitKey)
  {
    dependency.has_git = true;
    dependency.git_url = value;
  }
  else if (key == kPathKey)
  {
    dependency.has_path = true;
    dependency.repo_path = value;
  }
  else if (key == kOverridePathKey)
  {
    dependency.has_override_path = true;
  }
  else if (key == kRulesKey || key == kMatchesKey)
  {
    dependency.conditional = true;
  }
  else if (key == kRegistryUrlKey || key == kServiceUrlKey)
  {
    dependency.registry_url = value;
  }
}

/// Route one manifest node. Only top-level `dependencies:` is read: each entry
/// is a scalar constraint, a flow mapping or a block of fields. `rules:` items
/// and every other top-level section are read past.
void read_manifest_node(const Node& node, const std::vector<Frame>& stack, ManifestFile& manifest)
{
  if (stack.empty())
  {
    if (node.key == kDependenciesKey && !node.opens_block && !node.value.empty() &&
        node.value != "{}")
    {
      ++manifest.malformed;  // a one-line `dependencies: {...}` is not read
    }
    return;
  }
  if (stack.front().key != kDependenciesKey)
  {
    return;
  }
  if (stack.size() == kEntryDepth)
  {
    if (manifest.list_guard.swallow(node, manifest.malformed))
    {
      return;
    }
    if (node.key.empty() || node.is_flow_sequence)
    {
      ++manifest.malformed;
      return;
    }
    ManifestDependency dependency;
    dependency.name = node.key;
    if (node.is_flow_mapping)
    {
      for_each_flow_field(node.value, [&dependency](std::string_view key, std::string_view value)
                          { read_dependency_field(key, value, dependency); });
    }
    else if (!node.opens_block)
    {
      dependency.constraint = node.value;
    }
    manifest.dependencies.push_back(dependency);
    return;
  }
  if (stack.size() == kFieldDepth && !manifest.dependencies.empty() &&
      stack[kEntryFrame].key == manifest.dependencies.back().name && !node.starts_sequence_item)
  {
    read_dependency_field(node.key, node.value, manifest.dependencies.back());
  }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

struct RegistryName
{
  std::string_view space;
  std::string_view name;
};

/// Split a registry component name into namespace and name. `idf` is the
/// framework; a bare name is in the default namespace; anything with an empty
/// part or a second `/` is not a registry name.
std::optional<RegistryName> split_registry_name(std::string_view full_name)
{
  if (full_name == kIdfName)
  {
    return RegistryName{kDefaultNamespace, kIdfReportedName};
  }
  const std::size_t slash = full_name.find('/');
  if (slash == std::string_view::npos)
  {
    return RegistryName{kDefaultNamespace, full_name};
  }
  const std::string_view space = full_name.substr(0, slash);
  const std::string_view name = full_name.substr(slash + 1);
  if (space.empty() || name.empty() || name.find('/') != std::string_view::npos)
  {
    return std::nullopt;
  }
  return RegistryName{space, name};
}

std::string registry_purl(const RegistryName& registry_name, std::string_view version)
{
  std::string purl = "pkg:generic/" + core::percent_encode(registry_name.space) + "/" +
                     core::percent_encode(registry_name.name);
  if (!version.empty())
  {
    purl += "@" + core::percent_encode(version);
  }
  return purl;
}

/// A repository-relative `path:` as a purl subpath: empty and `.` segments
/// dropped, each kept segment percent-encoded. A path that climbs with `..`
/// claims nothing and yields no subpath.
std::string purl_subpath(std::string_view repo_path)
{
  std::string subpath;
  std::size_t start = 0;
  while (start <= repo_path.size())
  {
    std::size_t slash = repo_path.find('/', start);
    if (slash == std::string_view::npos)
    {
      slash = repo_path.size();
    }
    const std::string_view segment = repo_path.substr(start, slash - start);
    if (segment == "..")
    {
      return {};
    }
    if (!segment.empty() && segment != ".")
    {
      if (!subpath.empty())
      {
        subpath += '/';
      }
      subpath += core::percent_encode(segment);
    }
    start = slash + 1;
  }
  return subpath;
}

/// The lower-cased host of an `https://host[:port]/path` registry url, or
/// empty when there is no `://`.
std::string url_host(std::string_view url)
{
  const std::size_t scheme_end = url.find("://");
  if (scheme_end == std::string_view::npos)
  {
    return {};
  }
  std::string_view authority = url.substr(scheme_end + 3);
  authority = authority.substr(0, authority.find_first_of("/?#"));
  const std::size_t userinfo_end = authority.rfind('@');
  if (userinfo_end != std::string_view::npos)
  {
    authority.remove_prefix(userinfo_end + 1);
  }
  return core::to_lower_ascii(authority.substr(0, authority.find(':')));
}

bool is_default_registry(std::string_view registry_url)
{
  if (registry_url.empty())
  {
    return true;
  }
  const std::string host = url_host(registry_url);
  return std::find(kDefaultRegistryHosts.begin(), kDefaultRegistryHosts.end(), host) !=
         kDefaultRegistryHosts.end();
}

bool has_variable(std::string_view text)
{
  return text.find(kVariableMarker) != std::string_view::npos;
}

/// The SHA-256 a lock records for a component, lower-cased, or empty when the
/// value is `null` or not 64 hex digits.
std::string component_sha256(std::string_view component_hash)
{
  if (component_hash.size() != kSha256HexLength || !core::is_hex_digits(component_hash))
  {
    return {};
  }
  return core::to_lower_ascii(component_hash);
}

/// Take one unit of the scan's component budget, or warn once and mark the
/// result incomplete when it is spent.
bool reserve_component(ParseState& state, std::size_t component_limit, ComponentsResult& result)
{
  if (state.component_budget == 0)
  {
    result.warn(core::WarningCode::kEntryLimitReached,
                "esp-idf: component limit " + std::to_string(component_limit) +
                    " reached; remaining entries skipped",
                std::string(kProducerName));
    result.complete = false;
    return false;
  }
  --state.component_budget;
  return true;
}

void push_component(core::Component component, std::string detail, core::Confidence confidence,
                    ParseState& state, ComponentsResult& result)
{
  component.evidence.push_back({core::Source::Manifest, std::move(detail), confidence});
  core::canonicalize_purl(component.purl, kProducerName, result.warnings);
  state.components.push_back(std::move(component));
}

core::Component registry_component(const RegistryName& registry_name, std::string_view version)
{
  core::Component component;
  component.name = std::string(registry_name.name);
  component.supplier = std::string(registry_name.space);
  component.version = std::string(version);
  component.purl = registry_purl(registry_name, version);
  return component;
}

/// A git-sourced component, named by the last segment of its dependency name
/// (`espressif/mdns` -> `mdns`); the supplier comes from the url. `version` is
/// a commit, tag or branch, or empty.
core::Component git_component(std::string_view name, std::string_view url, std::string_view version,
                              std::string_view repo_path)
{
  core::Component component;
  const std::size_t slash = name.rfind('/');
  component.name = std::string(
      slash == std::string_view::npos || slash + 1 == name.size() ? name : name.substr(slash + 1));
  component.version = core::normalized_object_id(version);
  component.supplier = core::parse_git_remote(std::string(url)).owner;
  component.purl = core::build_git_purl(std::string(url), component.version, component.name);
  const std::string subpath = purl_subpath(repo_path);
  if (!subpath.empty())
  {
    component.purl += "#" + subpath;
  }
  return component;
}

core::Confidence git_confidence(std::string_view version)
{
  if (version.empty())
  {
    return core::Confidence::Low;
  }
  return core::is_hex_object_id(version) ? core::Confidence::High : core::Confidence::Medium;
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

std::string names_for_warning(const std::vector<std::string>& names)
{
  std::string text;
  for (std::size_t index = 0; index < names.size() && index < kMaxNamesInWarning; ++index)
  {
    text += (index == 0 ? "'" : ", '") + core::escaped_for_diagnostic(names[index]) + "'";
  }
  if (names.size() > kMaxNamesInWarning)
  {
    text += " and " + std::to_string(names.size() - kMaxNamesInWarning) + " more";
  }
  return text;
}

void warn_file_counts(const FileCounts& counts, const std::string& label, ComponentsResult& result)
{
  const std::string producer(kProducerName);
  if (!counts.unversioned.empty())
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "esp-idf: " + std::to_string(counts.unversioned.size()) +
                    " lock entrie(s) with no version skipped (" +
                    names_for_warning(counts.unversioned) + "): " + label,
                producer, label);
  }
  if (!counts.missing_source.empty())
  {
    result.warn(core::WarningCode::kDependencyMissingSource,
                "esp-idf: " + std::to_string(counts.missing_source.size()) +
                    " git dependencie(s) with no url skipped (" +
                    names_for_warning(counts.missing_source) + "): " + label,
                producer, label);
  }
  if (!counts.unpinned.empty())
  {
    result.warn(core::WarningCode::kUnpinnedOrUnresolvedRef,
                "esp-idf: " + std::to_string(counts.unpinned.size()) +
                    " git dependencie(s) with no version reported without one (" +
                    names_for_warning(counts.unpinned) + "): " + label,
                producer, label);
  }
  if (!counts.unresolved.empty())
  {
    result.warn(core::WarningCode::kUnresolvedVariableOrInterpolation,
                "esp-idf: " + std::to_string(counts.unresolved.size()) +
                    " dependencie(s) naming an unexpanded ${...} variable skipped (" +
                    names_for_warning(counts.unresolved) + "): " + label,
                producer, label);
  }
  if (counts.malformed > 0)
  {
    result.warn(
        core::WarningCode::kMalformedEntrySkipped,
        "esp-idf: " + std::to_string(counts.malformed) + " malformed entrie(s) skipped: " + label,
        producer, label);
  }
  if (counts.unsupported_lines > 0)
  {
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "esp-idf: " + std::to_string(counts.unsupported_lines) +
                    " line(s) outside the readable YAML subset skipped: " + label,
                producer, label);
  }
}

bool lock_format_supported(std::string_view format_version)
{
  if (format_version.empty())
  {
    return true;  // the structure already proved it is a component manager lock
  }
  const std::string_view major = format_version.substr(0, format_version.find('.'));
  return std::find(kSupportedLockMajors.begin(), kSupportedLockMajors.end(), major) !=
         kSupportedLockMajors.end();
}

/// Emit one lock entry. Returns false once the component budget is spent.
bool emit_lock_entry(const LockEntry& entry, const std::string& label, std::size_t component_limit,
                     FileCounts& counts, ParseState& state, ComponentsResult& result)
{
  const std::string full_name(entry.name);
  if (entry.source_type == kSourceTypeLocal)
  {
    return true;  // part of the project itself, not a dependency
  }
  if (has_variable(entry.name) || has_variable(entry.git_url))
  {
    counts.unresolved.push_back(full_name);
    return true;
  }
  const bool is_git = entry.source_type == kSourceTypeGit;
  const bool is_registry =
      entry.source_type == kSourceTypeRegistry || entry.source_type == kSourceTypeIdf;
  if (!is_git && !is_registry)
  {
    ++counts.malformed;  // no source, or a source type this reader does not know
    return true;
  }
  if (entry.version.empty())
  {
    counts.unversioned.push_back(full_name);
    return true;
  }
  if (is_git && entry.git_url.empty())
  {
    counts.missing_source.push_back(full_name);
    return true;
  }
  std::optional<RegistryName> registry_name;
  if (is_registry)
  {
    registry_name =
        split_registry_name(entry.source_type == kSourceTypeIdf ? kIdfName : entry.name);
    if (!registry_name.has_value())
    {
      ++counts.malformed;
      return true;
    }
  }
  if (!reserve_component(state, component_limit, result))
  {
    return false;
  }

  std::string detail = label + " -> " + full_name;
  if (is_git)
  {
    push_component(git_component(entry.name, entry.git_url, entry.version, entry.repo_path),
                   std::move(detail), git_confidence(entry.version), state, result);
    return true;
  }
  if (!is_default_registry(entry.registry_url))
  {
    detail += " (registry " + core::escaped_for_diagnostic(entry.registry_url) + ")";
  }
  core::Component component = registry_component(*registry_name, entry.version);
  component.sha256 = component_sha256(entry.component_hash);
  push_component(std::move(component), std::move(detail), core::Confidence::High, state, result);
  return true;
}

void parse_lock(const core::WalkedManifestFile& file, std::size_t component_limit,
                ParseState& state, ComponentsResult& result)
{
  LockFile lock;
  FileCounts counts;
  counts.unsupported_lines = walk_yaml(file.bytes, [&lock](const Node& node, const auto& stack)
                                       { read_lock_node(node, stack, lock); });
  if (!lock.has_dependencies || !lock.has_manifest_hash)
  {
    return;  // a file named dependencies.lock that the component manager did not write
  }
  if (!lock_format_supported(lock.format_version))
  {
    result.warn(core::WarningCode::kLockfileFormatUnsupported,
                "esp-idf: dependencies.lock format version '" +
                    core::escaped_for_diagnostic(lock.format_version) +
                    "' is not supported (1.x and 2.x are read); file skipped: " + file.label,
                std::string(kProducerName), file.label);
    return;
  }
  counts.malformed = lock.malformed;
  for (const LockEntry& entry : lock.entries)
  {
    if (!emit_lock_entry(entry, file.label, component_limit, counts, state, result))
    {
      break;
    }
  }
  warn_file_counts(counts, file.label, result);
}

/// The evidence detail of a declared dependency: the constraint is recorded
/// here, never as a version, together with whether a `rules:`/`matches:`
/// condition gates it.
std::string declared_detail(const std::string& label, const ManifestDependency& dependency)
{
  std::string detail = label + " -> " + std::string(dependency.name);
  std::string notes;
  if (!dependency.constraint.empty())
  {
    notes = "requires " + std::string(dependency.constraint);
  }
  if (dependency.conditional)
  {
    notes += notes.empty() ? "conditional" : ", conditional";
  }
  if (!is_default_registry(dependency.registry_url))
  {
    notes += (notes.empty() ? "registry " : ", registry ") +
             core::escaped_for_diagnostic(dependency.registry_url);
  }
  if (!notes.empty())
  {
    detail += " (" + notes + ")";
  }
  return detail;
}

/// Emit one manifest dependency. Returns false once the component budget is
/// spent.
bool emit_manifest_dependency(const ManifestDependency& dependency, const std::string& label,
                              std::size_t component_limit, FileCounts& counts, ParseState& state,
                              ComponentsResult& result)
{
  const std::string full_name(dependency.name);
  if (!dependency.has_git && (dependency.has_path || dependency.has_override_path))
  {
    return true;  // a local component: part of the project itself
  }
  if (has_variable(dependency.name) || has_variable(dependency.git_url))
  {
    counts.unresolved.push_back(full_name);
    return true;
  }
  if (dependency.has_git)
  {
    if (dependency.git_url.empty())
    {
      counts.missing_source.push_back(full_name);
      return true;
    }
    // For a git source `version:` names a commit, tag or branch: a reference,
    // not a range. `*` asks for the default branch, which pins nothing.
    const std::string_view version =
        dependency.constraint == "*" ? std::string_view{} : dependency.constraint;
    if (version.empty())
    {
      counts.unpinned.push_back(full_name);
    }
    if (!reserve_component(state, component_limit, result))
    {
      return false;
    }
    push_component(
        git_component(dependency.name, dependency.git_url, version, dependency.repo_path),
        label + " -> " + full_name, git_confidence(version), state, result);
    return true;
  }
  const std::optional<RegistryName> registry_name = split_registry_name(dependency.name);
  if (!registry_name.has_value())
  {
    ++counts.malformed;
    return true;
  }
  if (!reserve_component(state, component_limit, result))
  {
    return false;
  }
  // A declaration, not a resolution: Medium with no version, the constraint
  // kept in the evidence detail (composer.json's rule).
  push_component(registry_component(*registry_name, {}), declared_detail(label, dependency),
                 core::Confidence::Medium, state, result);
  return true;
}

void parse_manifest(const core::WalkedManifestFile& file, std::size_t component_limit,
                    ParseState& state, ComponentsResult& result)
{
  ManifestFile manifest;
  FileCounts counts;
  counts.unsupported_lines = walk_yaml(file.bytes, [&manifest](const Node& node, const auto& stack)
                                       { read_manifest_node(node, stack, manifest); });
  counts.malformed = manifest.malformed;
  for (const ManifestDependency& dependency : manifest.dependencies)
  {
    if (!emit_manifest_dependency(dependency, file.label, component_limit, counts, state, result))
    {
      break;
    }
  }
  warn_file_counts(counts, file.label, result);
}

/// A purl without its version, keeping its qualifiers and subpath: what a
/// version-less declaration and a locked version of the same component share.
/// The `vcs_url` qualifier stays, so two `pkg:generic` git components of one
/// name from different repositories are never taken for each other.
std::string versionless_identity(std::string_view purl)
{
  const std::size_t extras = purl.find_first_of("?#");
  const std::string_view path = purl.substr(0, extras);
  const std::string_view tail =
      extras == std::string_view::npos ? std::string_view{} : purl.substr(extras);
  const std::size_t last_slash = path.rfind('/');
  const std::size_t at = path.find('@', last_slash == std::string_view::npos ? 0 : last_slash);
  return std::string(path.substr(0, at)) + std::string(tail);
}

/// Drop a version-less component when the scan also holds the same identity
/// with a version: a lock in one project resolved what a lockless manifest
/// elsewhere only declares, and listing both would count it twice.
void drop_versionless_shadowed_by_versioned(std::vector<core::Component>& components)
{
  std::set<std::string> versioned;
  for (const core::Component& component : components)
  {
    if (!component.version.empty())
    {
      versioned.insert(versionless_identity(component.purl));
    }
  }
  std::erase_if(components,
                [&versioned](const core::Component& component) {
                  return component.version.empty() &&
                         versioned.contains(versionless_identity(component.purl));
                });
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

enum class FileKind
{
  kLock,
  kManifest,
};

/// True for a file the component manager unpacked or a package manager
/// installed: someone else's declaration, never this project's.
bool is_installed_copy(const fs::path& relative_path)
{
  for (const fs::path& segment : relative_path.parent_path())
  {
    if (segment.generic_string() == kManagedComponentsDir)
    {
      return true;
    }
  }
  return core::is_inside_installed_dependencies(relative_path);
}

/// The directories holding a `dependencies.lock`. Built from the file index
/// alone, before any file is read, so a lock that sorts after a manifest it
/// covers (`components/` < `dependencies.lock`) still covers it.
std::set<fs::path> lock_directories(const core::FileIndex& file_index)
{
  std::set<fs::path> directories;
  for (const fs::path& relative_path : file_index.files)
  {
    if (core::file_name_of(relative_path) == kLockName && !is_installed_copy(relative_path))
    {
      directories.insert(relative_path.parent_path());
    }
  }
  return directories;
}

/// True when a lock sits in the manifest's directory or any directory above it.
bool covered_by_lock(const fs::path& relative_path, const std::set<fs::path>& locked_directories)
{
  if (locked_directories.empty())
  {
    return false;
  }
  fs::path directory = relative_path.parent_path();
  while (true)
  {
    if (locked_directories.contains(directory))
    {
      return true;
    }
    if (directory.empty())
    {
      return false;
    }
    fs::path parent = directory.parent_path();
    if (parent == directory)
    {
      return false;
    }
    directory = std::move(parent);
  }
}

/// Selects locks, and manifests no lock covers. Both skips are silent and come
/// before the file budget is charged. A truncated YAML document could lose
/// the keys that identify it, so oversized files are skipped.
std::optional<core::ManifestMatch<FileKind>> file_kind(const fs::path& relative_path,
                                                       const std::set<fs::path>& locked_directories)
{
  const std::string_view file_name = core::file_name_of(relative_path);
  if ((file_name != kLockName && file_name != kManifestName) || is_installed_copy(relative_path))
  {
    return std::nullopt;
  }
  if (file_name == kLockName)
  {
    return core::ManifestMatch<FileKind>{FileKind::kLock, core::OversizedFilePolicy::kSkip};
  }
  if (covered_by_lock(relative_path, locked_directories))
  {
    return std::nullopt;
  }
  return core::ManifestMatch<FileKind>{FileKind::kManifest, core::OversizedFilePolicy::kSkip};
}

core::ManifestWalkOptions walk_options_for(const ParseOptions& options)
{
  return core::make_walk_options(options, kProducerName, "ESP-IDF component file");
}

void parse_file(FileKind kind, const core::WalkedManifestFile& file, const ParseOptions& options,
                ParseState& state, ComponentsResult& result)
{
  switch (kind)
  {
    case FileKind::kLock:
      parse_lock(file, options.max_total_components, state, result);
      return;
    case FileKind::kManifest:
      parse_manifest(file, options.max_total_components, state, result);
      return;
  }
}

ComponentsResult finish(ParseState state, ComponentsResult result)
{
  // After every file is read, so a lock in one project can shadow a lockless
  // manifest in another; before the merge, so survivors dedupe and order by
  // purl.
  drop_versionless_shadowed_by_versioned(state.components);
  result.value = core::merge_all(std::move(state.components));
  return result;
}

}  // namespace

core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                 const fs::path& root, const ParseOptions& options)
{
  ComponentsResult result;
  ParseState state;
  state.component_budget = options.max_total_components;
  const std::set<fs::path> locked_directories = lock_directories(file_index);
  core::for_each_manifest_file(
      file_index, root, walk_options_for(options), result.warnings,
      [&](const fs::path& path) { return file_kind(path, locked_directories); },
      [&] { return !result.complete; }, [&](FileKind kind, core::WalkedManifestFile&& file)
      { parse_file(kind, file, options, state, result); });
  return finish(std::move(state), std::move(result));
}

core::Result<std::vector<core::Component>> parse_bytes(std::string_view file_name,
                                                       std::string_view bytes,
                                                       const ParseOptions& options)
{
  ComponentsResult result;
  ParseState state;
  state.component_budget = options.max_total_components;
  core::for_manifest_bytes(
      file_name, bytes, options.max_file_bytes, kProducerName, result.warnings,
      [](const fs::path& path) { return file_kind(path, {}); },
      [&](FileKind kind, core::WalkedManifestFile&& file)
      { parse_file(kind, file, options, state, result); });
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

}  // namespace bomwerk::parsers::embedded::esp_idf
