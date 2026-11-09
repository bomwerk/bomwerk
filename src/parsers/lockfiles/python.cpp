#include "parsers/lockfiles/python.hpp"

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
#include "core/manifest_names.hpp"
#include "core/manifest_walk.hpp"
#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/submodule_paths.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::lockfiles::python
{
namespace
{

constexpr std::string_view kProducerName = "python";
constexpr std::string_view kUvLockName = "uv.lock";
constexpr std::string_view kPoetryLockName = "poetry.lock";
constexpr std::string_view kRequirementsName = "requirements.txt";

/// The poetry dependency group every runtime dependency belongs to; a package
/// whose groups lack it is dev-only tooling.
constexpr std::string_view kPoetryMainGroup = "main";

/// PEP 503 name normalization: lower-case, runs of `-`/`_`/`.` collapse to a
/// single `-`. This is the identity pypi itself uses, so a `Flask` in
/// requirements.txt and a `flask` in uv.lock merge to one purl.
std::string normalize_pypi_name(std::string_view declared_name)
{
  std::string normalized;
  normalized.reserve(declared_name.size());
  bool previous_was_separator = false;
  for (const char character : declared_name)
  {
    if (character == '-' || character == '_' || character == '.')
    {
      previous_was_separator = true;
      continue;
    }
    if (previous_was_separator)
    {
      normalized.push_back('-');
      previous_was_separator = false;
    }
    normalized.push_back(core::to_lower_ascii(character));
  }
  return normalized;
}

/// Build the `pkg:pypi` purl from an already-normalized name; an empty
/// version yields a version-less purl (declared-but-unresolved requirement).
std::string build_pypi_purl(const std::string& normalized_name, const std::string& version)
{
  std::string purl = "pkg:pypi/" + core::percent_encode(normalized_name);
  if (!version.empty())
  {
    purl += "@" + core::percent_encode(version);
  }
  return purl;
}

/// Append one lock entry as a High-confidence component. `declared_name` keeps
/// its original spelling in the evidence detail when normalization changed it.
void emit_lock_component(std::string_view declared_name, std::string_view version,
                         core::Scope scope, const std::string& label,
                         std::vector<core::Component>& components,
                         core::Result<std::vector<core::Component>>& result)
{
  core::Component component;
  component.name = normalize_pypi_name(declared_name);
  component.version = core::trimmed(version);
  component.purl = build_pypi_purl(component.name, component.version);
  component.scope = scope;

  std::string detail = label;
  if (component.name != declared_name)
  {
    detail += " declared=" + std::string(declared_name);
  }
  // Lock entries are the resolver's own output -> High.
  component.evidence.push_back({core::Source::Manifest, detail, core::Confidence::High});

  core::canonicalize_purl(component.purl, kProducerName, result.warnings);
  components.push_back(std::move(component));
}

/// Parse the shared TOML shell of uv.lock/poetry.lock. vcpkg's tomlplusplus
/// port ships a precompiled, exceptions-enabled library (see CMakeLists.txt),
/// so `toml::parse` here throws `toml::parse_error` on malformed input rather
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
    result.warn(core::WarningCode::kInvalidToml, "python: " + label + ": not valid TOML, skipped",
                "python");
    return std::nullopt;
  }
}

/// Parse one uv.lock. Root-project entries (`source` with `virtual`/
/// `editable`) are skipped silently: the product is not its own dependency.
/// uv.lock carries no per-package dev marking, so scope is never guessed.
void parse_uv_lock(std::string_view bytes, const std::string& label, std::size_t package_limit,
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
    const toml::table* source_table = (*package_table)["source"].as_table();
    if (source_table != nullptr &&
        (source_table->contains("virtual") || source_table->contains("editable")))
    {
      continue;  // the root project / a workspace member: first-party
    }
    const std::optional<std::string> name = (*package_table)["name"].value<std::string>();
    const std::optional<std::string> version = (*package_table)["version"].value<std::string>();
    // A name made only of separators (`_`, `..-`) normalizes to nothing, and no
    // purl has an empty name: that entry is unusable, like a missing one.
    if (!name.has_value() || normalize_pypi_name(*name).empty() || !version.has_value() ||
        version->empty())
    {
      ++skipped_entry_count;
      continue;
    }
    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "python: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "python");
      result.complete = false;
      break;
    }
    --package_budget;
    emit_lock_component(*name, *version, core::Scope::Required, label, components, result);
  }
  if (skipped_entry_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "python: " + std::to_string(skipped_entry_count) +
                    " package entrie(s) without name/version skipped: " + label,
                "python");
  }
}

/// Parse one poetry.lock. A package whose `groups` array lacks `main`: or
/// whose legacy `category` (poetry <1.5) isn't `main`: is dev-only tooling
/// and gets Scope::Excluded; the lockfile said so, nothing is guessed.
void parse_poetry_lock(std::string_view bytes, const std::string& label, std::size_t package_limit,
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
    return;
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
    const std::optional<std::string> name = (*package_table)["name"].value<std::string>();
    const std::optional<std::string> version = (*package_table)["version"].value<std::string>();
    // A name made only of separators (`_`, `..-`) normalizes to nothing, and no
    // purl has an empty name: that entry is unusable, like a missing one.
    if (!name.has_value() || normalize_pypi_name(*name).empty() || !version.has_value() ||
        version->empty())
    {
      ++skipped_entry_count;
      continue;
    }

    core::Scope scope = core::Scope::Required;
    if (const toml::array* groups = (*package_table)["groups"].as_array())
    {
      bool has_any_group = false;
      bool has_main_group = false;
      for (const toml::node& group_node : *groups)
      {
        const std::optional<std::string> group_name = group_node.value<std::string>();
        if (group_name.has_value())
        {
          has_any_group = true;
          if (*group_name == kPoetryMainGroup)
          {
            has_main_group = true;
          }
        }
      }
      if (has_any_group && !has_main_group)
      {
        scope = core::Scope::Excluded;
      }
    }
    else if (const std::optional<std::string> category =
                 (*package_table)["category"].value<std::string>())
    {
      if (*category != kPoetryMainGroup)
      {
        scope = core::Scope::Excluded;
      }
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "python: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "python");
      result.complete = false;
      break;
    }
    --package_budget;
    emit_lock_component(*name, *version, scope, label, components, result);
  }
  if (skipped_entry_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "python: " + std::to_string(skipped_entry_count) +
                    " package entrie(s) without name/version skipped: " + label,
                "python");
  }
}

/// True when the character can appear in a PEP 508 project name.
bool is_requirement_name_character(char character)
{
  const char lowered = core::to_lower_ascii(character);
  return (lowered >= 'a' && lowered <= 'z') || (lowered >= '0' && lowered <= '9') ||
         lowered == '-' || lowered == '_' || lowered == '.';
}

/// Parse one recognized requirements file line-by-line. Option/include/URL/path lines are
/// counted and reported once per file: batch 1 reads plain requirement lines
/// only, and silence would hide real dependencies.
void parse_requirements(std::string_view bytes, const std::string& label, std::size_t package_limit,
                        std::size_t& package_budget, std::vector<core::Component>& components,
                        core::Result<std::vector<core::Component>>& result)
{
  std::size_t unsupported_line_count = 0;
  std::size_t line_start = 0;
  while (line_start <= bytes.size())
  {
    const std::size_t line_end = bytes.find('\n', line_start);
    const std::string_view raw_line =
        bytes.substr(line_start, (line_end == std::string_view::npos) ? std::string_view::npos
                                                                      : line_end - line_start);
    line_start = (line_end == std::string_view::npos) ? bytes.size() + 1 : line_end + 1;

    // Strip a comment: '#' at line start or preceded by whitespace (PEP 508
    // markers never contain an unquoted '#').
    std::string_view line = raw_line;
    for (std::size_t hash_position = line.find('#'); hash_position != std::string_view::npos;
         hash_position = line.find('#', hash_position + 1))
    {
      if (hash_position == 0 || line[hash_position - 1] == ' ' || line[hash_position - 1] == '\t')
      {
        line = line.substr(0, hash_position);
        break;
      }
    }
    line = core::trimmed_view(line);
    // pip-compile/uv pip compile --generate-hashes leave a trailing '\' line-continuation
    // marker on every pinned line; the continued lines (--hash=...) are already skipped
    // below as option lines, so dropping the marker is enough: no real join needed.
    if (!line.empty() && line.back() == '\\')
    {
      line = core::trimmed_view(line.substr(0, line.size() - 1));
    }
    if (line.empty())
    {
      continue;
    }
    // Options/includes (-r, -c, -e, --hash, …), URLs and filesystem paths are
    // out of batch-1 scope: counted, never silently dropped.
    if (line.front() == '-' || line.front() == '.' || line.front() == '/' ||
        line.find("://") != std::string_view::npos)
    {
      ++unsupported_line_count;
      continue;
    }

    // `name [extras] [specifier] [; marker]`: split the marker off first.
    std::string_view marker;
    const std::size_t marker_position = line.find(';');
    if (marker_position != std::string_view::npos)
    {
      marker = core::trimmed_view(line.substr(marker_position + 1));
      line = core::trimmed_view(line.substr(0, marker_position));
    }
    std::size_t name_length = 0;
    while (name_length < line.size() && is_requirement_name_character(line[name_length]))
    {
      ++name_length;
    }
    const std::string_view declared_name = line.substr(0, name_length);
    // A name made only of separators (`_`, `._.`) normalizes to nothing, and no
    // purl has an empty name: such a line is not a requirement (found by
    // fuzzing, T40).
    if (normalize_pypi_name(declared_name).empty())
    {
      ++unsupported_line_count;
      continue;
    }
    std::string_view rest = core::trimmed_view(line.substr(name_length));
    std::string_view extras;
    if (!rest.empty() && rest.front() == '[')
    {
      const std::size_t extras_end = rest.find(']');
      if (extras_end == std::string_view::npos)
      {
        ++unsupported_line_count;  // unterminated extras: hostile input
        continue;
      }
      extras = rest.substr(1, extras_end - 1);
      rest = core::trimmed_view(rest.substr(extras_end + 1));
    }

    // An exact `==`/`===` pin with a single clause and no wildcard is
    // pip-enforced -> High and it defines the identity version (the same logic
    // that makes a vcpkg `overrides` pin High). Everything else is a
    // constraint, not a resolved version -> Low, kept as evidence only.
    std::string pinned_version;
    if (rest.size() >= 2 && rest.substr(0, 2) == "==")
    {
      const std::string_view candidate =
          core::trimmed_view(rest.substr(rest.substr(0, 3) == "===" ? 3 : 2));
      if (!candidate.empty() && candidate.find(',') == std::string_view::npos &&
          candidate.find('*') == std::string_view::npos)
      {
        pinned_version = std::string(candidate);
      }
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "python: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "python");
      result.complete = false;
      break;
    }
    --package_budget;

    core::Component component;
    component.name = normalize_pypi_name(declared_name);
    component.version = pinned_version;
    component.purl = build_pypi_purl(component.name, component.version);

    std::string detail = label;
    if (component.name != declared_name)
    {
      detail += " declared=" + std::string(declared_name);
    }
    if (pinned_version.empty() && !rest.empty())
    {
      detail += " constraint=" + std::string(rest);
    }
    if (!extras.empty())
    {
      detail += " extras=" + std::string(extras);
    }
    if (!marker.empty())
    {
      detail += " marker=" + std::string(marker);
    }
    const core::Confidence confidence =
        pinned_version.empty() ? core::Confidence::Low : core::Confidence::High;
    component.evidence.push_back({core::Source::Manifest, detail, confidence});

    core::canonicalize_purl(component.purl, kProducerName, result.warnings);
    components.push_back(std::move(component));
  }

  if (unsupported_line_count > 0)
  {
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "python: " + std::to_string(unsupported_line_count) +
                    " unsupported requirement line(s) skipped: " + label,
                "python");
  }
}

/// The formats this producer reads.
enum class ManifestKind
{
  kUvLock,
  kPoetryLock,
  kRequirements,
};

/// Selects uv and poetry lockfiles (TOML: a truncated document cannot parse,
/// so an oversized one is skipped) and requirements files (line-based: an
/// oversized one keeps its complete-line prefix).
std::optional<core::ManifestMatch<ManifestKind>> manifest_kind(const fs::path& relative_path)
{
  const std::string_view file_name = core::file_name_of(relative_path);
  if (file_name == kUvLockName)
  {
    return core::ManifestMatch<ManifestKind>{ManifestKind::kUvLock,
                                             core::OversizedFilePolicy::kSkip};
  }
  if (file_name == kPoetryLockName)
  {
    return core::ManifestMatch<ManifestKind>{ManifestKind::kPoetryLock,
                                             core::OversizedFilePolicy::kSkip};
  }
  if (core::matches_manifest_name(file_name, kRequirementsName))
  {
    return core::ManifestMatch<ManifestKind>{ManifestKind::kRequirements,
                                             core::OversizedFilePolicy::kTrimToLastNewline};
  }
  return std::nullopt;
}

/// State shared by every python manifest of one scan: one package budget for all.
struct ParseState
{
  std::vector<core::Component> components;
  std::size_t package_budget = 0;
};

core::ManifestWalkOptions walk_options_for(const ParseOptions& options)
{
  return core::make_walk_options(options, kProducerName, "python");
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
  switch (kind)
  {
    case ManifestKind::kUvLock:
      parse_uv_lock(file.bytes, file.label, options.max_total_packages, state.package_budget,
                    state.components, result);
      return;
    case ManifestKind::kPoetryLock:
      parse_poetry_lock(file.bytes, file.label, options.max_total_packages, state.package_budget,
                        state.components, result);
      return;
    case ManifestKind::kRequirements:
      parse_requirements(file.bytes, file.label, options.max_total_packages, state.package_budget,
                         state.components, result);
      return;
  }
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

}  // namespace bomwerk::parsers::lockfiles::python
