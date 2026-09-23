#include "parsers/lockfiles/rubygems.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/exclusions.hpp"
#include "core/file_io.hpp"
#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/submodule_paths.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::lockfiles::rubygems
{
namespace
{

constexpr std::string_view kGemfileLockName = "Gemfile.lock";

/// The exact indentation Bundler writes for a resolved gem under `specs:`.
/// Deeper lines (6 spaces) are that gem's dependency edges, not gems.
constexpr std::size_t kSpecIndentation = 4;

/// Section metadata lines (`remote:`, `revision:`, `specs:`) sit at this
/// indentation.
constexpr std::size_t kSectionMetadataIndentation = 2;

/// The Gemfile.lock sections whose `specs:` lines are resolved gems.
enum class Section
{
  Gem,       ///< registry gems: emitted
  Git,       ///< git-pinned gems: emitted with remote@revision evidence
  Path,      ///< first-party local gems: skipped silently
  Untracked  ///< PLATFORMS / DEPENDENCIES / BUNDLED WITH / unknown headers
};

/// Build the `pkg:gem` purl. Gem names have no namespace; platform-suffixed
/// versions are kept verbatim.
std::string build_gem_purl(const std::string& gem_name, const std::string& version)
{
  return "pkg:gem/" + core::percent_encode(gem_name) + "@" + core::percent_encode(version);
}

/// Number of leading space characters: Gemfile.lock structure is literal
/// space indentation, never tabs.
std::size_t leading_space_count(std::string_view line)
{
  std::size_t count = 0;
  while (count < line.size() && line[count] == ' ')
  {
    ++count;
  }
  return count;
}

/// Split a `name (version)` spec line. Returns false when the line does not
/// have that exact shape.
bool split_spec_line(std::string_view spec_line, std::string_view& gem_name,
                     std::string_view& version)
{
  const std::size_t open_paren = spec_line.find(" (");
  if (open_paren == std::string_view::npos || open_paren == 0)
  {
    return false;
  }
  const std::size_t close_paren = spec_line.find(')', open_paren + 2);
  if (close_paren == std::string_view::npos || close_paren != spec_line.size() - 1)
  {
    return false;
  }
  gem_name = spec_line.substr(0, open_paren);
  version = spec_line.substr(open_paren + 2, close_paren - open_paren - 2);
  return !gem_name.empty() && !version.empty();
}

/// Parse one Gemfile.lock's sections into components. `label` is the
/// root-relative path used in warnings and evidence details.
void parse_gemfile_lock(std::string_view bytes, const std::string& label, std::size_t package_limit,
                        std::size_t& package_budget, std::vector<core::Component>& components,
                        core::Result<std::vector<core::Component>>& result)
{
  Section current_section = Section::Untracked;
  bool inside_specs = false;
  std::string current_remote;
  std::string current_revision;
  std::size_t malformed_line_count = 0;

  std::size_t line_start = 0;
  while (line_start <= bytes.size())
  {
    const std::size_t line_end = bytes.find('\n', line_start);
    const std::string_view raw_line =
        bytes.substr(line_start, (line_end == std::string_view::npos) ? std::string_view::npos
                                                                      : line_end - line_start);
    line_start = (line_end == std::string_view::npos) ? bytes.size() + 1 : line_end + 1;

    const std::string_view line = core::trimmed_view(raw_line);
    if (line.empty())
    {
      continue;
    }
    const std::size_t indentation = leading_space_count(raw_line);

    // An unindented line is a section header; everything it governs follows.
    if (indentation == 0)
    {
      if (line == "GEM")
      {
        current_section = Section::Gem;
      }
      else if (line == "GIT")
      {
        current_section = Section::Git;
      }
      else if (line == "PATH")
      {
        current_section = Section::Path;
      }
      else
      {
        current_section = Section::Untracked;
      }
      inside_specs = false;
      current_remote.clear();
      current_revision.clear();
      continue;
    }
    if (current_section == Section::Untracked)
    {
      continue;
    }

    if (indentation == kSectionMetadataIndentation)
    {
      if (line == "specs:")
      {
        inside_specs = true;
      }
      else if (line.starts_with("remote: "))
      {
        current_remote = core::trimmed(line.substr(std::string_view("remote: ").size()));
      }
      else if (line.starts_with("revision: "))
      {
        current_revision = core::trimmed(line.substr(std::string_view("revision: ").size()));
      }
      continue;
    }
    if (!inside_specs || indentation != kSpecIndentation)
    {
      continue;  // a gem's own dependency edges (6 spaces) or unknown shape
    }
    if (current_section == Section::Path)
    {
      continue;  // first-party local gems: the product, not dependencies
    }

    std::string_view gem_name;
    std::string_view version;
    if (!split_spec_line(line, gem_name, version))
    {
      ++malformed_line_count;
      continue;
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "rubygems: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "rubygems");
      result.complete = false;
      break;
    }
    --package_budget;

    core::Component component;
    component.name = std::string(gem_name);
    component.version = std::string(version);
    component.purl = build_gem_purl(component.name, component.version);

    std::string detail = label;
    if (current_section == Section::Git)
    {
      detail += " (git " + current_remote + "@" + current_revision + ")";
    }
    else if (!current_remote.empty())
    {
      detail += " (remote " + current_remote + ")";
    }
    // Lock entries are Bundler's own resolver output -> High.
    component.evidence.push_back({core::Source::Manifest, detail, core::Confidence::High});

    const core::Result<core::Purl> parsed_purl = core::Purl::parse(component.purl);
    if (!parsed_purl.complete)
    {
      result.warn(core::WarningCode::kPurlValidationFailed,
                  "rubygems: produced purl failed validation: " + component.purl, "rubygems");
    }
    else
    {
      component.purl = parsed_purl.value.canonical();
    }
    components.push_back(std::move(component));
  }

  if (malformed_line_count > 0)
  {
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "rubygems: " + std::to_string(malformed_line_count) +
                    " malformed spec line(s) skipped: " + label,
                "rubygems");
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

  for (const fs::path& relative_path : file_index.files)
  {
    if (relative_path.filename().string() != kGemfileLockName)
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      result.warn(core::WarningCode::kFileLimitReached,
                  "rubygems: file limit reached; remaining Gemfile.lock files skipped", "rubygems");
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
      result.warn(core::WarningCode::kUnreadableFile, "rubygems: unreadable file: " + label,
                  "rubygems");
      continue;
    }
    std::string_view bytes = file_read.bytes;
    if (file_read.truncated)
    {
      // Line-based: the readable prefix still parses; drop the cut-off tail
      // line so it cannot count as malformed.
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "rubygems: file exceeds size limit, parsing first part only: " + label,
                  "rubygems");
      const std::size_t last_newline = bytes.rfind('\n');
      bytes = (last_newline == std::string_view::npos) ? std::string_view{}
                                                       : bytes.substr(0, last_newline + 1);
    }
    parse_gemfile_lock(bytes, label, options.max_total_packages, package_budget, components,
                       result);
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

}  // namespace bomwerk::parsers::lockfiles::rubygems
