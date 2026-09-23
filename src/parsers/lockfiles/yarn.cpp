#include "parsers/lockfiles/yarn.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <iterator>
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
#include "core/yaml_subset.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::lockfiles::yarn
{
namespace
{

constexpr std::string_view kYarnLockName = "yarn.lock";

/// Yarn Classic writes this banner on the second line of every v1 lockfile;
/// Berry writes a `__metadata` block instead. Only the banner region is read,
/// so format detection costs nothing on a multi-megabyte file.
constexpr std::string_view kClassicBanner = "# yarn lockfile v1";
constexpr std::size_t kFormatProbeBytes = 512;

/// An entry key sits at the document level and its fields one step in. Deeper
/// lines are a dependency's own edges, never an entry of their own.
constexpr std::size_t kEntryKeyIndentation = 0;
constexpr std::size_t kEntryFieldIndentation = 2;

/// The Berry fields this parser reads. `__metadata` is the lockfile's own
/// header block, not a package.
constexpr std::string_view kMetadataKey = "__metadata";
constexpr std::string_view kResolutionKey = "resolution";

/// Yarn Classic states the resolved version as `version "1.2.6"`: space
/// separated, no colon, which is why v1 is not YAML and gets its own scanner.
constexpr std::string_view kClassicVersionPrefix = "version ";

/// Locator protocols. `npm` is the only one that maps to a purl.
constexpr std::string_view kNpmProtocol = "npm";
constexpr std::string_view kPatchProtocol = "patch";

/// A workspace member IS the product being scanned, exactly like a rubygems
/// PATH spec: skipped silently, never counted, since a monorepo declaring
/// hundreds of members is normal shape, not a gap worth a warning.
constexpr std::string_view kWorkspaceProtocol = "workspace";

/// `link:`/`portal:`/`file:` are also first-party, but: unlike a workspace
/// member: they can point outside the workspace graph the monorepo itself
/// declares, so they are skipped with a counted warning instead of silently.
constexpr std::string_view kLocalPathProtocols[] = {"link", "portal", "file"};

/// Separates a patch locator's qualifiers (`::version=…&hash=…`) from the patch
/// file that precedes them.
constexpr std::string_view kPatchQualifierSeparator = "::";

/// Why entries in one lockfile were not emitted. Counted rather than warned
/// per entry, so a monorepo yields one sentence instead of hundreds. Workspace
/// members are not here: they are skipped silently, not counted.
struct SkipCounts
{
  std::size_t local_path = 0;            ///< link:/portal:/file: locators
  std::size_t unsupported_protocol = 0;  ///< exec:, git and http URLs: no purl mapping
  std::size_t malformed = 0;             ///< a locator or entry that did not have the shape
  std::size_t versionless = 0;           ///< a Classic entry that never resolved a version
};

/// Strip one matching pair of surrounding quotes; anything else is returned
/// unchanged.
std::string_view unquoted(std::string_view text)
{
  constexpr std::size_t kDelimiterPairLength = 2;
  if (text.size() < kDelimiterPairLength)
  {
    return text;
  }
  const char first = text.front();
  if ((first != '"' && first != '\'') || text.back() != first)
  {
    return text;
  }
  return text.substr(1, text.size() - kDelimiterPairLength);
}

/// An npm scope names a real registry-enforced organization/account
/// (npmjs.com), so it doubles as NTIA/CRA supplier evidence: an unscoped
/// package states no publisher at all in the lockfile, and stays empty
/// rather than guessing one.
std::string npm_supplier_from_package_name(const std::string& package_name)
{
  const std::size_t scope_separator = package_name.find('/');
  if (!package_name.empty() && package_name.front() == '@' && scope_separator != std::string::npos)
  {
    return package_name.substr(1, scope_separator - 1);
  }
  return {};
}

/// Build the `pkg:npm` purl, keeping an `@scope` as the purl namespace so a
/// scoped package reads `pkg:npm/%40scope/name@1.2.3`.
std::string build_npm_purl(const std::string& package_name, const std::string& version)
{
  std::string purl = "pkg:npm/";
  const std::size_t scope_separator = package_name.find('/');
  if (!package_name.empty() && package_name.front() == '@' && scope_separator != std::string::npos)
  {
    purl += core::percent_encode_purl_namespace(package_name.substr(0, scope_separator));
    purl += "/";
    purl += core::percent_encode(package_name.substr(scope_separator + 1));
  }
  else
  {
    purl += core::percent_encode(package_name);
  }
  purl += "@" + core::percent_encode(version);
  return purl;
}

/// Split a Yarn locator `<name>@<protocol>:<selector>`. Returns false when the
/// text has no protocol separator.
///
/// The separator is the FIRST `@` past index 0 that is followed by a protocol
/// token and a colon. Index 0 is skipped so a scoped name keeps its `@`, and
/// taking the first such `@` rather than the last is what makes a `patch:`
/// locator split correctly: its selector embeds a whole second locator, `@`
/// and all.
bool split_locator(std::string_view locator, std::string_view& package_name,
                   std::string_view& protocol, std::string_view& selector)
{
  for (std::size_t at_sign = locator.find('@', 1); at_sign != std::string_view::npos;
       at_sign = locator.find('@', at_sign + 1))
  {
    std::size_t scan = at_sign + 1;
    while (scan < locator.size() &&
           ((locator[scan] >= 'a' && locator[scan] <= 'z') || locator[scan] == '+'))
    {
      ++scan;
    }
    if (scan == at_sign + 1 || scan >= locator.size() || locator[scan] != ':')
    {
      continue;
    }
    package_name = locator.substr(0, at_sign);
    protocol = locator.substr(at_sign + 1, scan - at_sign - 1);
    selector = locator.substr(scan + 1);
    return !package_name.empty() && !selector.empty();
  }
  return false;
}

/// Name of a Yarn Classic descriptor `name@range`. The separator is the first
/// `@` past a leading scope: a range may itself contain `@`
/// (`foo@npm:bar@^1.0.0`), a package name may not.
std::string_view descriptor_name(std::string_view descriptor)
{
  const std::size_t at_sign = descriptor.find('@', 1);
  if (at_sign == std::string_view::npos)
  {
    return {};
  }
  return descriptor.substr(0, at_sign);
}

bool is_local_path_protocol(std::string_view protocol)
{
  return std::find(std::begin(kLocalPathProtocols), std::end(kLocalPathProtocols), protocol) !=
         std::end(kLocalPathProtocols);
}

bool is_classic_format(std::string_view bytes)
{
  const std::string_view probe = bytes.substr(0, std::min(bytes.size(), kFormatProbeBytes));
  return probe.find(kClassicBanner) != std::string_view::npos;
}

/// Append one resolved package. `detail` is the evidence pointer already built.
void append_npm_component(std::string_view package_name, std::string_view version,
                          std::string detail, std::vector<core::Component>& components,
                          core::Result<std::vector<core::Component>>& result)
{
  core::Component component;
  component.name = std::string(package_name);
  component.version = std::string(version);
  component.purl = build_npm_purl(component.name, component.version);
  component.supplier = npm_supplier_from_package_name(component.name);
  // Lock entries are Yarn's own resolver output -> High.
  component.evidence.push_back({core::Source::Manifest, std::move(detail), core::Confidence::High});

  const core::Result<core::Purl> parsed_purl = core::Purl::parse(component.purl);
  if (!parsed_purl.complete)
  {
    result.warn(core::WarningCode::kPurlValidationFailed,
                "yarn: produced purl failed validation: " + component.purl, "yarn");
  }
  else
  {
    component.purl = parsed_purl.value.canonical();
  }
  components.push_back(std::move(component));
}

/// Emit the counted skips as one warning each, so a lockfile contributes a
/// fixed number of sentences no matter how many entries it holds.
void warn_skip_counts(const SkipCounts& skips, const std::string& label,
                      core::Result<std::vector<core::Component>>& result)
{
  if (skips.local_path > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "yarn: " + std::to_string(skips.local_path) +
                    " link/portal/file entrie(s) skipped as first-party: " + label,
                "yarn");
  }
  if (skips.unsupported_protocol > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "yarn: " + std::to_string(skips.unsupported_protocol) +
                    " entrie(s) with an unsupported protocol skipped: " + label,
                "yarn");
  }
  if (skips.versionless > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "yarn: " + std::to_string(skips.versionless) +
                    " entrie(s) without a resolved version skipped: " + label,
                "yarn");
  }
  if (skips.malformed > 0)
  {
    result.warn(
        core::WarningCode::kMalformedEntrySkipped,
        "yarn: " + std::to_string(skips.malformed) + " malformed entrie(s) skipped: " + label,
        "yarn");
  }
}

/// Parse one Yarn Berry lockfile. Only `resolution:` is read, so an entry can
/// be emitted the moment its locator arrives: there is no state to flush.
void parse_berry_lock(std::string_view bytes, const std::string& label, std::size_t package_limit,
                      std::size_t& package_budget, std::vector<core::Component>& components,
                      core::Result<std::vector<core::Component>>& result)
{
  core::yaml_subset::Reader reader(bytes);
  core::yaml_subset::Node node;
  SkipCounts skips;
  bool inside_metadata = false;
  bool recognized_berry = false;

  while (reader.next(node))
  {
    if (node.indentation == kEntryKeyIndentation)
    {
      inside_metadata = node.key == kMetadataKey;
      recognized_berry = recognized_berry || inside_metadata;
      continue;
    }
    if (inside_metadata || node.indentation != kEntryFieldIndentation || node.key != kResolutionKey)
    {
      continue;
    }
    recognized_berry = true;

    std::string_view package_name;
    std::string_view protocol;
    std::string_view selector;
    if (!split_locator(node.value, package_name, protocol, selector))
    {
      ++skips.malformed;
      continue;
    }

    // A patched package is the registry package with a diff applied: recover
    // the locator underneath, and keep the patch visible in the evidence so
    // the SBOM never presents it as the pristine tarball.
    std::string underlying_locator;
    std::string patch_note;
    if (protocol == kPatchProtocol)
    {
      const std::size_t patch_marker = selector.find('#');
      underlying_locator = core::percent_decode(
          (patch_marker == std::string_view::npos) ? selector : selector.substr(0, patch_marker));
      if (patch_marker != std::string_view::npos)
      {
        const std::string_view patch_tail = selector.substr(patch_marker + 1);
        patch_note = std::string(patch_tail.substr(0, patch_tail.find(kPatchQualifierSeparator)));
      }
      if (!split_locator(underlying_locator, package_name, protocol, selector))
      {
        ++skips.malformed;
        continue;
      }
    }

    if (protocol == kWorkspaceProtocol)
    {
      continue;  // the product itself: silent, exactly like a rubygems PATH spec
    }
    if (is_local_path_protocol(protocol))
    {
      ++skips.local_path;
      continue;
    }
    if (protocol != kNpmProtocol)
    {
      ++skips.unsupported_protocol;
      continue;
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "yarn: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "yarn");
      result.complete = false;
      break;
    }
    --package_budget;

    std::string detail = label;
    if (!patch_note.empty())
    {
      detail += " (patched: " + patch_note + ")";
    }
    append_npm_component(package_name, selector, std::move(detail), components, result);
  }

  if (!recognized_berry)
  {
    result.warn(core::WarningCode::kLockfileFormatUnsupported,
                "yarn: no Berry entries and no v1 banner, unrecognized lockfile format: " + label,
                "yarn");
  }
  warn_skip_counts(skips, label, result);

  const std::size_t unsupported_line_count = reader.stats().unsupported_line_count;
  if (unsupported_line_count > 0)
  {
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "yarn: " + std::to_string(unsupported_line_count) +
                    " line(s) outside the readable YAML subset skipped: " + label,
                "yarn");
  }
}

/// Parse one Yarn Classic (v1) lockfile. Not YAML: an entry key is a comma
/// separated descriptor list ending in `:`, and its fields are `key "value"`.
void parse_classic_lock(std::string_view bytes, const std::string& label, std::size_t package_limit,
                        std::size_t& package_budget, std::vector<core::Component>& components,
                        core::Result<std::vector<core::Component>>& result)
{
  SkipCounts skips;
  std::string_view pending_name;

  std::size_t line_start = 0;
  while (line_start <= bytes.size())
  {
    const std::size_t line_end = bytes.find('\n', line_start);
    const std::string_view raw_line =
        bytes.substr(line_start, (line_end == std::string_view::npos) ? std::string_view::npos
                                                                      : line_end - line_start);
    line_start = (line_end == std::string_view::npos) ? bytes.size() + 1 : line_end + 1;

    const std::string_view line = core::trimmed_view(raw_line);
    if (line.empty() || line.front() == '#')
    {
      continue;
    }
    const std::size_t indentation = core::leading_space_count(raw_line);

    if (indentation == kEntryKeyIndentation)
    {
      // The previous entry ended without ever naming a resolved version.
      if (!pending_name.empty())
      {
        ++skips.versionless;
      }
      pending_name = {};
      if (!line.ends_with(':'))
      {
        ++skips.malformed;
        continue;
      }
      const std::string_view descriptors = line.substr(0, line.size() - 1);
      const std::string_view first_descriptor =
          core::trimmed_view(descriptors.substr(0, descriptors.find(',')));
      pending_name = descriptor_name(unquoted(first_descriptor));
      if (pending_name.empty())
      {
        ++skips.malformed;
      }
      continue;
    }
    if (indentation != kEntryFieldIndentation || pending_name.empty() ||
        !line.starts_with(kClassicVersionPrefix))
    {
      continue;  // `resolved`/`integrity`, or a dependency edge one step deeper
    }

    const std::string_view version =
        unquoted(core::trimmed_view(line.substr(kClassicVersionPrefix.size())));
    if (version.empty())
    {
      ++skips.versionless;
      pending_name = {};
      continue;
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "yarn: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "yarn");
      result.complete = false;
      pending_name = {};
      break;
    }
    --package_budget;

    append_npm_component(pending_name, version, label, components, result);
    pending_name = {};  // one component per entry; later fields are not versions
  }

  if (!pending_name.empty())
  {
    ++skips.versionless;
  }
  warn_skip_counts(skips, label, result);
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
    if (relative_path.filename().string() != kYarnLockName)
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      result.warn(core::WarningCode::kFileLimitReached,
                  "yarn: file limit reached; remaining yarn.lock files skipped", "yarn");
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
      result.warn(core::WarningCode::kUnreadableFile, "yarn: unreadable file: " + label, "yarn");
      continue;
    }
    std::string_view bytes = file_read.bytes;
    if (file_read.truncated)
    {
      // Line-based: the readable prefix still parses; drop the cut-off tail
      // line so it cannot count as malformed.
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "yarn: file exceeds size limit, parsing first part only: " + label, "yarn");
      const std::size_t last_newline = bytes.rfind('\n');
      bytes = (last_newline == std::string_view::npos) ? std::string_view{}
                                                       : bytes.substr(0, last_newline + 1);
    }

    if (is_classic_format(bytes))
    {
      parse_classic_lock(bytes, label, options.max_total_packages, package_budget, components,
                         result);
    }
    else
    {
      parse_berry_lock(bytes, label, options.max_total_packages, package_budget, components,
                       result);
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

}  // namespace bomwerk::parsers::lockfiles::yarn
