#include "parsers/lockfiles/pnpm.hpp"

#include <cstddef>
#include <filesystem>
#include <optional>
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

namespace bomwerk::parsers::lockfiles::pnpm
{
namespace
{

constexpr std::string_view kPnpmLockName = "pnpm-lock.yaml";

/// Document-level keys. `packages:` is the ONLY section read: `snapshots:`
/// repeats every one of its keys with the peer dependencies each was resolved
/// against appended, and `importers:` names the workspace's own members.
constexpr std::size_t kDocumentIndentation = 0;
constexpr std::string_view kLockfileVersionKey = "lockfileVersion";
constexpr std::string_view kPackagesKey = "packages";

/// A package entry key sits two spaces in; its fields sit four.
constexpr std::size_t kEntryKeyIndentation = 2;
constexpr std::size_t kEntryFieldIndentation = 4;
constexpr std::string_view kResolutionKey = "resolution";

/// The resolution field marking a registry tarball. Its absence means a git or
/// URL dependency, whose "version" is a URL.
constexpr std::string_view kIntegrityField = "integrity";

/// Lockfile generations this grammar reads. 9 and 6 both spell a package key
/// `name@version`; 5 spells it `name/version`, which this would misread as a
/// version-less name rather than fail, so it is refused outright.
constexpr int kLockfileVersionV9 = 9;
constexpr int kLockfileVersionV6 = 6;

/// No real `lockfileVersion` has more digits than this in its major component;
/// the bound keeps the hand-rolled parse below free of overflow.
constexpr std::size_t kMaxVersionDigits = 3;

/// Why entries in one lockfile were not emitted. Counted rather than warned per
/// entry, so a 2600-entry lockfile yields a fixed number of sentences.
struct SkipCounts
{
  std::size_t malformed = 0;               ///< a key that was not `name@version`
  std::size_t unsupported_resolution = 0;  ///< git/tarball resolutions: no purl mapping
  std::size_t missing_resolution = 0;      ///< an entry whose `resolution:` never arrived
};

/// The entry whose key has been read but whose `resolution:` has not. pnpm puts
/// identity in the key and the registry proof in a later line, so one entry
/// spans two nodes.
struct PendingEntry
{
  std::string_view name;
  std::string_view version;
  bool active = false;
};

/// Major version number in a `lockfileVersion` value (`'9.0'` -> 9), or nullopt
/// when it does not open with digits.
std::optional<int> lockfile_major_version(std::string_view lockfile_version)
{
  std::size_t digit_count = 0;
  while (digit_count < lockfile_version.size() && lockfile_version[digit_count] >= '0' &&
         lockfile_version[digit_count] <= '9')
  {
    ++digit_count;
  }
  if (digit_count == 0 || digit_count > kMaxVersionDigits)
  {
    return std::nullopt;
  }
  int major_version = 0;
  for (std::size_t index = 0; index < digit_count; ++index)
  {
    major_version = major_version * 10 + (lockfile_version[index] - '0');
  }
  return major_version;
}

bool is_supported_lockfile_version(std::string_view lockfile_version)
{
  const std::optional<int> major_version = lockfile_major_version(lockfile_version);
  if (!major_version.has_value())
  {
    return false;
  }
  return *major_version == kLockfileVersionV9 || *major_version == kLockfileVersionV6;
}

/// Split a `packages:` key into name and version, reading both spellings: v9
/// `name@1.2.3` and v6 `/name@1.2.3`. Any trailing `(peer@1.0.0)` suffix is
/// removed FIRST: it embeds its own `@`, so cutting it before the split is what
/// keeps the version from swallowing it.
bool split_package_key(std::string_view packages_key, std::string_view& package_name,
                       std::string_view& version)
{
  if (!packages_key.empty() && packages_key.front() == '/')
  {
    packages_key.remove_prefix(1);  // the pnpm v6 spelling
  }
  const std::size_t peer_suffix = packages_key.find('(');
  if (peer_suffix != std::string_view::npos)
  {
    packages_key = packages_key.substr(0, peer_suffix);
  }

  // The LAST `@`, not the first: a scoped package opens with an `@` that is
  // part of its name (`@scope/name@1.2.3`).
  const std::size_t separator = packages_key.rfind('@');
  if (separator == std::string_view::npos || separator == 0)
  {
    return false;
  }
  package_name = packages_key.substr(0, separator);
  version = packages_key.substr(separator + 1);
  return !package_name.empty() && !version.empty();
}

/// Offset of the next top-level `,` in `content`, honoring quotes, or
/// `content.size()` when none remains. Mirrors `yaml_subset`'s own
/// quote-aware scanning: a flow mapping field's value can itself be quoted and
/// carry a literal comma (a `tarball:` URL's query string), which a naive
/// unquoted split would cut in the wrong place.
std::size_t unquoted_comma_offset(std::string_view content)
{
  constexpr std::string_view kQuoteCharacters = "\"'";
  char open_quote = '\0';
  for (std::size_t index = 0; index < content.size(); ++index)
  {
    const char character = content[index];
    if (open_quote != '\0')
    {
      if (character == '\\' && open_quote == '"')
      {
        ++index;  // an escaped byte never closes the region
        continue;
      }
      if (character == open_quote)
      {
        open_quote = '\0';
      }
      continue;
    }
    if (kQuoteCharacters.find(character) != std::string_view::npos)
    {
      open_quote = character;
      continue;
    }
    if (character == ',')
    {
      return index;
    }
  }
  return content.size();
}

/// Value of `field` inside a flow mapping's interior text: what the reader
/// hands back as `Node::value` when `is_flow_mapping`. Fields are
/// `,`-separated, so a two-field `{repo: …, commit: …}` is walked exactly like a
/// one-field `{integrity: …}`; the split is quote-aware so a comma inside a
/// quoted field value cannot be mistaken for a field separator.
std::string_view flow_mapping_field(std::string_view interior_text, std::string_view field)
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
    if (core::trimmed_view(segment.substr(0, colon)) == field)
    {
      return core::trimmed_view(segment.substr(colon + 1));
    }
  }
  return {};
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
  // Lock entries are pnpm's own resolver output -> High.
  component.evidence.push_back({core::Source::Manifest, std::move(detail), core::Confidence::High});

  const core::Result<core::Purl> parsed_purl = core::Purl::parse(component.purl);
  if (!parsed_purl.complete)
  {
    result.warn(core::WarningCode::kPurlValidationFailed,
                "pnpm: produced purl failed validation: " + component.purl, "pnpm");
  }
  else
  {
    component.purl = parsed_purl.value.canonical();
  }
  components.push_back(std::move(component));
}

/// Close the entry currently open, counting it when no `resolution:` ever
/// arrived. Called at every new entry key, at section end and at end of input,
/// so an entry can never be dropped without being counted.
void close_pending_entry(PendingEntry& pending, SkipCounts& skips)
{
  if (pending.active)
  {
    ++skips.missing_resolution;
  }
  pending.active = false;
}

/// Emit the counted skips as one warning each.
void warn_skip_counts(const SkipCounts& skips, const std::string& label,
                      core::Result<std::vector<core::Component>>& result)
{
  if (skips.unsupported_resolution > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "pnpm: " + std::to_string(skips.unsupported_resolution) +
                    " git/URL entrie(s) without a registry integrity skipped: " + label,
                "pnpm");
  }
  if (skips.missing_resolution > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "pnpm: " + std::to_string(skips.missing_resolution) +
                    " entrie(s) without a resolution skipped: " + label,
                "pnpm");
  }
  if (skips.malformed > 0)
  {
    result.warn(
        core::WarningCode::kMalformedEntrySkipped,
        "pnpm: " + std::to_string(skips.malformed) + " malformed package key(s) skipped: " + label,
        "pnpm");
  }
}

/// Parse one pnpm-lock.yaml's `packages:` section into components. `label` is
/// the root-relative path used in warnings and evidence details.
void parse_pnpm_lock(std::string_view bytes, const std::string& label, std::size_t package_limit,
                     std::size_t& package_budget, std::vector<core::Component>& components,
                     core::Result<std::vector<core::Component>>& result)
{
  core::yaml_subset::Reader reader(bytes);
  core::yaml_subset::Node node;
  SkipCounts skips;
  PendingEntry pending;
  bool inside_packages = false;
  bool version_seen = false;
  bool version_supported = false;

  while (reader.next(node))
  {
    // A document-level key or a new entry key both end whatever entry was
    // pending. Tracking this is the whole reason `snapshots:` cannot leak:
    // its keys are shaped exactly like a package's but carry the peer set
    // they were resolved against.
    if (node.indentation <= kEntryKeyIndentation)
    {
      close_pending_entry(pending, skips);
    }

    if (node.indentation == kDocumentIndentation)
    {
      if (node.key == kLockfileVersionKey)
      {
        version_seen = true;
        version_supported = is_supported_lockfile_version(node.value);
        if (!version_supported)
        {
          result.warn(core::WarningCode::kLockfileFormatUnsupported,
                      "pnpm: " + label + ": lockfileVersion '" + std::string(node.value) +
                          "' unsupported (reads 6 and 9), skipped",
                      "pnpm");
          return;
        }
      }
      inside_packages = node.key == kPackagesKey;
      continue;
    }
    if (!inside_packages || !version_supported)
    {
      continue;
    }

    if (node.indentation == kEntryKeyIndentation)
    {
      std::string_view package_name;
      std::string_view version;
      if (!split_package_key(node.key, package_name, version))
      {
        ++skips.malformed;
        continue;
      }
      pending.name = package_name;
      pending.version = version;
      pending.active = true;
      continue;
    }
    if (node.indentation != kEntryFieldIndentation || node.key != kResolutionKey || !pending.active)
    {
      continue;
    }

    // A registry package resolves to an integrity hash. A git or URL dependency
    // resolves to `{tarball: …}` or `{repo:, commit:}`, which puts a URL where
    // the version belongs: counted, never forced into a purl.
    const std::string_view integrity =
        node.is_flow_mapping ? flow_mapping_field(node.value, kIntegrityField) : std::string_view{};
    const std::string_view package_name = pending.name;
    const std::string_view version = pending.version;
    pending.active = false;  // resolved either way; only emission is left
    if (integrity.empty())
    {
      ++skips.unsupported_resolution;
      continue;
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "pnpm: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "pnpm");
      result.complete = false;
      break;
    }
    --package_budget;

    // `integrity` is sha512: evidence, never Component::sha256.
    std::string detail = label + " (integrity " + std::string(integrity) + ")";
    append_npm_component(package_name, version, std::move(detail), components, result);
  }
  close_pending_entry(pending, skips);

  if (!version_seen)
  {
    // Nothing was emitted: the section gate above requires a known version.
    result.warn(core::WarningCode::kLockfileFormatUnsupported,
                "pnpm: " + label + ": no lockfileVersion, skipped", "pnpm");
    return;
  }
  warn_skip_counts(skips, label, result);

  const std::size_t unsupported_line_count = reader.stats().unsupported_line_count;
  if (unsupported_line_count > 0)
  {
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "pnpm: " + std::to_string(unsupported_line_count) +
                    " line(s) outside the readable YAML subset skipped: " + label,
                "pnpm");
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
    if (relative_path.filename().string() != kPnpmLockName)
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      result.warn(core::WarningCode::kFileLimitReached,
                  "pnpm: file limit reached; remaining pnpm-lock.yaml files skipped", "pnpm");
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
      result.warn(core::WarningCode::kUnreadableFile, "pnpm: unreadable file: " + label, "pnpm");
      continue;
    }
    std::string_view bytes = file_read.bytes;
    if (file_read.truncated)
    {
      // Line-based: the readable prefix still parses; drop the cut-off tail
      // line so it cannot count as malformed.
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "pnpm: file exceeds size limit, parsing first part only: " + label, "pnpm");
      const std::size_t last_newline = bytes.rfind('\n');
      bytes = (last_newline == std::string_view::npos) ? std::string_view{}
                                                       : bytes.substr(0, last_newline + 1);
    }
    parse_pnpm_lock(bytes, label, options.max_total_packages, package_budget, components, result);
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

}  // namespace bomwerk::parsers::lockfiles::pnpm
