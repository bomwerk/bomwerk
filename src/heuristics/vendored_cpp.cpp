#include "heuristics/vendored_cpp.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "core/file_io.hpp"
#include "core/git_config.hpp"
#include "core/git_dir.hpp"
#include "core/git_url.hpp"
#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"
#include "heuristics/vendor_root.hpp"

namespace fs = std::filesystem;

namespace bomwerk::heuristics::vendored_cpp
{
namespace
{

// Evidence detail strings are for a human reading the SBOM, not raw file
// dumps: cap how much of a LICENSE/README line is echoed back.
constexpr std::size_t kMaxEvidenceDetailChars = 120u;
constexpr std::size_t kMaxReadmeLines = 10u;

/// First non-blank line of `content`, trimmed and truncated for display.
std::string first_line_truncated(const std::string& content, std::size_t max_chars)
{
  const std::size_t newline = content.find('\n');
  std::string_view first_line = (newline == std::string::npos)
                                    ? std::string_view(content)
                                    : std::string_view(content).substr(0, newline);
  first_line = core::trimmed_view(first_line);
  if (first_line.size() > max_chars)
  {
    return std::string(first_line.substr(0, max_chars)) + "…";
  }
  return std::string(first_line);
}

/// Up to `max_lines` non-blank lines of `content`, joined and truncated for
/// display: used for a README, never parsed for identity (rule: honest is
/// better than clever; a folder name is a deterministic identity, freeform
/// prose is not).
std::string first_lines_truncated(const std::string& content, std::size_t max_lines,
                                  std::size_t max_chars)
{
  std::string joined;
  std::size_t line_count = 0;
  std::size_t position = 0;
  while (position < content.size() && line_count < max_lines)
  {
    const std::size_t newline = content.find('\n', position);
    const std::size_t end = (newline == std::string::npos) ? content.size() : newline;
    const std::string_view line =
        core::trimmed_view(std::string_view(content).substr(position, end - position));
    if (!line.empty())
    {
      if (!joined.empty())
      {
        joined += " / ";
      }
      joined += std::string(line);
      ++line_count;
    }
    if (newline == std::string::npos)
    {
      break;
    }
    position = newline + 1;
  }
  if (joined.size() > max_chars)
  {
    joined.resize(max_chars);
    joined += "…";
  }
  return joined;
}

// ---- version-header table -------------------------------------------------

struct VersionHeaderSignature
{
  std::string_view canonical_name;
  std::string_view header_filename;
  std::string_view version_macro;  ///< the macro whose value is the version; HOW that value is
                                   ///< written depends on which table the row sits in
};

/// How a signature's version macro writes its value. A property of the TABLE a
/// row is in rather than a field on the row, so adding a form never touches the
/// existing rows.
enum class MacroValueForm
{
  QuotedString,  ///< `#define ZLIB_VERSION "1.2.11"`
  BareDotted     ///< `#define UTHASH_VERSION 2.4.0`
};

// The goal is roughly the ~30 most common vendored libs; this starter set covers the
// libraries most often vendored verbatim into a C/C++ tree whose header
// exposes its version as a single quoted-string macro. Extending this to ~30
// is just adding rows: a stale or wrong macro name fails safe (no match,
// falls back to Low confidence), never a wrong answer, so growing this list
// is low-risk follow-up work, not something this table needs to be complete
// for the first cut.
constexpr VersionHeaderSignature kVersionHeaderSignatures[] = {
    {"zlib", "zlib.h", "ZLIB_VERSION"},
    {"libpng", "png.h", "PNG_LIBPNG_VER_STRING"},
    {"sqlite3", "sqlite3.h", "SQLITE_VERSION"},
    {"curl", "curlver.h", "LIBCURL_VERSION"},
    {"libxml2", "xmlversion.h", "LIBXML_DOTTED_VERSION"},
    {"openssl", "opensslv.h", "OPENSSL_VERSION_TEXT"},
    {"mbedtls", "version.h", "MBEDTLS_VERSION_STRING"},
    {"zstd", "zstd.h", "ZSTD_VERSION_STRING"},
    {"lz4", "lz4.h", "LZ4_VERSION_STRING"},
    {"libevent", "event.h", "LIBEVENT_VERSION"},
    {"civetweb", "civetweb.h", "CIVETWEB_VERSION"},
    {"mongoose", "mongoose.h", "MG_VERSION"},
    {"doctest", "doctest.h", "DOCTEST_VERSION_STR"},
    {"lua", "lua.h", "LUA_RELEASE"},
    {"libssh2", "libssh2.h", "LIBSSH2_VERSION"},
    {"c-ares", "ares_version.h", "ARES_VERSION_STR"},
    {"icu", "uvernum.h", "U_ICU_VERSION"},
    {"harfbuzz", "hb-version.h", "HB_VERSION_STRING"},
    {"xz-liblzma", "version.h", "LZMA_VERSION_STRING"},
    {"libpsl", "psl.h", "PSL_VERSION"},
    // FreeRTOS keeps its version in include/task.h, a very common basename;
    // the exact macro name is what keeps an unrelated task.h from matching.
    {"freertos", "task.h", "tskKERNEL_VERSION_NUMBER"},
};

// Libraries whose header writes the version as a BARE dotted number, not a
// quoted string. uthash declares `#define UTHASH_VERSION 2.4.0`, which the
// quoted-string rows above can never read, so a vendored copy was reported by
// its folder name with no version at all.
//
// Only a dotted value qualifies, and that is the whole safety argument. A bare
// integer is an API revision, not a release: stb writes `#define STBI_VERSION 1`,
// and reading that as a version would assert a release that does not exist.
// Requiring a dot is also what keeps a separate-macros library such as cJSON
// (`CJSON_VERSION_MAJOR 1`, `_MINOR 7`, `_PATCH 15`) out of here: those are three
// numbers on three lines, which this form deliberately does not try to assemble.
constexpr VersionHeaderSignature kBareDottedVersionSignatures[] = {
    {"uthash", "uthash.h", "UTHASH_VERSION"},
};

/// Cap on a bare dotted value's length. A version is a handful of characters;
/// a header cannot make this scan return a megabyte-long "version" that then
/// reaches a purl.
constexpr std::size_t kMaxBareVersionChars = 64u;

struct VersionMatch
{
  std::string canonical_name;
  std::string version;
  fs::path relative_path;  ///< root-relative path of the matched header
  std::string version_macro;
  MacroValueForm form;  ///< how the header wrote the value, so evidence can quote it faithfully
};

/// The value of a bare dotted `#define`, read from `value_start` to the end of
/// its line: `2.4.0` from `#define UTHASH_VERSION 2.4.0`. `nullopt` unless the
/// value is digits and single dots only, starts and ends on a digit, has at
/// least one dot, fits `kMaxBareVersionChars`, and is followed by nothing but
/// whitespace or the start of a comment. Anything else is not a version:
/// `2.4.0abc` and `2.4.0-dev` are not read as `2.4.0`, a value ending in a line
/// continuation is not read at all, and a bare `2` (an API revision) never
/// qualifies.
std::optional<std::string> read_bare_dotted_value(const std::string& content,
                                                  std::size_t value_start, std::size_t line_end)
{
  std::size_t token_end = value_start;
  bool saw_dot = false;
  while (token_end < line_end)
  {
    const char character = content[token_end];
    if (character >= '0' && character <= '9')
    {
      ++token_end;
      continue;
    }
    if (character == '.')
    {
      const bool leading_dot = token_end == value_start;
      const bool doubled_dot = token_end > value_start && content[token_end - 1] == '.';
      if (leading_dot || doubled_dot)
      {
        return std::nullopt;
      }
      saw_dot = true;
      ++token_end;
      continue;
    }
    break;
  }

  const std::size_t token_length = token_end - value_start;
  if (token_length == 0 || !saw_dot || content[token_end - 1] == '.' ||
      token_length > kMaxBareVersionChars)
  {
    return std::nullopt;
  }
  if (token_end < line_end)
  {
    const char terminator = content[token_end];
    const bool ends_cleanly =
        terminator == ' ' || terminator == '\t' || terminator == '\r' || terminator == '/';
    if (!ends_cleanly)
    {
      return std::nullopt;
    }
  }
  return content.substr(value_start, token_length);
}

/// Find `#define <macro_name> <value>` in `content` and return `<value>`, read
/// in the given `form`: a quoted string (`"1.2.11"`) or a bare dotted number
/// (`2.4.0`). Bounded to the same source line as the macro name (a hostile file
/// cannot make this scan past its own line, let alone past `content`'s own size
/// cap). Each candidate occurrence is checked in turn: a macro name that is
/// only a prefix of a longer identifier (e.g. `ZLIB_VERSION_H` when searching
/// for `ZLIB_VERSION`), or isn't a `#define` of the requested form on its line,
/// does not end the search: an unrelated earlier occurrence must never hide a
/// real one later in the same file. `nullopt` only once every occurrence has
/// been tried and none matched.
std::optional<std::string> extract_macro_value(const std::string& content,
                                               std::string_view macro_name, MacroValueForm form)
{
  const std::string needle = "#define " + std::string(macro_name);
  std::size_t search_from = 0;
  while (search_from <= content.size())
  {
    const std::size_t position = content.find(needle, search_from);
    if (position == std::string::npos)
    {
      return std::nullopt;
    }
    // However this occurrence turns out, the next search starts right after
    // it: never past a later, possibly-real occurrence of the same needle.
    search_from = position + 1;

    std::size_t cursor = position + needle.size();
    if (cursor < content.size() &&
        (std::isalnum(static_cast<unsigned char>(content[cursor])) != 0 || content[cursor] == '_'))
    {
      continue;  // macro_name was only a prefix of a longer identifier
    }

    const std::size_t line_end = content.find('\n', cursor);
    const std::size_t search_end = (line_end == std::string::npos) ? content.size() : line_end;

    while (cursor < search_end && (content[cursor] == ' ' || content[cursor] == '\t'))
    {
      ++cursor;
    }
    if (form == MacroValueForm::BareDotted)
    {
      std::optional<std::string> bare_value = read_bare_dotted_value(content, cursor, search_end);
      if (bare_value.has_value())
      {
        return bare_value;
      }
      continue;  // not a bare dotted number on this line: try the next occurrence
    }
    if (cursor >= search_end || content[cursor] != '"')
    {
      continue;  // not a quoted-string macro (or the read was truncated mid-line)
    }
    const std::size_t value_start = cursor + 1;
    const std::size_t closing_quote = content.find('"', value_start);
    if (closing_quote == std::string::npos || closing_quote >= search_end)
    {
      continue;  // unterminated within the line
    }
    return content.substr(value_start, closing_quote - value_start);
  }
  return std::nullopt;
}

/// Try every signature against every candidate file (filtered by basename
/// first, which is cheap) so a filename collision between two signatures
/// (`mbedtls` and `xz-liblzma` both use `version.h`) resolves correctly: a
/// file that doesn't contain a given signature's macro simply fails that one
/// signature and the next candidate is tried, rather than the first filename
/// match winning regardless of content.
std::optional<VersionMatch> find_version_header_match(const fs::path& root,
                                                      const std::vector<fs::path>& files,
                                                      const ParseLimits& limits)
{
  for (const fs::path& relative_file : files)
  {
    const std::string basename = relative_file.filename().string();
    const std::string_view basename_view(basename);

    // One pass over a table, reading each row's macro in that table's form. Both
    // tables go through the same basename filter and the same bounded read, so
    // a bare-dotted row can never read more of a file than a quoted one would.
    const auto match_table = [&](std::span<const VersionHeaderSignature> table,
                                 MacroValueForm form) -> std::optional<VersionMatch>
    {
      for (const VersionHeaderSignature& signature : table)
      {
        if (basename_view != signature.header_filename)
        {
          continue;
        }
        const core::BoundedFileRead file_read =
            core::read_file_bounded(root / relative_file, limits.max_header_bytes);
        if (!file_read.readable)
        {
          continue;
        }
        const std::optional<std::string> version =
            extract_macro_value(file_read.bytes, signature.version_macro, form);
        if (version.has_value())
        {
          return VersionMatch{std::string(signature.canonical_name), *version, relative_file,
                              std::string(signature.version_macro), form};
        }
      }
      return std::nullopt;
    };

    if (std::optional<VersionMatch> match =
            match_table(kVersionHeaderSignatures, MacroValueForm::QuotedString))
    {
      return match;
    }
    if (std::optional<VersionMatch> match =
            match_table(kBareDottedVersionSignatures, MacroValueForm::BareDotted))
    {
      return match;
    }
  }
  return std::nullopt;
}

// ---- LICENSE / README clues ------------------------------------------------

constexpr std::string_view kLicenseFileNames[] = {"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING",
                                                  "COPYING.txt"};
constexpr std::string_view kReadmeFileNames[] = {"README", "README.txt", "README.md"};

struct RecognizedLicense
{
  std::string_view first_line_contains;
  std::string_view spdx_id;
};

// Deliberately a small, local table distinct from `output/spdx_license_ids`'s
// full catalog: a producer may not include `output` (module dependency law),
// and duplicating a bigger SPDX classifier here is exactly the "clever" Doc
// 08 §3 warns against. Only the license text itself becomes `Component::license`; an
// unrecognized LICENSE file is still cited as evidence, just without a
// guessed identifier.
constexpr RecognizedLicense kRecognizedLicenses[] = {
    {"MIT License", "MIT"},
    {"Apache License", "Apache-2.0"},
    {"zlib License", "Zlib"},
    {"BSD 3-Clause", "BSD-3-Clause"},
    {"BSD 2-Clause", "BSD-2-Clause"},
    {"ISC License", "ISC"},
    {"Mozilla Public License", "MPL-2.0"},
};

std::string recognize_license(const std::string& content)
{
  for (const RecognizedLicense& candidate : kRecognizedLicenses)
  {
    if (content.find(candidate.first_line_contains) != std::string::npos)
    {
      return std::string(candidate.spdx_id);
    }
  }
  return {};
}

struct LicenseClue
{
  std::string spdx_id;     ///< empty when the text isn't unambiguously recognized
  std::string first_line;  ///< truncated, for the evidence detail
  fs::path relative_path;
};

std::optional<LicenseClue> find_license_clue(const fs::path& root,
                                             const std::vector<fs::path>& files,
                                             const ParseLimits& limits)
{
  for (const fs::path& relative_file : files)
  {
    const std::string basename = relative_file.filename().string();
    const std::string_view basename_view(basename);
    bool matches_name = false;
    for (std::string_view candidate : kLicenseFileNames)
    {
      if (basename_view == candidate)
      {
        matches_name = true;
        break;
      }
    }
    if (!matches_name)
    {
      continue;
    }
    const core::BoundedFileRead file_read =
        core::read_file_bounded(root / relative_file, limits.max_license_bytes);
    if (!file_read.readable)
    {
      continue;
    }
    LicenseClue clue;
    clue.relative_path = relative_file;
    clue.first_line = first_line_truncated(file_read.bytes, kMaxEvidenceDetailChars);
    clue.spdx_id = recognize_license(file_read.bytes);
    return clue;
  }
  return std::nullopt;
}

struct ReadmeClue
{
  std::string text;  ///< first ~10 non-blank lines, truncated
  fs::path relative_path;
};

std::optional<ReadmeClue> find_readme_clue(const fs::path& root, const std::vector<fs::path>& files,
                                           const ParseLimits& limits)
{
  for (const fs::path& relative_file : files)
  {
    const std::string basename = relative_file.filename().string();
    const std::string_view basename_view(basename);
    bool matches_name = false;
    for (std::string_view candidate : kReadmeFileNames)
    {
      if (basename_view == candidate)
      {
        matches_name = true;
        break;
      }
    }
    if (!matches_name)
    {
      continue;
    }
    const core::BoundedFileRead file_read =
        core::read_file_bounded(root / relative_file, limits.max_readme_bytes);
    if (!file_read.readable)
    {
      continue;
    }
    ReadmeClue clue;
    clue.relative_path = relative_file;
    clue.text = first_lines_truncated(file_read.bytes, kMaxReadmeLines, kMaxEvidenceDetailChars);
    return clue;
  }
  return std::nullopt;
}

// ---- leftover .git clue ----------------------------------------------------

struct GitClue
{
  bool has_git_dir = false;
  std::string commit;  ///< empty when present but unresolved
  std::string name;    ///< remote repo name, when a resolvable origin exists
  std::string owner;   ///< remote owner (supplier evidence), when resolvable
  std::string purl;    ///< built via core::build_git_purl, when commit + remote both resolve
};

/// Mirrors `parsers::cpp::submodules::parse`'s own git-dir handling almost
/// exactly, now that both live on the shared `core::` primitives:
/// resolve the git dir without running git, read HEAD, and if that resolves,
/// try the origin remote for a proper forge purl. Never reads outside
/// `containment_root` (see `core::resolve_git_dir`).
GitClue find_git_clue(const fs::path& root, const fs::path& vendor_root,
                      const fs::path& containment_root)
{
  GitClue clue;
  const fs::path work_dir = root / vendor_root;
  const fs::path git_dir = core::resolve_git_dir(work_dir, containment_root);
  if (git_dir.empty())
  {
    return clue;
  }
  clue.has_git_dir = true;
  clue.commit = core::read_head_commit(git_dir);
  if (clue.commit.empty())
  {
    return clue;  // present but unresolved; still cited as weak evidence below
  }

  const core::Result<core::GitConfig> config = core::read_git_config(git_dir / "config");
  const std::string* origin_url = config.value.find("remote", "origin", "url");
  if (origin_url != nullptr && !origin_url->empty())
  {
    const core::GitRemote remote = core::parse_git_remote(*origin_url);
    const std::string folder_name = vendor_root.filename().string();
    clue.name = remote.repo.empty() ? folder_name : remote.repo;
    clue.owner = remote.owner;
    clue.purl = core::build_git_purl(*origin_url, clue.commit, clue.name);
  }
  return clue;
}

// ---- component assembly ----------------------------------------------------

core::Component build_component(const fs::path& root, const fs::path& vendor_root,
                                const std::vector<fs::path>& files, const ParseLimits& limits,
                                bool containment_root_valid, const fs::path& containment_root,
                                core::Result<std::vector<core::Component>>& result)
{
  core::Component component;
  component.root = vendor_root;
  const std::string folder_name = vendor_root.filename().string();

  const std::optional<VersionMatch> version_match = find_version_header_match(root, files, limits);
  const std::optional<LicenseClue> license_clue = find_license_clue(root, files, limits);
  const std::optional<ReadmeClue> readme_clue = find_readme_clue(root, files, limits);
  const GitClue git_clue =
      containment_root_valid ? find_git_clue(root, vendor_root, containment_root) : GitClue{};

  core::Confidence confidence = core::Confidence::Low;
  if (!git_clue.commit.empty())
  {
    confidence = core::Confidence::Medium;
    component.name = git_clue.name.empty() ? folder_name : git_clue.name;
    component.version = git_clue.commit;
    component.purl = !git_clue.purl.empty()
                         ? git_clue.purl
                         : "pkg:generic/" + core::percent_encode(component.name) + "@" +
                               core::percent_encode(component.version);
    // The leftover .git's remote owner is NTIA/CRA supplier evidence :
    // empty when the origin resolved to no owner segment, never guessed.
    component.supplier = git_clue.owner;
  }
  else if (version_match.has_value())
  {
    confidence = core::Confidence::Medium;
    component.name = version_match->canonical_name;
    component.version = version_match->version;
    component.purl = "pkg:generic/" + core::percent_encode(component.name) + "@" +
                     core::percent_encode(component.version);
  }
  else
  {
    component.name = folder_name;
    component.purl = folder_derived_purl(vendor_root);
  }

  if (license_clue.has_value() && !license_clue->spdx_id.empty())
  {
    component.license = license_clue->spdx_id;
  }

  component.evidence.push_back(
      {core::Source::Heuristic,
       vendor_root.string() + " -> found under a vendored-code trigger directory",
       core::Confidence::Low});
  if (version_match.has_value())
  {
    // Quoted exactly as the header wrote it: a bare `2.4.0` is not shown as
    // `"2.4.0"`, since evidence that misquotes the file is worse than none.
    const std::string quoted_value = version_match->form == MacroValueForm::QuotedString
                                         ? "\"" + version_match->version + "\""
                                         : version_match->version;
    component.evidence.push_back({core::Source::Heuristic,
                                  version_match->relative_path.string() + " -> #define " +
                                      version_match->version_macro + " " + quoted_value,
                                  core::Confidence::Medium});
  }
  if (license_clue.has_value())
  {
    component.evidence.push_back(
        {core::Source::Heuristic,
         license_clue->relative_path.string() + " -> \"" + license_clue->first_line + "\"",
         core::Confidence::Low});
  }
  if (readme_clue.has_value())
  {
    component.evidence.push_back(
        {core::Source::Heuristic,
         readme_clue->relative_path.string() + " -> \"" + readme_clue->text + "\"",
         core::Confidence::Low});
  }
  if (git_clue.has_git_dir)
  {
    const bool resolved = !git_clue.commit.empty();
    component.evidence.push_back(
        {core::Source::Heuristic,
         (vendor_root / ".git").string() +
             (resolved ? " -> HEAD " + git_clue.commit : " present, HEAD unresolved"),
         resolved ? core::Confidence::Medium : core::Confidence::Low});
  }

  // Dogfood core::Purl, same discipline as parsers::cpp::submodules: a purl
  // this producer cannot parse back is a bug in the builder above, not merely
  // degraded input.
  const core::Result<core::Purl> validated = core::Purl::parse(component.purl);
  if (!validated.complete)
  {
    result.warn(core::WarningCode::kPurlValidationFailed,
                vendor_root.string() + " produced an unparsable purl '" + component.purl + "'",
                "vendored");
  }

  spdlog::debug("vendored: {} -> {} [{}]", vendor_root.string(), component.purl,
                core::to_string(confidence));
  return component;
}

}  // namespace

std::string folder_derived_purl(const fs::path& vendor_root)
{
  return "pkg:generic/" + core::percent_encode(vendor_root.filename().string());
}

core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                 const fs::path& root, ParseLimits limits)
{
  core::Result<std::vector<core::Component>> result;

  std::map<fs::path, std::vector<fs::path>> files_by_vendor_root;
  for (const fs::path& relative_path : file_index.files)
  {
    // Shared with the fingerprint matcher (heuristics/vendor_root.hpp), which
    // scores the same roots by content: the two join on this path, so the rule
    // that produces it lives in one place. The DNS-namespace-container skip
    // that used to sit here is part of that rule now.
    const std::optional<fs::path> vendor_root = vendor_root_for(relative_path);
    if (!vendor_root.has_value())
    {
      continue;
    }
    files_by_vendor_root[*vendor_root].push_back(relative_path);
  }

  std::error_code root_absolute_error;
  const fs::path containment_root = fs::absolute(root, root_absolute_error).lexically_normal();
  const bool containment_root_valid = !root_absolute_error;

  result.value.reserve(files_by_vendor_root.size());
  for (const auto& [vendor_root, files] : files_by_vendor_root)
  {
    core::Component component = build_component(root, vendor_root, files, limits,
                                                containment_root_valid, containment_root, result);
    result.value.push_back(std::move(component));
  }

  // Deterministic order (rule 3), matching every other producer.
  std::sort(result.value.begin(), result.value.end(),
            [](const core::Component& left, const core::Component& right)
            { return left.purl < right.purl; });

  spdlog::debug("vendored-code heuristic: {} component(s)", result.value.size());
  return result;
}

std::vector<std::string_view> recognized_license_spdx_ids()
{
  std::vector<std::string_view> ids;
  ids.reserve(std::size(kRecognizedLicenses));
  for (const RecognizedLicense& candidate : kRecognizedLicenses)
  {
    ids.push_back(candidate.spdx_id);
  }
  return ids;
}

}  // namespace bomwerk::heuristics::vendored_cpp
