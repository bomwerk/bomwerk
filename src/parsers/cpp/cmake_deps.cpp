#include "parsers/cpp/cmake_deps.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "core/exclusions.hpp"
#include "core/file_io.hpp"
#include "core/git_url.hpp"
#include "core/model.hpp"
#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/result.hpp"
#include "core/submodule_paths.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"
#include "parsers/cpp/cmake_scanner.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::cpp::cmake_deps
{
namespace
{

/// CPM's single-argument shorthand mini-DSL defines exactly these prefixes
/// (`gh:owner/repo@v`). An unknown prefix is surfaced as a warning by the
/// caller, never guessed: inventing prefixes CPM itself rejects would
/// fabricate dependencies. Extending support is one row here.
struct ShorthandForge
{
  std::string_view prefix;  ///< shorthand scheme, e.g. "gh"
  std::string_view host;    ///< forge host it expands to
};
constexpr ShorthandForge kShorthandForges[] = {
    {"gh", "github.com"}, {"gl", "gitlab.com"}, {"bb", "bitbucket.org"}};

/// CPM/FetchContent repository keyword -> forge URL prefix
/// (`GITHUB_REPOSITORY owner/repo`). Checked in this order, so a bare
/// `GIT_REPOSITORY <url>` (empty prefix: the value is already a full URL) is
/// the fallback after the three named forges.
struct ForgeKeyword
{
  std::string_view keyword;
  std::string_view url_prefix;
};
constexpr ForgeKeyword kForgeKeywords[] = {{"GITHUB_REPOSITORY", "https://github.com/"},
                                           {"GITLAB_REPOSITORY", "https://gitlab.com/"},
                                           {"BITBUCKET_REPOSITORY", "https://bitbucket.org/"},
                                           {"GIT_REPOSITORY", ""}};

/// Legacy VCS keywords FetchContent/ExternalProject still accept. They have no
/// first-class purl type, so components pin the exact URL in a `vcs_url`
/// qualifier: old systems are reported, never silently dropped.
struct LegacyVcsKeyword
{
  std::string_view repository_keyword;  ///< e.g. "SVN_REPOSITORY"
  std::string_view version_keyword;     ///< e.g. "SVN_REVISION"
  std::string_view vcs_kind;            ///< vcs_url scheme, e.g. "svn"
};
constexpr LegacyVcsKeyword kLegacyVcsKeywords[] = {{"SVN_REPOSITORY", "SVN_REVISION", "svn"},
                                                   {"HG_REPOSITORY", "HG_TAG", "hg"},
                                                   {"CVS_REPOSITORY", "CVS_TAG", "cvs"}};

/// Exactly the archive forms CMake's ExternalProject/FetchContent download
/// step extracts (Modules/ExternalProject.cmake). Formats CMake cannot extract
/// (rar, deb, rpm, …) are deliberately absent: a URL naming one can never be a
/// buildable CMake dependency, so guessing a version from it would be noise.
/// Compound suffixes precede their overlapping short forms so one
/// left-to-right `ends_with` pass strips the longest match.
constexpr std::string_view kArchiveSuffixes[] = {".tar.gz", ".tgz", ".tar.bz2", ".tbz2",
                                                 ".tar.xz", ".txz", ".tar.zst", ".tzst",
                                                 ".zip",    ".7z",  ".tar"};

constexpr std::string_view kUnknownComponentName = "unknown";

/// A value CMake resolves only at configure time: a `${var}` reference or a
/// `$<...>` generator expression: cannot be pinned by static parsing, so the
/// component built from it is low-confidence.
bool contains_unresolved(std::string_view text)
{
  return text.find("${") != std::string_view::npos || text.find("$<") != std::string_view::npos;
}

bool is_all_digits(std::string_view text)
{
  if (text.empty())
  {
    return false;
  }
  for (const char character : text)
  {
    if (character < '0' || character > '9')
    {
      return false;
    }
  }
  return true;
}

/// The argument immediately after the first occurrence of `keyword` (matched
/// case-insensitively, allocation-free), or nullopt if the keyword is absent
/// or has no value. Example: `keyword_value({"NAME","fmt"}, "name")` -> `"fmt"`.
std::optional<std::string> keyword_value(const std::vector<std::string>& arguments,
                                         std::string_view keyword)
{
  for (std::size_t index = 0; index + 1 < arguments.size(); ++index)
  {
    if (core::equals_ascii_ignore_case(arguments[index], keyword))
    {
      return arguments[index + 1];
    }
  }
  return std::nullopt;
}

/// Best-effort version from an archive URL: single left-to-right pass over
/// views, no allocation until the returned copy. Take the filename, strip one
/// archive suffix, then the token after the last '-' when it starts with a
/// digit. Example: `guess_version_from_url(".../zlib-1.3.1.tar.gz")` ->
/// `"1.3.1"`; `guess_version_from_url(".../latest.zip")` -> `""`.
std::string guess_version_from_url(std::string_view url)
{
  const std::size_t last_slash = url.find_last_of('/');
  std::string_view filename =
      (last_slash == std::string_view::npos) ? url : url.substr(last_slash + 1);
  for (const std::string_view suffix : kArchiveSuffixes)
  {
    if (filename.size() > suffix.size() && filename.ends_with(suffix))
    {
      filename.remove_suffix(suffix.size());
      break;
    }
  }
  const std::size_t last_dash = filename.find_last_of('-');
  if (last_dash == std::string_view::npos || last_dash + 1 >= filename.size())
  {
    return {};
  }
  const std::string_view version_candidate = filename.substr(last_dash + 1);
  if (version_candidate.front() < '0' || version_candidate.front() > '9')
  {
    return {};
  }
  return std::string(version_candidate);
}

constexpr std::size_t kSvnRevisionFlagLength = 2;  // length of "-r" / "-R"

/// ExternalProject conventionally writes SVN revisions as `-r<rev>`; strip the
/// flag so the version is the bare revision. Example: `"-r1234"` -> `"1234"`.
std::string strip_svn_revision_prefix(const std::string& revision)
{
  std::string_view view(revision);
  if (view.size() > kSvnRevisionFlagLength && (view.substr(0, kSvnRevisionFlagLength) == "-r" ||
                                               view.substr(0, kSvnRevisionFlagLength) == "-R"))
  {
    view.remove_prefix(kSvnRevisionFlagLength);
  }
  return std::string(view);
}

struct ForgeTarget
{
  std::string url;
  std::string version;
};

/// True when `prefix` is one of CPM's defined shorthand schemes (`gh`/`gl`/
/// `bb`), regardless of whether the rest of the shorthand string is
/// well-formed. Lets the caller distinguish "recognized scheme, malformed
/// value" from "scheme CPM doesn't define at all" when warning.
bool is_known_shorthand_prefix(std::string_view prefix)
{
  for (const ShorthandForge& forge : kShorthandForges)
  {
    if (prefix == forge.prefix)
    {
      return true;
    }
  }
  return false;
}

/// Parse the CPM shorthand `<gh|gl|bb>:<owner>/<repo>[@v | #ref]` into a
/// synthesized forge URL + version, via kShorthandForges. Nullopt when the
/// prefix is not one CPM defines (the caller then reports it) or the form is
/// malformed. Example: `"gh:fmtlib/fmt#10.2.1"` ->
/// `{url: "https://github.com/fmtlib/fmt", version: "10.2.1"}`.
std::optional<ForgeTarget> parse_cpm_shorthand(const std::string& argument)
{
  const std::size_t colon = argument.find(':');
  if (colon == std::string::npos)
  {
    return std::nullopt;
  }
  const std::string_view prefix = std::string_view(argument).substr(0, colon);
  std::string_view host;
  for (const ShorthandForge& forge : kShorthandForges)
  {
    if (prefix == forge.prefix)
    {
      host = forge.host;
      break;
    }
  }
  if (host.empty())
  {
    return std::nullopt;
  }

  std::string remainder = argument.substr(colon + 1);
  std::string version;
  const std::size_t separator = std::min(remainder.find('@'), remainder.find('#'));
  if (separator != std::string::npos)
  {
    version = remainder.substr(separator + 1);
    remainder = remainder.substr(0, separator);
  }
  if (remainder.empty())
  {
    return std::nullopt;
  }
  return ForgeTarget{"https://" + std::string(host) + "/" + remainder, version};
}

bool is_cmake_file(const fs::path& path)
{
  if (path.filename() == "CMakeLists.txt")
  {
    return true;
  }
  return path.extension() == ".cmake";
}

bool is_declaration_command(std::string_view lower_name)
{
  return lower_name == "fetchcontent_declare" || lower_name == "externalproject_add" ||
         lower_name == "cpmaddpackage" || lower_name == "cpmfindpackage" ||
         lower_name == "cpmdeclarepackage";
}

bool is_make_available_command(std::string_view lower_name)
{
  return lower_name == "fetchcontent_makeavailable" || lower_name == "fetchcontent_populate";
}

/// `pkg:generic/<name>[@<version>]` with qualifiers in sorted key order
/// (`checksum` < `download_url`) for a canonical, byte-stable purl. Example:
/// `build_archive_purl("zlib", "1.3.1", "https://zlib.net/z.tar.gz",
/// "sha256:ab…")` -> `"pkg:generic/zlib@1.3.1?checksum=sha256:ab…&download_url=
/// https%3A%2F%2Fzlib.net%2Fz.tar.gz"`.
std::string build_archive_purl(const std::string& name, const std::string& version,
                               const std::string& url, const std::string& checksum_qualifier)
{
  std::string purl = "pkg:generic/" + core::percent_encode(name.empty() ? kUnknownComponentName
                                                                        : std::string_view{name});
  if (!version.empty())
  {
    purl += "@" + core::percent_encode(version);
  }
  purl += "?";
  if (!checksum_qualifier.empty())
  {
    purl += "checksum=" + checksum_qualifier + "&";
  }
  purl += "download_url=" + core::percent_encode(url);
  return purl;
}

core::Confidence lowered_by_one(core::Confidence confidence)
{
  if (confidence == core::Confidence::High)
  {
    return core::Confidence::Medium;
  }
  return core::Confidence::Low;
}

struct Extracted
{
  std::string name;
  std::string git_url;          ///< a full forge/raw git URL, if any
  std::string version;          ///< GIT_TAG / VERSION / shorthand / legacy revision
  std::string archive_url;      ///< URL keyword (source tarball), if any
  std::string url_hash;         ///< URL_HASH value, e.g. "SHA256=…", if any
  std::string legacy_vcs_kind;  ///< "svn" | "hg" | "cvs" when a legacy keyword matched
  std::string legacy_vcs_url;   ///< the legacy repository URL
  std::string unrecognized_shorthand_prefix;  ///< "xx" from an unknown "xx:" CPM arg
  bool declare_only = false;
};

/// Pull the fields we care about out of one declaration command. `declare_only`
/// is true for CPMDeclarePackage and for a FetchContent_Declare whose name never
/// appears in a FetchContent_MakeAvailable call. `lower_name` is
/// `command.name` already lower-cased by the caller (parse() needs it too, to
/// route the command before this function ever sees it), so it is not
/// recomputed here.
Extracted extract_declaration(const CmakeCommand& command, const std::string& lower_name,
                              const std::set<std::string>& made_available)
{
  Extracted extracted;
  const std::vector<std::string>& arguments = command.arguments;
  const bool is_cpm = lower_name == "cpmaddpackage" || lower_name == "cpmfindpackage" ||
                      lower_name == "cpmdeclarepackage";

  if (is_cpm && arguments.size() == 1)
  {
    const std::string& argument = arguments.front();
    const std::optional<ForgeTarget> shorthand = parse_cpm_shorthand(argument);
    if (shorthand.has_value())
    {
      extracted.git_url = shorthand->url;
      extracted.version = shorthand->version;
      extracted.name = core::parse_git_remote(shorthand->url).repo;
    }
    else
    {
      extracted.name = argument;
      const std::size_t colon = argument.find(':');
      if (colon != std::string::npos)
      {
        extracted.unrecognized_shorthand_prefix = argument.substr(0, colon);
      }
    }
  }
  else
  {
    if (is_cpm)
    {
      extracted.name = keyword_value(arguments, "NAME").value_or(std::string{});
    }
    else if (!arguments.empty())
    {
      extracted.name = arguments.front();  // FetchContent/ExternalProject: name is positional
    }

    for (const ForgeKeyword& forge : kForgeKeywords)
    {
      const std::optional<std::string> repository = keyword_value(arguments, forge.keyword);
      if (repository.has_value())
      {
        extracted.git_url = std::string(forge.url_prefix) + *repository;
        break;
      }
    }

    const std::optional<std::string> git_tag = keyword_value(arguments, "GIT_TAG");
    const std::optional<std::string> version = keyword_value(arguments, "VERSION");
    if (git_tag.has_value())
    {
      extracted.version = *git_tag;
    }
    else if (version.has_value())
    {
      extracted.version = *version;
    }

    const std::optional<std::string> url = keyword_value(arguments, "URL");
    if (url.has_value())
    {
      extracted.archive_url = *url;
    }
    const std::optional<std::string> url_hash = keyword_value(arguments, "URL_HASH");
    if (url_hash.has_value())
    {
      extracted.url_hash = *url_hash;
    }

    for (const LegacyVcsKeyword& legacy : kLegacyVcsKeywords)
    {
      const std::optional<std::string> repository =
          keyword_value(arguments, legacy.repository_keyword);
      if (repository.has_value())
      {
        extracted.legacy_vcs_kind = std::string(legacy.vcs_kind);
        extracted.legacy_vcs_url = *repository;
        if (extracted.version.empty())
        {
          const std::optional<std::string> revision =
              keyword_value(arguments, legacy.version_keyword);
          if (revision.has_value())
          {
            extracted.version =
                (legacy.vcs_kind == "svn") ? strip_svn_revision_prefix(*revision) : *revision;
          }
        }
        break;
      }
    }
  }

  if (extracted.name.empty() && !extracted.git_url.empty())
  {
    extracted.name = core::parse_git_remote(extracted.git_url).repo;
  }

  if (lower_name == "cpmdeclarepackage")
  {
    extracted.declare_only = true;
  }
  else if (lower_name == "fetchcontent_declare")
  {
    extracted.declare_only = made_available.count(core::to_lower_ascii(extracted.name)) == 0;
  }
  // CPMAddPackage/CPMFindPackage/ExternalProject_Add build immediately: not
  // declare-only (default false).
  return extracted;
}

struct SourcedCommand
{
  CmakeCommand command;
  std::string source_label;
  std::string lower_name;  ///< already-lowered command.name, computed once in parse()
};

/// If `unresolved`, downgrade `confidence` to Low and warn that
/// `component_name` carries an unresolved `${var}`/`$<...>`: the one piece of
/// logic every purl-building branch below needs, so it lives in one place
/// instead of three copies that could drift.
void apply_unresolved_downgrade(bool unresolved, const std::string& source_label,
                                const std::string& component_name, core::Confidence& confidence,
                                core::Result<std::vector<core::Component>>& result)
{
  if (unresolved)
  {
    confidence = core::Confidence::Low;
    result.warn(core::WarningCode::kUnresolvedVariableOrInterpolation,
                "cmake: '" + source_label + "' dependency '" + component_name +
                    "' has an unresolved variable; reported at low confidence",
                "cmake");
  }
}

std::optional<core::Component> component_from_declaration(
    const CmakeCommand& command, const std::string& source_label, const std::string& lower_name,
    const std::set<std::string>& made_available, core::Result<std::vector<core::Component>>& result)
{
  const Extracted extracted = extract_declaration(command, lower_name, made_available);

  if (!extracted.unrecognized_shorthand_prefix.empty())
  {
    const bool prefix_is_known = is_known_shorthand_prefix(extracted.unrecognized_shorthand_prefix);
    result.warn(
        core::WarningCode::kDependencyMissingSource,
        "cmake: '" + source_label + "' uses a " +
            (prefix_is_known ? std::string{"malformed CPM shorthand (empty owner/repo) for prefix"}
                             : std::string{"CPM shorthand with an unrecognized prefix"}) +
            " '" + extracted.unrecognized_shorthand_prefix + ":'; treated as a bare package name",
        "cmake");
  }

  const bool has_repository = !extracted.git_url.empty();
  const bool has_archive = !extracted.archive_url.empty();
  const bool has_legacy_vcs = !extracted.legacy_vcs_url.empty();
  if (!has_repository && !has_archive && !has_legacy_vcs && extracted.name.empty())
  {
    result.warn(core::WarningCode::kDependencyMissingSource,
                "cmake: '" + source_label + "' has a " + command.name +
                    " call with no name, repository or URL; skipped",
                "cmake");
    return std::nullopt;
  }

  core::Component component;
  component.name = extracted.name.empty() ? std::string(kUnknownComponentName) : extracted.name;
  std::string version = extracted.version;
  core::Confidence confidence = core::Confidence::Medium;

  if (has_repository)
  {
    const bool unresolved = contains_unresolved(extracted.git_url) || contains_unresolved(version);
    // Normalize here as well as inside build_git_purl so the emitted `version`
    // field and the purl's version agree; a tag passes through untouched.
    version = core::normalized_object_id(version);
    component.version = version;
    component.purl = core::build_git_purl(extracted.git_url, version, component.name);
    // NTIA/CRA supplier evidence straight from GIT_REPOSITORY's owner
    // segment. Deliberately not attempted for the archive/URL branch below :
    // parsing an arbitrary download URL's path as host/owner/repo produces
    // garbage far more often than a real owner, and inventing supplier data
    // would be worse than the honest gap.
    component.supplier = core::parse_git_remote(extracted.git_url).owner;
    if (core::is_hex_object_id(version))
    {
      confidence = core::Confidence::High;
    }
    else
    {
      apply_unresolved_downgrade(unresolved, source_label, component.name, confidence, result);
    }
  }
  else if (has_archive)
  {
    if (version.empty())
    {
      version = guess_version_from_url(extracted.archive_url);
      if (version.empty())
      {
        spdlog::debug("cmake: no version recognizable in archive url '{}' ({})",
                      extracted.archive_url, source_label);
      }
    }
    const bool unresolved =
        contains_unresolved(extracted.archive_url) || contains_unresolved(version);
    std::string checksum_qualifier;
    const std::size_t equals = extracted.url_hash.find('=');
    if (equals != std::string::npos && equals + 1 < extracted.url_hash.size())
    {
      const std::string algorithm =
          core::to_lower_ascii(std::string_view(extracted.url_hash).substr(0, equals));
      // Lower-case the digest as well as the algorithm: purl-spec defines the
      // `checksum` qualifier as lower-case hex, and without this one archive
      // written "SHA256=AB…" in one manifest and "sha256=ab…" in another splits
      // into two components with two bom-ref UUIDs (rule 3).
      const std::string hex =
          core::to_lower_ascii(std::string_view(extracted.url_hash).substr(equals + 1));
      // Reject a non-hex value outright: unvalidated, it could inject '&'/'='
      // into the purl query string (a hostile URL_HASH crafted to look like
      // "SHA256=abc&download_url=evil") or leave garbage in Component::sha256.
      if (core::is_hex_digits(hex))
      {
        checksum_qualifier = algorithm + ":" + hex;
        if (algorithm == "sha256")
        {
          component.sha256 = hex;
        }
      }
      else
      {
        result.warn(core::WarningCode::kMalformedEntrySkipped,
                    "cmake: '" + source_label + "' dependency '" + component.name +
                        "' has a URL_HASH value that is not valid hex; ignoring the checksum",
                    "cmake");
      }
    }
    component.version = version;
    component.purl =
        build_archive_purl(component.name, version, extracted.archive_url, checksum_qualifier);
    if (!checksum_qualifier.empty() && !unresolved)
    {
      confidence = core::Confidence::High;
    }
    else
    {
      apply_unresolved_downgrade(unresolved, source_label, component.name, confidence, result);
    }
  }
  else if (has_legacy_vcs)
  {
    // svn/hg/cvs (legacy ExternalProject/FetchContent keywords): no first-class
    // purl type exists, so pin the exact URL in a vcs_url qualifier, mirroring
    // the generic git fallback.
    const bool unresolved =
        contains_unresolved(extracted.legacy_vcs_url) || contains_unresolved(version);
    component.version = version;
    component.purl = "pkg:generic/" + core::percent_encode(component.name);
    if (!version.empty())
    {
      component.purl += "@" + core::percent_encode(version);
    }
    component.purl += "?vcs_url=" + core::percent_encode(extracted.legacy_vcs_kind + "+" +
                                                         extracted.legacy_vcs_url);
    apply_unresolved_downgrade(unresolved, source_label, component.name, confidence, result);
    if (!unresolved && extracted.legacy_vcs_kind == "svn" && is_all_digits(version))
    {
      confidence = core::Confidence::High;  // an SVN revision number is immutable
    }
  }
  else
  {
    component.version = version;
    component.purl = "pkg:generic/" + core::percent_encode(component.name);
    if (!version.empty())
    {
      component.purl += "@" + core::percent_encode(version);
    }
    confidence = core::Confidence::Low;
    result.warn(core::WarningCode::kDependencyMissingSource,
                "cmake: '" + source_label + "' declares '" + component.name +
                    "' with no repository or URL; reported as a generic component",
                "cmake");
  }

  if (extracted.declare_only)
  {
    confidence = lowered_by_one(confidence);
  }

  // A command the lexer could not fully parse (unterminated quote/paren, caps
  // tripped) yields values we cannot trust: cap it at Low regardless of how
  // pinned the recovered text looks, and say so in the evidence.
  if (!command.well_formed)
  {
    confidence = core::Confidence::Low;
  }

  // Dogfood core::Purl: a purl we cannot parse back is a builder bug, not merely
  // degraded input: surface it so tests/fuzzers catch it (as submodules does).
  const core::Result<core::Purl> validated = core::Purl::parse(component.purl);
  if (!validated.complete)
  {
    result.warn(
        core::WarningCode::kPurlValidationFailed,
        "cmake: '" + source_label + "' produced an unparsable purl '" + component.purl + "'",
        "cmake");
  }

  std::string detail = source_label + " -> " + command.name + "(" + component.name + ")";
  if (extracted.declare_only)
  {
    detail += " [declared, not confirmed built]";
  }
  if (!command.well_formed)
  {
    detail += " [from a malformed declaration]";
  }
  component.evidence.push_back({core::Source::Manifest, detail, confidence});
  return component;
}

}  // namespace

core::Result<std::vector<core::Component>> parse(const fs::path& root)
{
  return parse(root, ParseLimits{});
}

core::Result<std::vector<core::Component>> parse(const fs::path& root, const ParseLimits& limits)
{
  std::error_code directory_error;
  if (!fs::is_directory(root, directory_error) || directory_error)
  {
    spdlog::debug("cmake: '{}' is not a scannable directory", root.string());
    return {};  // nothing to scan; not an error
  }

  const core::Result<core::FileIndex> file_index =
      core::build_file_index(root, core::default_excluded_dir_names(),
                             core::with_submodule_subtrees(root, limits.excluded_subtrees));

  core::Result<std::vector<core::Component>> result = parse(file_index.value, root, limits);
  for (const core::Warning& warning : file_index.warnings)
  {
    result.warn(warning);
  }
  return result;
}

core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                 const fs::path& root, const ParseLimits& limits)
{
  core::Result<std::vector<core::Component>> result;

  // file_index.files is already sorted (core::build_file_index, rule 3); this
  // filter preserves that order, so cmake_files needs no re-sort before the
  // cap below.
  std::vector<fs::path> cmake_files;
  for (const fs::path& relative_path : file_index.files)
  {
    if (is_cmake_file(relative_path))
    {
      cmake_files.push_back(relative_path);
    }
  }

  if (cmake_files.size() > limits.max_scanned_files)
  {
    result.warn(core::WarningCode::kFileLimitReached,
                "cmake: " + std::to_string(cmake_files.size()) + " CMake files exceed the " +
                    std::to_string(limits.max_scanned_files) +
                    "-file limit; scanning the first files in sorted order only",
                "cmake");
    cmake_files.resize(limits.max_scanned_files);
  }

  std::vector<SourcedCommand> declarations;
  std::set<std::string> made_available;
  bool declarations_capped = false;
  for (const fs::path& relative_path : cmake_files)
  {
    const std::string source_label = relative_path.string();
    const fs::path file_path = root / relative_path;

    const core::BoundedFileRead file_read =
        core::read_file_bounded(file_path, limits.max_file_bytes);
    if (!file_read.readable)
    {
      result.warn(core::WarningCode::kUnreadableFile, "cmake: cannot read '" + source_label + "'",
                  "cmake");
      continue;
    }
    if (file_read.truncated)
    {
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "cmake: '" + source_label + "' exceeds the " +
                      std::to_string(limits.max_file_bytes) +
                      "-byte cap; only the first part scanned",
                  "cmake");
    }

    core::Result<std::vector<CmakeCommand>> scanned = scan_cmake_commands(file_read.bytes);
    static constexpr std::string_view kUnterminatedCommandPrefix = "cmake: unterminated command ";
    for (const core::Warning& warning : scanned.warnings)
    {
      // A truncated read always leaves the last in-flight command looking
      // "unterminated" to the scanner, purely as a side effect of the cap
      // cutting the file off mid-command: not a separate defect worth its
      // own warning on top of the cap warning already emitted above.
      if (file_read.truncated && warning.message.starts_with(kUnterminatedCommandPrefix))
      {
        continue;
      }
      result.warn(core::Warning{warning.code, source_label + ": " + warning.message,
                                warning.ecosystem, warning.affected_path});
    }
    for (CmakeCommand& command : scanned.value)
    {
      const std::string lower_name = core::to_lower_ascii(command.name);
      if (is_make_available_command(lower_name))
      {
        // A malformed/truncated MakeAvailable call cannot be trusted to name
        // every argument it was meant to: recovering the wrong dependency as
        // "confirmed built" would raise its confidence on bad evidence.
        if (command.well_formed)
        {
          for (const std::string& argument : command.arguments)
          {
            // FetchContent treats the dependency name case-insensitively
            // (cmake.org/cmake/help/latest/module/FetchContent.html), so
            // `FetchContent_Declare(GoogleTest ...)` followed by
            // `FetchContent_MakeAvailable(googletest)` refers to the same
            // dependency; normalize case here to match extract_declaration's
            // lookup below.
            made_available.insert(core::to_lower_ascii(argument));
          }
        }
        else
        {
          result.warn(
              core::WarningCode::kMalformedEntrySkipped,
              "cmake: '" + source_label + "' has a malformed " + command.name +
                  " call; its arguments are not trusted to confirm any dependency was built",
              "cmake");
        }
      }
      else if (is_declaration_command(lower_name))
      {
        if (declarations.size() >= limits.max_total_declarations)
        {
          if (!declarations_capped)
          {
            result.warn(core::WarningCode::kEntryLimitReached,
                        "cmake: more than " + std::to_string(limits.max_total_declarations) +
                            " dependency declarations; ignoring the rest",
                        "cmake");
            declarations_capped = true;
          }
          continue;
        }
        declarations.push_back({std::move(command), source_label, lower_name});
      }
    }
  }

  std::vector<core::Component> components;
  for (const SourcedCommand& declaration : declarations)
  {
    std::optional<core::Component> component =
        component_from_declaration(declaration.command, declaration.source_label,
                                   declaration.lower_name, made_available, result);
    if (component.has_value())
    {
      spdlog::debug("cmake {} -> {}", declaration.source_label, component->purl);
      components.push_back(std::move(*component));
    }
  }

  // Dedup + canonical purl ordering (rule 3): a dep declared in two files, or
  // declared then made-available, collapses to one component with merged
  // evidence. run_scan merges again over all producers: idempotent.
  result.value = core::merge_all(std::move(components));
  spdlog::debug("parsed CMake dependencies: {} components from {} files", result.value.size(),
                cmake_files.size());
  return result;
}

}  // namespace bomwerk::parsers::cpp::cmake_deps
