#include "heuristics/vendored_cpp.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
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
#include "heuristics/vendoring_record.hpp"

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

/// Which statement assigns the value: a C preprocessor `#define`, or a CMake
/// `set()` in the library's own build file. Like `MacroValueForm`, a property
/// of the table.
enum class AssignmentSyntax
{
  CDefine,  ///< `#define NAME value`
  CMakeSet  ///< `set(NAME value)`
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
// numbers on three lines, read only through the split table below.
constexpr VersionHeaderSignature kBareDottedVersionSignatures[] = {
    {"uthash", "uthash.h", "UTHASH_VERSION"},
};

/// A library whose header writes its release as three separate integer macros.
struct SplitVersionSignature
{
  std::string_view canonical_name;
  std::string_view header_filename;
  std::string_view major_macro;
  std::string_view minor_macro;
  std::string_view patch_macro;
};

// Libraries whose header splits the release across MAJOR, MINOR and PATCH
// macros, one bare integer per line. Every row is opt-in and checked against
// upstream before it is added, because a MAJOR/MINOR pair is not always the
// release: libsodium's `SODIUM_LIBRARY_VERSION_MAJOR` is the ABI version, and
// assembling it would assert a release that does not exist. That is why this
// is a table of named libraries and not a pattern over any `*_VERSION_MAJOR`.
//
// cJSON: upstream's cJSON.h sets the three macros to the release tag's numbers
// (tag v1.7.15 ships MAJOR 1, MINOR 7, PATCH 15).
constexpr SplitVersionSignature kSplitVersionSignatures[] = {
    {"cjson", "cJSON.h", "CJSON_VERSION_MAJOR", "CJSON_VERSION_MINOR", "CJSON_VERSION_PATCH"},
};

// Libraries whose OWN top-level CMakeLists.txt sets the release, read only
// from `<vendor root>/CMakeLists.txt` and only when the folder names the
// library. `set(VERSION ...)` is the most generic assignment there is, so the
// row is what makes it safe: libjpeg-turbo's build file opens with
// `set(VERSION 3.1.2)` for its own release (upstream tag 3.1.2, the same line
// OpenCV's 3rdparty copy keeps), while the same variable in some other
// project's build file means nothing to us.
constexpr VersionHeaderSignature kCMakeVersionSignatures[] = {
    {"libjpeg-turbo", "CMakeLists.txt", "VERSION"},
};

// The same split-release shape as above, written as CMake `set()` calls. The
// third part is whatever the row names: openjpeg calls it `_BUILD`
// (`set(OPENJPEG_VERSION_BUILD 3)` in upstream's CMakeLists.txt at tag
// v2.5.3, the source of its 2.5.3 release number), not `_PATCH`.
constexpr SplitVersionSignature kCMakeSplitVersionSignatures[] = {
    {"openjpeg", "CMakeLists.txt", "OPENJPEG_VERSION_MAJOR", "OPENJPEG_VERSION_MINOR",
     "OPENJPEG_VERSION_BUILD"},
};

/// How an encoded-integer version macro packs its release into one number.
enum class EncodedVersionRule
{
  /// `MAJOR * 1000000 + MINOR * 1000 + PATCH`: `3019001` is 3.19.1.
  MajorMillionsMinorThousands
};

/// A library whose header writes its release as ONE bare integer that a named
/// rule decodes.
struct EncodedVersionSignature
{
  std::string_view canonical_name;
  std::string_view header_filename;
  std::string_view version_macro;
  EncodedVersionRule rule;
};

// Libraries whose header packs the release into one integer. Each row names
// its decoding rule, and the folder must name the library.
//
// protobuf: `stubs/common.h` writes it as `GOOGLE_PROTOBUF_VERSION` (3019001
// at tag v3.19.1, 5029000 at v29.0), and `port_def.inc` as `PROTOBUF_VERSION`
// in the 3.x and 22.x releases (3019001 at v3.19.1, 4022000 at v22.0). The
// number is the C++ runtime's version. Up to 3.21 that is also the release
// tag; from 22.0 on upstream tags the repository `v22.0` while the C++
// runtime it ships is 4.22.0. The decoded value is the runtime's, because
// that is what the header states.
constexpr EncodedVersionSignature kEncodedIntegerVersionSignatures[] = {
    {"protobuf", "port_def.inc", "PROTOBUF_VERSION",
     EncodedVersionRule::MajorMillionsMinorThousands},
    {"protobuf", "common.h", "GOOGLE_PROTOBUF_VERSION",
     EncodedVersionRule::MajorMillionsMinorThousands},
};

/// Fewest digits an encoded version may have: seven puts the major part at 1
/// or more, so `999` or `0` is never read as release `0.0.999`.
constexpr std::size_t kMinEncodedVersionDigits = 7u;

/// Cap on a bare dotted value's length. A version is a handful of characters;
/// a header cannot make this scan return a megabyte-long "version" that then
/// reaches a purl.
constexpr std::size_t kMaxBareVersionChars = 64u;

/// Cap on one integer part of a split version. Nine digits fit any real
/// release number and can never overflow anything downstream.
constexpr std::size_t kMaxVersionPartDigits = 9u;

struct VersionMatch
{
  std::string canonical_name;
  std::string version;
  fs::path relative_path;  ///< root-relative path of the matched header
  /// The macro line(s) as the header wrote them, for the evidence entry. A bare
  /// `2.4.0` is not shown as `"2.4.0"`: evidence that misquotes the file is
  /// worse than none.
  std::string quoted_lines;
};

bool is_blank(char character)
{
  return character == ' ' || character == '\t';
}

/// True when a CMake `set(NAME value)` ends cleanly right after its value at
/// `token_end`: optional blanks, the closing `)`, then nothing on the line but
/// blanks, a CR or a `#` comment. A second argument (`set(VERSION 3.1.2 3.1.3)`
/// is a list, `set(X 1 CACHE ...)` something else again) means the value is
/// not the plain number it looked like.
bool cmake_set_ends_cleanly(const std::string& content, std::size_t token_end, std::size_t line_end)
{
  std::size_t cursor = token_end;
  while (cursor < line_end && is_blank(content[cursor]))
  {
    ++cursor;
  }
  if (cursor >= line_end || content[cursor] != ')')
  {
    return false;
  }
  ++cursor;
  while (cursor < line_end && (is_blank(content[cursor]) || content[cursor] == '\r'))
  {
    ++cursor;
  }
  return cursor >= line_end || content[cursor] == '#';
}

/// True when the character right after a bare value ends it cleanly. For a
/// `#define`: whitespace, a CR (CRLF line endings), or the start of a `//` or
/// `/*` comment. Anything else (`15u`, `2.4.0abc`, `15/2`, a `\` continuation)
/// means the token is not the plain number it looked like. For a CMake
/// `set()`, see `cmake_set_ends_cleanly`.
bool bare_value_ends_cleanly(const std::string& content, std::size_t token_end,
                             std::size_t line_end, AssignmentSyntax syntax)
{
  if (syntax == AssignmentSyntax::CMakeSet)
  {
    return cmake_set_ends_cleanly(content, token_end, line_end);
  }
  if (token_end >= line_end)
  {
    return true;
  }
  const char terminator = content[token_end];
  if (terminator == ' ' || terminator == '\t' || terminator == '\r')
  {
    return true;
  }
  if (terminator == '/' && token_end + 1 < line_end)
  {
    const char next = content[token_end + 1];
    return next == '/' || next == '*';
  }
  return false;
}

/// The value of a bare dotted `#define`, read from `value_start` to the end of
/// its line: `2.4.0` from `#define UTHASH_VERSION 2.4.0`. `nullopt` unless the
/// value is digits and single dots only, starts and ends on a digit, has at
/// least one dot, fits `kMaxBareVersionChars`, and is followed by nothing but
/// whitespace or the start of a comment. Anything else is not a version:
/// `2.4.0abc` and `2.4.0-dev` are not read as `2.4.0`, a value ending in a line
/// continuation is not read at all, and a bare `2` (an API revision) never
/// qualifies.
std::optional<std::string> read_bare_dotted_value(const std::string& content,
                                                  std::size_t value_start, std::size_t line_end,
                                                  AssignmentSyntax syntax)
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
  if (!bare_value_ends_cleanly(content, token_end, line_end, syntax))
  {
    return std::nullopt;
  }
  return content.substr(value_start, token_length);
}

/// The value of a bare integer `#define`, one part of a split version: `15`
/// from `#define CJSON_VERSION_PATCH 15`. `nullopt` unless the value is digits
/// only, at most `kMaxVersionPartDigits` of them, without a leading zero (`07`
/// is octal in C, and no release writes its parts that way), and ends cleanly
/// (see `bare_value_ends_cleanly`). `-1`, `7.0`, `15u` and `"7"` are all
/// rejected, never trimmed down to a number.
std::optional<std::string> read_bare_integer_value(const std::string& content,
                                                   std::size_t value_start, std::size_t line_end,
                                                   AssignmentSyntax syntax)
{
  std::size_t token_end = value_start;
  while (token_end < line_end && content[token_end] >= '0' && content[token_end] <= '9')
  {
    ++token_end;
  }
  const std::size_t token_length = token_end - value_start;
  if (token_length == 0 || token_length > kMaxVersionPartDigits)
  {
    return std::nullopt;
  }
  if (token_length > 1 && content[value_start] == '0')
  {
    return std::nullopt;
  }
  if (!bare_value_ends_cleanly(content, token_end, line_end, syntax))
  {
    return std::nullopt;
  }
  return content.substr(value_start, token_length);
}

/// The value of a quoted-string `#define`: `1.2.11` from `"1.2.11"`. `nullopt`
/// unless the value opens with a quote that closes on the same line.
std::optional<std::string> read_quoted_value(const std::string& content, std::size_t value_start,
                                             std::size_t line_end)
{
  if (value_start >= line_end || content[value_start] != '"')
  {
    return std::nullopt;
  }
  const std::size_t closing_quote = content.find('"', value_start + 1);
  if (closing_quote == std::string::npos || closing_quote >= line_end)
  {
    return std::nullopt;  // unterminated within the line
  }
  if (closing_quote == value_start + 1)
  {
    // `#define X ""` states no version. Returning it would report a match with
    // an empty version (found by fuzzing, T40); declining lets a later real
    // definition of the same macro still win.
    return std::nullopt;
  }
  return content.substr(value_start + 1, closing_quote - value_start - 1);
}

std::optional<std::string> read_macro_value(const std::string& content, std::size_t value_start,
                                            std::size_t line_end, MacroValueForm form,
                                            AssignmentSyntax syntax)
{
  switch (form)
  {
    case MacroValueForm::QuotedString:
      return read_quoted_value(content, value_start, line_end);
    case MacroValueForm::BareDotted:
      return read_bare_dotted_value(content, value_start, line_end, syntax);
  }
  return std::nullopt;
}

/// True when only blanks sit between the start of `position`'s line and
/// `position`: the assignment is a real statement, not a mention inside a
/// comment (`// #define X 1`, `# set(X 1)`) or a longer expression.
bool only_blanks_before_on_line(const std::string& content, std::size_t position)
{
  std::size_t line_start = position;
  while (line_start > 0 && is_blank(content[line_start - 1]))
  {
    --line_start;
  }
  return line_start == 0 || content[line_start - 1] == '\n';
}

/// Visit every `#define <macro_name>` in `content` whose name is the whole
/// identifier: a macro name that is only a prefix of a longer one (e.g.
/// `ZLIB_VERSION_H` when searching for `ZLIB_VERSION`) is skipped. A mention in
/// a comment without `#define` in front never matches at all. `visit` gets the
/// offset of the value (past the whitespace after the name) and the end of
/// that source line, so no reader can scan past its own line, and returns
/// true to stop the walk.
template <typename Visitor>
void for_each_define(const std::string& content, std::string_view macro_name, Visitor&& visit)
{
  const std::string needle = "#define " + std::string(macro_name);
  std::size_t search_from = 0;
  while (search_from <= content.size())
  {
    const std::size_t position = content.find(needle, search_from);
    if (position == std::string::npos)
    {
      return;
    }
    // However this occurrence turns out, the next search starts right after
    // it: never past a later, possibly-real occurrence of the same needle.
    search_from = position + 1;

    // Only a real directive: nothing but blanks may precede `#define` on its
    // line. A commented-out `// #define X 1` or `/* #define X 1 */` is not a
    // definition and must never supply (or duplicate) a version part.
    if (!only_blanks_before_on_line(content, position))
    {
      continue;
    }

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
    if (visit(cursor, search_end))
    {
      return;
    }
  }
}

/// Visit every `set(<variable_name> <value>)` in a CMake file, the CMake
/// counterpart of `for_each_define`: `set` in any case (CMake commands are
/// case-insensitive), blanks allowed around the `(`, only blanks before `set`
/// on its line (so a `# set(X 1)` comment never matches), and the variable
/// name followed by a blank and then its value on the same line. A name that
/// is only part of a longer one (`MY_VERSION`, `VERSION_MAJOR` when searching
/// for `VERSION`) is skipped, and so is a mention such as `${VERSION}`.
template <typename Visitor>
void for_each_cmake_set(const std::string& content, std::string_view variable_name, Visitor&& visit)
{
  constexpr std::string_view kSetCommand = "set";
  std::size_t search_from = 0;
  while (search_from < content.size())
  {
    const std::size_t position = content.find(variable_name, search_from);
    if (position == std::string::npos)
    {
      return;
    }
    search_from = position + 1;

    const std::size_t name_end = position + variable_name.size();
    if (name_end >= content.size() || !is_blank(content[name_end]))
    {
      continue;  // a longer identifier, or no value on this line
    }

    std::size_t cursor = position;
    while (cursor > 0 && is_blank(content[cursor - 1]))
    {
      --cursor;
    }
    if (cursor == 0 || content[cursor - 1] != '(')
    {
      continue;
    }
    --cursor;
    while (cursor > 0 && is_blank(content[cursor - 1]))
    {
      --cursor;
    }
    if (cursor < kSetCommand.size() ||
        !core::equals_ascii_ignore_case(
            std::string_view(content).substr(cursor - kSetCommand.size(), kSetCommand.size()),
            kSetCommand))
    {
      continue;
    }
    if (!only_blanks_before_on_line(content, cursor - kSetCommand.size()))
    {
      continue;  // `offset(VERSION 1)`, or a `#` comment
    }

    const std::size_t line_end = content.find('\n', name_end);
    const std::size_t search_end = (line_end == std::string::npos) ? content.size() : line_end;
    std::size_t value_start = name_end;
    while (value_start < search_end && is_blank(content[value_start]))
    {
      ++value_start;
    }
    if (visit(value_start, search_end))
    {
      return;
    }
  }
}

/// Visit every assignment of `name` in `syntax`: see `for_each_define` and
/// `for_each_cmake_set`.
template <typename Visitor>
void for_each_assignment(const std::string& content, std::string_view name, AssignmentSyntax syntax,
                         Visitor&& visit)
{
  if (syntax == AssignmentSyntax::CMakeSet)
  {
    for_each_cmake_set(content, name, std::forward<Visitor>(visit));
    return;
  }
  for_each_define(content, name, std::forward<Visitor>(visit));
}

/// How `syntax` writes `name` set to `value`, for an evidence entry that
/// quotes the file as it is written.
std::string written_assignment(AssignmentSyntax syntax, std::string_view name,
                               std::string_view value)
{
  if (syntax == AssignmentSyntax::CMakeSet)
  {
    return "set(" + std::string(name) + " " + std::string(value) + ")";
  }
  return "#define " + std::string(name) + " " + std::string(value);
}

/// Find an assignment of `macro_name` in `content` and return its value, read
/// in the given `form`. Each candidate occurrence is checked in turn: one that
/// isn't an assignment of the requested form on its line does not end the
/// search, since an unrelated earlier occurrence must never hide a real one
/// later in the same file. `nullopt` only once every occurrence has been tried
/// and none matched.
std::optional<std::string> extract_macro_value(const std::string& content,
                                               std::string_view macro_name, MacroValueForm form,
                                               AssignmentSyntax syntax)
{
  std::optional<std::string> value;
  for_each_assignment(content, macro_name, syntax,
                      [&](std::size_t value_start, std::size_t line_end)
                      {
                        value = read_macro_value(content, value_start, line_end, form, syntax);
                        return value.has_value();
                      });
  return value;
}

/// The value of `macro_name` as a bare integer, but only when `content` holds
/// exactly ONE `#define` of it and that one is a bare integer. A second
/// definition (an `#if` branch, a stray copy) makes the part ambiguous, and
/// picking either would be a guess, so it yields nothing. This is stricter
/// than `extract_macro_value` on purpose: a split version is assembled from
/// three of these, and one wrong part is a wrong version.
std::optional<std::string> extract_sole_integer(const std::string& content,
                                                std::string_view macro_name,
                                                AssignmentSyntax syntax)
{
  std::optional<std::string> value;
  std::size_t definitions = 0;
  for_each_assignment(content, macro_name, syntax,
                      [&](std::size_t value_start, std::size_t line_end)
                      {
                        ++definitions;
                        value = read_bare_integer_value(content, value_start, line_end, syntax);
                        return definitions > 1;  // a second definition already decides it
                      });
  if (definitions != 1)
  {
    return std::nullopt;
  }
  return value;
}

/// `MAJOR.MINOR.PATCH` from a split-version signature's three macros, all or
/// nothing: any part missing, duplicated, quoted or not a plain integer gives
/// `nullopt`, never a partial version such as `1.7`. Each macro is searched
/// over the whole read, so the order the file writes them in does not matter.
std::optional<VersionMatch> read_split_version(const std::string& content,
                                               const SplitVersionSignature& signature,
                                               const fs::path& relative_file,
                                               AssignmentSyntax syntax)
{
  const std::string_view part_macros[] = {signature.major_macro, signature.minor_macro,
                                          signature.patch_macro};
  std::string version;
  std::string quoted_lines;
  for (std::string_view macro : part_macros)
  {
    const std::optional<std::string> part = extract_sole_integer(content, macro, syntax);
    if (!part.has_value())
    {
      return std::nullopt;
    }
    if (!version.empty())
    {
      version += '.';
      quoted_lines += "; ";
    }
    version += *part;
    quoted_lines += written_assignment(syntax, macro, *part);
  }
  return VersionMatch{std::string(signature.canonical_name), version, relative_file, quoted_lines};
}

/// The release an encoded integer stands for under `rule`: `3019001` ->
/// `3.19.1`. `nullopt` for fewer than `kMinEncodedVersionDigits` digits.
/// `digits` comes from `read_bare_integer_value`, so it is at most
/// `kMaxVersionPartDigits` decimal digits with no leading zero and fits
/// `std::uint64_t` with room to spare.
std::optional<std::string> decode_version(std::string_view digits, EncodedVersionRule rule)
{
  if (digits.size() < kMinEncodedVersionDigits)
  {
    return std::nullopt;
  }
  constexpr std::uint64_t kDecimalBase = 10u;
  std::uint64_t number = 0;
  for (const char digit : digits)
  {
    number = number * kDecimalBase + static_cast<std::uint64_t>(digit - '0');
  }
  switch (rule)
  {
    case EncodedVersionRule::MajorMillionsMinorThousands:
    {
      constexpr std::uint64_t kMajorUnit = 1000000u;
      constexpr std::uint64_t kMinorUnit = 1000u;
      return std::to_string(number / kMajorUnit) + "." +
             std::to_string((number / kMinorUnit) % kMinorUnit) + "." +
             std::to_string(number % kMinorUnit);
    }
  }
  return std::nullopt;
}

/// An encoded-integer signature's release, read through the same
/// one-definition-only rule as a split part (a second `#define` makes it
/// ambiguous) and decoded by the row's rule.
std::optional<VersionMatch> read_encoded_version(const std::string& content,
                                                 const EncodedVersionSignature& signature,
                                                 const fs::path& relative_file)
{
  const std::optional<std::string> digits =
      extract_sole_integer(content, signature.version_macro, AssignmentSyntax::CDefine);
  if (!digits.has_value())
  {
    return std::nullopt;
  }
  const std::optional<std::string> version = decode_version(*digits, signature.rule);
  if (!version.has_value())
  {
    return std::nullopt;
  }
  return VersionMatch{
      std::string(signature.canonical_name), *version, relative_file,
      written_assignment(AssignmentSyntax::CDefine, signature.version_macro, *digits)};
}

/// Lowercase letters and digits only, so names compare across spelling:
/// `cjson-prebuilt` -> `cjsonprebuilt`, `cJSON` -> `cjson`.
std::string identity_key(std::string_view text)
{
  std::string key;
  key.reserve(text.size());
  for (const char character : text)
  {
    const auto byte = static_cast<unsigned char>(character);
    if (std::isalnum(byte) != 0)
    {
      key += static_cast<char>(std::tolower(byte));
    }
  }
  return key;
}

/// True when the vendored folder's own name carries the library's name:
/// `third_party/uthash` for uthash, `third_party/cjson-prebuilt` for cJSON.
///
/// The bare-dotted and split tables require this; the quoted table does not.
/// A bare `#define UTHASH_VERSION 1.9.1` says which library a HEADER is, not
/// which library the whole DIRECTORY is: godot's `thirdparty/libktx` bundles
/// `lib/uthash.h`, and without this check the whole libktx directory was
/// reported as `uthash@1.9.1` and libktx vanished from the SBOM. The quoted
/// rows keep their old behaviour because their canonical name often does not
/// appear in the folder name at all (sqlite3's header usually sits in a folder
/// called `sqlite` or `sqlite-prebuilt`), and requiring it there would drop
/// versions the scanner reads correctly today.
///
/// `folder_key` is `identity_key` of the folder name, computed once per vendor
/// root by the caller, and the canonical name goes through the same key, so
/// `libjpeg-turbo` compares as `libjpegturbo`. Accepted spellings are those
/// that contain the name once case and punctuation are ignored (`uthash`,
/// `UTHash-2.4`, `ut_hash`, `cjson-prebuilt`, `libjpeg_turbo`); a folder named
/// for something else (`libktx`, `hash`, `utils`) does not.
bool folder_names_library(std::string_view folder_key, std::string_view canonical_name)
{
  return folder_key.find(identity_key(canonical_name)) != std::string_view::npos;
}

/// A header's text as every version table reads it: when the cap cut the
/// file, the last line is dropped, since a value cut mid-line (`15` read as
/// `1`, `2.4.0` as `2.4`) would otherwise look complete and reach a purl.
std::string header_text_from(core::BoundedFileRead file_read)
{
  if (file_read.truncated)
  {
    const std::size_t last_newline = file_read.bytes.rfind('\n');
    file_read.bytes.resize(last_newline == std::string::npos ? 0 : last_newline + 1);
  }
  return std::move(file_read.bytes);
}

/// One candidate file against every signature table, for a vendored folder
/// whose `identity_key` is `folder_key`. `at_vendor_root_top` says the file
/// sits directly in the vendor root, which the CMake tables require: a
/// library's own build file is `<root>/CMakeLists.txt`, while one deeper down
/// belongs to a subdirectory or a bundled dependency. `read_header()` returns
/// the file's text (see `header_text_from`), or nullopt when it cannot be read;
/// it is called only when some row names this basename, so a scan reads
/// lazily.
template <typename ReadHeader>
std::optional<VersionMatch> match_header_file(std::string_view folder_key,
                                              const fs::path& relative_file,
                                              bool at_vendor_root_top, ReadHeader&& read_header)
{
  const std::string basename = relative_file.filename().string();
  const std::string_view basename_view(basename);

  // One pass over a single-macro table, reading each row's macro in that
  // table's form and syntax.
  const auto match_table = [&](std::span<const VersionHeaderSignature> table, MacroValueForm form,
                               AssignmentSyntax syntax,
                               bool folder_must_name_library) -> std::optional<VersionMatch>
  {
    for (const VersionHeaderSignature& signature : table)
    {
      if (basename_view != signature.header_filename)
      {
        continue;
      }
      if (folder_must_name_library && !folder_names_library(folder_key, signature.canonical_name))
      {
        continue;
      }
      const std::optional<std::string>& text = read_header();
      if (!text.has_value())
      {
        continue;
      }
      const std::optional<std::string> version =
          extract_macro_value(*text, signature.version_macro, form, syntax);
      if (version.has_value())
      {
        const std::string shown_value =
            form == MacroValueForm::QuotedString ? "\"" + *version + "\"" : *version;
        return VersionMatch{std::string(signature.canonical_name), *version, relative_file,
                            written_assignment(syntax, signature.version_macro, shown_value)};
      }
    }
    return std::nullopt;
  };

  // One pass over a split-release table: the folder must always name the
  // library, since a MAJOR/MINOR pair is not always a release.
  const auto match_split_table = [&](std::span<const SplitVersionSignature> table,
                                     AssignmentSyntax syntax) -> std::optional<VersionMatch>
  {
    for (const SplitVersionSignature& signature : table)
    {
      if (basename_view != signature.header_filename ||
          !folder_names_library(folder_key, signature.canonical_name))
      {
        continue;
      }
      const std::optional<std::string>& text = read_header();
      if (!text.has_value())
      {
        continue;
      }
      if (std::optional<VersionMatch> match =
              read_split_version(*text, signature, relative_file, syntax))
      {
        return match;
      }
    }
    return std::nullopt;
  };

  if (std::optional<VersionMatch> match = match_table(
          kVersionHeaderSignatures, MacroValueForm::QuotedString, AssignmentSyntax::CDefine, false))
  {
    return match;
  }
  if (std::optional<VersionMatch> match =
          match_table(kBareDottedVersionSignatures, MacroValueForm::BareDotted,
                      AssignmentSyntax::CDefine, true))
  {
    return match;
  }
  if (std::optional<VersionMatch> match =
          match_split_table(kSplitVersionSignatures, AssignmentSyntax::CDefine))
  {
    return match;
  }
  if (at_vendor_root_top)
  {
    if (std::optional<VersionMatch> match = match_table(
            kCMakeVersionSignatures, MacroValueForm::BareDotted, AssignmentSyntax::CMakeSet, true))
    {
      return match;
    }
    if (std::optional<VersionMatch> match =
            match_split_table(kCMakeSplitVersionSignatures, AssignmentSyntax::CMakeSet))
    {
      return match;
    }
  }
  for (const EncodedVersionSignature& signature : kEncodedIntegerVersionSignatures)
  {
    if (basename_view != signature.header_filename ||
        !folder_names_library(folder_key, signature.canonical_name))
    {
      continue;
    }
    const std::optional<std::string>& text = read_header();
    if (!text.has_value())
    {
      continue;
    }
    if (std::optional<VersionMatch> match = read_encoded_version(*text, signature, relative_file))
    {
      return match;
    }
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
                                                      const fs::path& vendor_root,
                                                      const std::vector<fs::path>& files,
                                                      const ParseLimits& limits)
{
  const std::string folder_key = identity_key(vendor_root.filename().string());
  for (const fs::path& relative_file : files)
  {
    // Read lazily, once per file, and only when some row names this basename.
    // Every table goes through this same bounded read, so no row can read
    // more of a file than another.
    std::optional<std::string> header_text;
    bool header_read = false;
    const auto read_header = [&]() -> const std::optional<std::string>&
    {
      if (!header_read)
      {
        header_read = true;
        core::BoundedFileRead file_read =
            core::read_file_bounded(root / relative_file, limits.max_header_bytes);
        if (file_read.readable)
        {
          header_text = header_text_from(std::move(file_read));
        }
      }
      return header_text;
    };
    const bool at_vendor_root_top = relative_file.parent_path() == vendor_root;
    if (std::optional<VersionMatch> match =
            match_header_file(folder_key, relative_file, at_vendor_root_top, read_header))
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

// ---- vendoring records -----------------------------------------------------

/// The index a directory of vendored libraries may keep beside them, one
/// section per library (Godot's `thirdparty/README.md`).
constexpr std::string_view kRecordIndexFileName = "README.md";
/// The record a vendored directory may keep inside itself (Chromium's
/// convention, copied by projects that vendor from it).
constexpr std::string_view kChromiumRecordFileName = "README.chromium";

/// A vendoring record that applies to one vendor root, and the file it came
/// from (the evidence names it).
struct RecordClue
{
  vendoring_record::Record record;
  fs::path relative_path;
};

/// A record file's text under `max_record_bytes`, trimmed like a header (a cut
/// last line is dropped, so a truncated `- Version: 1.2` never reads as
/// complete). nullopt when unreadable.
std::optional<std::string> read_record_text(const fs::path& root, const fs::path& relative_path,
                                            const ParseLimits& limits)
{
  core::BoundedFileRead file_read =
      core::read_file_bounded(root / relative_path, limits.max_record_bytes);
  if (!file_read.readable)
  {
    return std::nullopt;
  }
  return header_text_from(std::move(file_read));
}

/// The index records of every directory that holds vendor roots, each index
/// read and parsed lazily, at most once per scan. `index_files` are the
/// root-relative `README.md` paths the file index holds outside every vendor
/// root: only those, so an excluded or unindexed file is never read.
class RecordIndexCache
{
 public:
  RecordIndexCache(fs::path root, std::set<fs::path> index_files, const ParseLimits& limits)
      : root_(std::move(root)), index_files_(std::move(index_files)), limits_(limits)
  {
  }

  /// The record `<parent>/README.md` keeps for `vendor_root`'s folder name,
  /// where `<parent>` is the directory holding `vendor_root`.
  [[nodiscard]] std::optional<RecordClue> find(const fs::path& vendor_root)
  {
    const fs::path index_path = vendor_root.parent_path() / fs::path(kRecordIndexFileName);
    if (index_files_.find(index_path) == index_files_.end())
    {
      return std::nullopt;
    }
    auto cached = records_by_index_.find(index_path);
    if (cached == records_by_index_.end())
    {
      std::map<std::string, vendoring_record::Record> records;
      if (const std::optional<std::string> text = read_record_text(root_, index_path, limits_))
      {
        for (vendoring_record::Record& record : vendoring_record::parse_index(*text))
        {
          std::string folder = record.folder;
          records.emplace(std::move(folder), std::move(record));
        }
      }
      cached = records_by_index_.emplace(index_path, std::move(records)).first;
    }
    const auto record = cached->second.find(vendor_root.filename().string());
    if (record == cached->second.end())
    {
      return std::nullopt;
    }
    return RecordClue{record->second, index_path};
  }

 private:
  fs::path root_;
  std::set<fs::path> index_files_;
  ParseLimits limits_;
  std::map<fs::path, std::map<std::string, vendoring_record::Record>> records_by_index_;
};

/// The record for `vendor_root`: its own `README.chromium` when that states a
/// version (the record closest to the code), else its section in the parent
/// directory's index. A `README.chromium` deeper inside the vendor root
/// describes a sub-library, not this one, and is not read.
std::optional<RecordClue> find_record_clue(const fs::path& root, const fs::path& vendor_root,
                                           const std::vector<fs::path>& files,
                                           const ParseLimits& limits,
                                           RecordIndexCache& record_index)
{
  const fs::path chromium_path = vendor_root / fs::path(kChromiumRecordFileName);
  if (std::find(files.begin(), files.end(), chromium_path) != files.end())
  {
    if (const std::optional<std::string> text = read_record_text(root, chromium_path, limits))
    {
      if (std::optional<vendoring_record::Record> record =
              vendoring_record::parse_readme_chromium(*text))
      {
        return RecordClue{std::move(*record), chromium_path};
      }
    }
  }
  return record_index.find(vendor_root);
}

/// True for a repository-name segment as forges spell them: letters, digits,
/// `.`, `_` and `-`. A `#fragment`, `?query` or percent escape is not part of a
/// repository's name.
bool is_plain_repository_segment(std::string_view segment)
{
  return !segment.empty() &&
         std::all_of(segment.begin(), segment.end(),
                     [](char character)
                     {
                       return std::isalnum(static_cast<unsigned char>(character)) != 0 ||
                              character == '.' || character == '_' || character == '-';
                     });
}

/// The owner and repository of a record's upstream when it is exactly a
/// repository on a forge bomwerk maps to a purl type
/// (`https://github.com/<owner>/<repo>[.git]`). A deeper path
/// (`/blob/master/src/to_chars.cpp`), a homepage, or another host is not a
/// repository URL and gives nullopt.
std::optional<core::GitRemote> forge_repository_of(const std::string& upstream)
{
  if (upstream.empty())
  {
    return std::nullopt;
  }
  core::GitRemote remote = core::parse_git_remote(upstream);
  if (!is_plain_repository_segment(remote.owner) || !is_plain_repository_segment(remote.repo))
  {
    return std::nullopt;
  }
  const std::string probe = core::build_git_purl(upstream, {}, {});
  if (!core::is_forge_purl_type(core::purl_type_of(probe)))
  {
    return std::nullopt;
  }
  return remote;
}

/// A release compared the way two people would: one leading `v` is spelling,
/// not a different release (`v1.3.2` is `1.3.2`).
bool same_release(std::string_view left, std::string_view right)
{
  const auto without_v = [](std::string_view release)
  {
    if (!release.empty() && (release.front() == 'v' || release.front() == 'V'))
    {
      release.remove_prefix(1);
    }
    return release;
  };
  return without_v(left) == without_v(right);
}

/// Name, version and purl from a record alone. A release keeps the folder's
/// generic identity, exactly as a version header gives one, and claims no tag
/// spelling (`0.22.3` or `v0.22.3`) it cannot check. A commit whose upstream
/// is a forge repository becomes that repository at that commit, exactly as a
/// leftover `.git` does (`find_git_clue`): the same fact gives the same purl
/// whichever file stated it. Any other commit stays generic, without a
/// `vcs_url`, since a homepage is not a git URL.
void apply_record_identity(core::Component& component, const vendoring_record::Record& record,
                           const std::string& folder_name)
{
  component.version = record.version;
  if (!record.states_release())
  {
    if (const std::optional<core::GitRemote> forge = forge_repository_of(record.upstream))
    {
      component.name = forge->repo;
      component.purl = core::build_git_purl(record.upstream, record.commit, folder_name);
      return;
    }
  }
  component.name = folder_name;
  component.purl = "pkg:generic/" + core::percent_encode(component.name) + "@" +
                   core::percent_encode(component.version);
}

/// The evidence detail for a record: which file, which section, and the
/// Version line and upstream as written.
std::string record_evidence_detail(const RecordClue& clue)
{
  std::string detail = clue.relative_path.string() + " -> ";
  if (!clue.record.folder.empty())
  {
    detail += "section " + clue.record.folder + ": ";
  }
  detail += "\"" + first_line_truncated(clue.record.version_line, kMaxEvidenceDetailChars) + "\"";
  if (!clue.record.upstream.empty())
  {
    detail += ", upstream " + first_line_truncated(clue.record.upstream, kMaxEvidenceDetailChars);
  }
  return detail;
}

// ---- component assembly ----------------------------------------------------

/// Version sources, strongest first: a leftover `.git` HEAD, then the
/// library's own files (a version header, its own `CMakeLists.txt`), then a
/// vendoring record, then nothing but the folder name. A record that states a
/// release different from the library's own files is a finding, not a tie to
/// break: the library's files win and the disagreement is a warning that
/// names both.
core::Component build_component(const fs::path& root, const fs::path& vendor_root,
                                const std::vector<fs::path>& files, const ParseLimits& limits,
                                bool containment_root_valid, const fs::path& containment_root,
                                RecordIndexCache& record_index,
                                core::Result<std::vector<core::Component>>& result)
{
  core::Component component;
  component.root = vendor_root;
  const std::string folder_name = vendor_root.filename().string();

  const std::optional<VersionMatch> version_match =
      find_version_header_match(root, vendor_root, files, limits);
  const std::optional<RecordClue> record_clue =
      find_record_clue(root, vendor_root, files, limits, record_index);
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
    if (record_clue.has_value() && record_clue->record.states_release() &&
        !same_release(version_match->version, record_clue->record.version))
    {
      result.warn(core::WarningCode::kVendoringRecordVersionDisagreement,
                  "vendored: " + vendor_root.string() + ": " + record_clue->relative_path.string() +
                      " states version \"" +
                      core::escaped_for_diagnostic(record_clue->record.version) + "\" but " +
                      version_match->relative_path.string() + " states \"" +
                      core::escaped_for_diagnostic(version_match->version) +
                      "\", keeping the library's own version",
                  "vendored", vendor_root);
    }
  }
  else if (record_clue.has_value())
  {
    confidence = core::Confidence::Medium;
    apply_record_identity(component, record_clue->record, folder_name);
  }
  else
  {
    component.name = folder_name;
    component.purl = folder_derived_purl(vendor_root);
  }

  // A record's forge owner is supplier evidence on the same terms as a
  // leftover .git's remote owner, and fills the field only when that did not.
  if (component.supplier.empty() && record_clue.has_value())
  {
    if (const std::optional<core::GitRemote> forge =
            forge_repository_of(record_clue->record.upstream))
    {
      component.supplier = forge->owner;
    }
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
    component.evidence.push_back(
        {core::Source::Heuristic,
         version_match->relative_path.string() + " -> " + version_match->quoted_lines,
         core::Confidence::Medium});
  }
  if (record_clue.has_value())
  {
    component.evidence.push_back(
        {core::Source::Heuristic, record_evidence_detail(*record_clue), core::Confidence::Medium});
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
  // README.md files outside every vendor root: a directory's index of the
  // libraries vendored beside it (Godot's thirdparty/README.md) is one of
  // these, since vendor_root_for drops a file sitting directly in a trigger
  // directory.
  std::set<fs::path> record_index_files;
  for (const fs::path& relative_path : file_index.files)
  {
    // Shared with the fingerprint matcher (heuristics/vendor_root.hpp), which
    // scores the same roots by content: the two join on this path, so the rule
    // that produces it lives in one place. The DNS-namespace-container skip
    // that used to sit here is part of that rule now.
    const std::optional<fs::path> vendor_root = vendor_root_for(relative_path);
    if (!vendor_root.has_value())
    {
      if (relative_path.filename() == fs::path(kRecordIndexFileName))
      {
        record_index_files.insert(relative_path);
      }
      continue;
    }
    files_by_vendor_root[*vendor_root].push_back(relative_path);
  }

  std::error_code root_absolute_error;
  const fs::path containment_root = fs::absolute(root, root_absolute_error).lexically_normal();
  const bool containment_root_valid = !root_absolute_error;

  RecordIndexCache record_index(root, std::move(record_index_files), limits);
  result.value.reserve(files_by_vendor_root.size());
  for (const auto& [vendor_root, files] : files_by_vendor_root)
  {
    core::Component component =
        build_component(root, vendor_root, files, limits, containment_root_valid, containment_root,
                        record_index, result);
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

std::optional<VersionHeaderMatch> match_version_header(std::string_view vendor_folder_name,
                                                       const std::filesystem::path& header_path,
                                                       std::string_view header_bytes,
                                                       const ParseLimits& limits)
{
  const std::optional<std::string> header_text =
      header_text_from(core::bound_in_memory_bytes(header_bytes, limits.max_header_bytes));
  const bool at_vendor_root_top =
      header_path.parent_path().filename() == fs::path(vendor_folder_name);
  const std::optional<VersionMatch> match =
      match_header_file(identity_key(vendor_folder_name), header_path, at_vendor_root_top,
                        [&]() -> const std::optional<std::string>& { return header_text; });
  if (!match.has_value())
  {
    return std::nullopt;
  }
  return VersionHeaderMatch{match->canonical_name, match->version, match->relative_path,
                            match->quoted_lines};
}

std::vector<VersionHeaderRow> version_header_signatures()
{
  std::vector<VersionHeaderRow> rows;
  for (const VersionHeaderSignature& signature : kVersionHeaderSignatures)
  {
    rows.push_back({signature.header_filename, signature.canonical_name});
  }
  for (const VersionHeaderSignature& signature : kBareDottedVersionSignatures)
  {
    rows.push_back({signature.header_filename, signature.canonical_name});
  }
  for (const SplitVersionSignature& signature : kSplitVersionSignatures)
  {
    rows.push_back({signature.header_filename, signature.canonical_name});
  }
  for (const VersionHeaderSignature& signature : kCMakeVersionSignatures)
  {
    rows.push_back({signature.header_filename, signature.canonical_name});
  }
  for (const SplitVersionSignature& signature : kCMakeSplitVersionSignatures)
  {
    rows.push_back({signature.header_filename, signature.canonical_name});
  }
  for (const EncodedVersionSignature& signature : kEncodedIntegerVersionSignatures)
  {
    rows.push_back({signature.header_filename, signature.canonical_name});
  }
  return rows;
}

}  // namespace bomwerk::heuristics::vendored_cpp
