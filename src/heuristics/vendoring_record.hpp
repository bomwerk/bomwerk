#pragma once
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bomwerk::heuristics::vendoring_record
{

/// Longest line either reader looks at. Every field a `Record` keeps comes
/// from one line, so this also bounds every string in it.
inline constexpr std::size_t kMaxLineChars = 512u;

/// Longest release string a record may state. Anything longer is not a version.
inline constexpr std::size_t kMaxVersionChars = 64u;

/// What one vendoring record states about one vendored directory: the note a
/// project keeps beside code it copied in, saying which upstream release or
/// commit the copy came from. A record is a human-maintained claim about the
/// copy, not part of the copied bytes, so `vendored_cpp` ranks it below the
/// library's own files (a version header, its own `CMakeLists.txt`).
struct Record
{
  std::string folder;        ///< the directory an index section names; empty for README.chromium
  std::string version;       ///< the stated release, else the stated commit; never empty
  std::string commit;        ///< the one 40- or 64-hex object id stated, lower-cased; may be empty
  std::string upstream;      ///< one `http(s)://` URL with no spaces, as written; may be empty
  std::string version_line;  ///< the Version (and Revision) line(s) as written, for evidence

  /// True when the record names a release (`0.22.3`, `vulkan-sdk-1.4.335.0`)
  /// rather than only a commit: `version` then holds that release. A release
  /// is never an object id, so it can never equal `commit`.
  [[nodiscard]] bool states_release() const { return version != commit; }
};

/// Read an index of vendored directories in the format Godot keeps in
/// `thirdparty/README.md`: one Markdown section per directory, headed by the
/// directory's name, with top-level bullets such as
///
///     ## zlib
///
///     - Upstream: https://github.com/madler/zlib
///     - Version: 1.3.2 (da607da739fa6047df13e66a2af6b8bec7c2a498, 2026)
///
/// The grammar is strict on purpose (honest is better than clever):
/// - a `#` or `##` heading whose text is one token (no blanks, no `/` or `\`)
///   opens that token's section; any other `#`/`##` heading closes the current
///   section without opening one; deeper headings are section text;
/// - only bullets at column 0 count (`- Version:`, `- Upstream:`), so the
///   indented `  * Version:` items of a collection section describe its single
///   files, not the directory;
/// - a section with more than one `- Version:` (two libraries in one
///   directory), or a name with more than one section, yields no record;
/// - a bullet line longer than `kMaxLineChars` is ignored.
///
/// The Version value is read as `<head> (<part>, <part>, ...)`. The head, cut
/// at its first comma, is the release unless it is a VCS word or placeholder
/// (`git`, `main`, `?`, `0`, ...), an object id or an abbreviated commit, or
/// not a version-shaped token (1 to `kMaxVersionChars` of `[A-Za-z0-9._+~-]`
/// with a digit). The commit is the one object id among the head and the
/// parts; two different ones state no commit. A section that states neither a
/// release nor a commit yields no record.
///
/// Returns the records sorted by `folder`, each name at most once. Never
/// throws; `text` is untrusted and the caller bounds its size.
[[nodiscard]] std::vector<Record> parse_index(std::string_view text);

/// Read a Chromium-style `README.chromium` (the file that sits inside the
/// directory it describes): `Key: value` fields at the top of the file, before
/// `Description:`. The first non-blank line must be a `Name:` field, otherwise
/// the file is prose that happens to carry this name and nothing is read.
/// `Version:` goes through the same value grammar as an index (so
/// `git (see METADATA)` and `0` state no release), a 40- or 64-hex
/// `Revision:` is the commit, and a single-URL `URL:` is the upstream. A field
/// written twice is ignored. `nullopt` when the file states neither a release
/// nor a commit. Never throws.
[[nodiscard]] std::optional<Record> parse_readme_chromium(std::string_view text);

}  // namespace bomwerk::heuristics::vendoring_record
