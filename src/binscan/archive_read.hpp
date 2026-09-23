#pragma once
#include <filesystem>
#include <string>
#include <vector>

#include "binscan/bounds.hpp"
#include "core/result.hpp"

namespace bomwerk::binscan
{

/// What one `ar` archive tells bomwerk about its contents.
///
/// This is the only view bomwerk has into a PREBUILT vendored `.a`: the link scan can
/// prove such an archive was linked, but nothing until now could say what is
/// inside one. Member names routinely carry the upstream library's own file
/// layout (`deflate.o`, `crypto/aes.o`), which is evidence about identity that
/// a link line cannot supply.
struct ArchiveContents
{
  bool is_archive = false;                   ///< opens with `!<arch>\n`
  std::vector<std::string> member_names;     ///< object members, sorted, deduplicated
  std::vector<std::string> indexed_symbols;  ///< from the archive symbol index, sorted
  bool members_truncated = false;            ///< hit kMaxArchiveMembers, or the walk ran short
  bool symbols_truncated = false;            ///< hit kMaxSymbolSample
  bool symbols_unavailable = false;          ///< no readable index; see `read_archive`
};

/// Read one `ar` archive's member names and symbol-index sample.
///
/// Both dialects are handled, because a vendored `.a` may have been produced
/// by either toolchain and bomwerk does not get to choose:
///
///   * GNU: a `//` long-name string table with members spelled `/<offset>`
///     into it, short names spelled `name/`, and a leading `/` (or `/SYM64/`)
///     symbol index whose counts and offsets are big-endian by specification.
///   * BSD: long names spelled `#1/<length>` with the name occupying the
///     first `<length>` bytes of the member's own data, short names padded
///     with spaces, and a `__.SYMDEF` index.
///
/// Member names come back for both. The SYMBOL sample comes back only for the
/// GNU index: `__.SYMDEF` stores its counts in the producing host's native
/// byte order, which the archive itself does not record, so reading it means
/// guessing an endianness: and a guess that lands wrong yields plausible
/// garbage rather than an error. That case sets `symbols_unavailable` and
/// keeps the names, rather than reporting invented symbols; the platform this
/// pass targets emits the GNU form.
///
/// Never throws and never indexes unchecked (rule 1). A member header whose
/// declared size runs past the end of the file ends the walk with a warning
/// and whatever was read so far: a partly readable archive still names the
/// members it got through, and partial output beats none.
[[nodiscard]] core::Result<ArchiveContents> read_archive(const std::filesystem::path& path);

}  // namespace bomwerk::binscan
