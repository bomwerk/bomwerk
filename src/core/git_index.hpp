#pragma once
#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "core/git_config.hpp"
#include "core/result.hpp"

namespace bomwerk::core
{

/// The hash a repository names its objects with, from `extensions.objectFormat`
/// in its `.git/config`. It fixes how wide every object id in the index is (20
/// or 32 bytes), so it must be known before a single entry can be read.
enum class GitObjectFormat
{
  Sha1,
  Sha256
};

/// One submodule pin recorded in a superproject's index: a gitlink entry (mode
/// `160000`) at stage 0. `path` is the working-tree path exactly as git stores
/// it ('/'-separated, relative to the repository root); `commit` is the
/// lower-case hex object id `git submodule update` would check out there.
struct Gitlink
{
  std::string path;
  std::string commit;
};

/// The largest `.git/index` read at all. A very large monorepo index is tens of
/// MiB; anything past this is refused with a warning rather than loaded.
inline constexpr std::size_t kMaxGitIndexBytes = 128u * 1024u * 1024u;

/// The longest entry path accepted. git's own limit is the platform's PATH_MAX
/// in practice; a longer name is refused as malformed rather than copied.
inline constexpr std::size_t kMaxGitIndexPathBytes = 4096;

/// The object format `config` declares: `extensions.objectFormat = sha256`
/// (case-insensitive) is `Sha256`; absent or anything else is `Sha1`, git's
/// own default. An unknown value is not guessed at: a SHA-1 read of a
/// differently-hashed index fails its structural checks and is refused.
[[nodiscard]] GitObjectFormat object_format_of(const GitConfig& config);

/// The gitlinks in an in-memory `.git/index`, sorted by path.
///
/// Reads index versions 2, 3 and 4 without running git (hard rule 9). The
/// reader refuses the WHOLE index, returning nothing plus one
/// `kGitIndexUnreadable` warning naming `label` and the reason, on anything it
/// cannot read with certainty: a wrong signature, an unknown version, an entry
/// count the file cannot hold, an entry running past the checksum, a name whose
/// length disagrees with its flags, non-NUL padding, unknown extended flags, a
/// path that is absolute or climbs with `..`, a duplicate path, or a split
/// index (`link` extension: its entries live in another file). Refusing beats
/// guessing here, because a misread entry would put a wrong commit in a purl.
/// A gitlink seen only at a conflict stage (1 to 3) has no pin and is left out.
/// The trailing checksum is bounded but not verified (`index.skipHash` writes
/// zeros there). Pure and allocation-bounded: this is what the
/// `fuzz_git_index_*` harnesses call.
[[nodiscard]] Result<std::vector<Gitlink>> parse_git_index_gitlinks(std::string_view bytes,
                                                                    GitObjectFormat object_format,
                                                                    const std::string& label);

/// `parse_git_index_gitlinks` over `<git_dir>/index`. No index at all is not an
/// error (an empty result, no warning). A symlinked index is never followed, and
/// one larger than `kMaxGitIndexBytes` is refused before it is read; both warn.
[[nodiscard]] Result<std::vector<Gitlink>> read_git_index_gitlinks(
    const std::filesystem::path& git_dir, GitObjectFormat object_format);

}  // namespace bomwerk::core
