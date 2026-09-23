#pragma once
#include <filesystem>
#include <string>

namespace bomwerk::core
{

/// True when `relative_path` is safe to descend into: not absolute and never
/// escaping via `..` (the shape of CVE-2018-11235). Used for a HEAD `ref:`
/// value (git itself never allows `..` there, per git-check-ref-format, so
/// rejecting it here can only ever reject a hostile value) and for any other
/// caller-declared relative path that will be joined onto a scanned root
/// before being read (e.g. `.gitmodules`' `path=`).
[[nodiscard]] bool is_contained_relative_path(const std::filesystem::path& relative_path);

/// Resolve the git directory for a working tree without running git. `.git` is
/// a directory in a normal checkout and a file ("gitdir: …") in a submodule or
/// worktree. A symlinked `.git` is never followed. `containment_root` bounds
/// where a `gitdir:` pointer may resolve to: a pointer that escapes the
/// scanned tree is rejected and reported as absent, rather than reading a file
/// outside the scan. Empty when there is no git dir at all (e.g. an
/// uninitialized submodule, or a vendored folder that was never a checkout).
[[nodiscard]] std::filesystem::path resolve_git_dir(const std::filesystem::path& work_dir,
                                                    const std::filesystem::path& containment_root);

/// The commit checked out in `git_dir`: a detached HEAD holds the id directly;
/// otherwise HEAD is `ref: refs/…`, resolved via the loose ref then
/// `packed-refs`. Empty when no commit can be resolved. Bounded against
/// hostile input (rule 1): ref files and `packed-refs` are size-capped, and a
/// `ref:` value is rejected before ever being joined onto a path.
[[nodiscard]] std::string read_head_commit(const std::filesystem::path& git_dir);

}  // namespace bomwerk::core
