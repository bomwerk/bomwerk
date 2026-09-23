#pragma once
#include <filesystem>
#include <set>

namespace bomwerk::core
{

/// Working-tree paths of the git submodules declared in `<root>/.gitmodules`,
/// root-relative and lexically normal.
///
/// This is the single definition of "which subtrees hold a submodule's
/// contents". A submodule is worth exactly ONE component: the .gitmodules parser
/// reports it pinned to its checked-out commit: so walking into it would count
/// a whole foreign project as this project's dependencies. Scanning a repo with
/// vcpkg as a submodule reported ~2,959 components from `vcpkg/ports/*` before
/// that rule existed. Both walk entry points consult this function: `run_scan`
/// (unless `--include-submodule-contents`) and each producer's standalone
/// `parse(root, …)` overload, so a caller that bypasses the CLI cannot silently
/// walk into a submodule.
///
/// Returns a bare set rather than a Result on purpose: reporting a malformed
/// `.gitmodules` belongs to the submodules PRODUCER, which already warns about
/// every case below, and warning about one file from twelve call sites would
/// duplicate it in the run's warning list and the HTML report. Input that does
/// not parse simply contributes no paths, which fails toward scanning more.
///
/// Declared paths are untrusted input: a missing `path`, an
/// absolute one, or one escaping the root via `..` (CVE-2018-11235) is dropped,
/// matching the .gitmodules parser's own filter. Never throws (rule 1) and never runs
/// `git` (rule 9): `.gitmodules` is read as a file, bounded by
/// core::read_git_config.
[[nodiscard]] std::set<std::filesystem::path> submodule_subtrees(const std::filesystem::path& root);

/// `caller_excluded` plus every submodule subtree under `root`: the skip set a
/// producer's standalone `parse(root, …)` overload hands to build_file_index.
/// Those overloads take no scan options, so they always apply the default; only
/// `run_scan` can lift it, via `--include-submodule-contents`.
[[nodiscard]] std::set<std::filesystem::path> with_submodule_subtrees(
    const std::filesystem::path& root, std::set<std::filesystem::path> caller_excluded);

}  // namespace bomwerk::core
