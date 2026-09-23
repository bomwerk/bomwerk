#pragma once
#include <filesystem>
#include <set>
#include <vector>

#include "core/result.hpp"

namespace bomwerk::core
{

/// One deterministically-ordered index of every regular file under a scanned
/// root, with excluded directories and vendored submodule subtrees already
/// skipped. Building this once and filtering it is cheaper than each producer
/// walking the tree again: on a huge repo (hundreds of thousands of files)
/// the walk itself, not the parsing, dominates wall time.
struct FileIndex
{
  /// Root-relative, lexically-normal paths, sorted (Hard Rule 3: directory
  /// iteration order is unspecified).
  std::vector<std::filesystem::path> files;
};

/// Walk `root` once: skip any directory whose basename is in
/// `excluded_dir_names`, and any subtree rooted at a path in
/// `excluded_subtrees` (already root-relative, lexically-normal: e.g. a
/// vendored git submodule's working-tree path from
/// `parsers::cpp::submodules::parse`). When `included_subtrees` is non-empty
/// (bomwerk.toml `[scan] include`), only files inside one of those
/// root-relative subtrees are collected: directories are still traversed
/// when they lead to an included subtree, and exclusion always beats
/// inclusion; an empty set means "everything", preserving the earlier
/// behavior at every existing call site. Collect every remaining regular file
/// as a root-relative path, then sort. `root` not being a directory yields an
/// empty index, not an error. Never throws: a walk error appends a warning
/// and stops the walk early with whatever was collected so far (Hard Rule 1)
///: it never sets `complete = false`.
/// Example: `build_file_index(root, {"build", ".git"}, {})` skips a top-level
/// `build/` or `.git/` directory entirely and returns every other file.
/// When a pruned directory's name is collision-prone
/// (`core::collision_prone_excluded_dir_names()`: a small subset common
/// enough to also legitimately hold first-party source, e.g. `build/`) and a
/// bounded two-level peek inside it finds a recognized manifest filename
/// (`core::default_manifest_names()`), one warning names the directory before
/// pruning it: the directory is still excluded either way; only the
/// silence changes.
[[nodiscard]] Result<FileIndex> build_file_index(
    const std::filesystem::path& root, const std::set<std::string>& excluded_dir_names,
    const std::set<std::filesystem::path>& excluded_subtrees,
    const std::set<std::filesystem::path>& included_subtrees = {});

/// `lexically_normal` plus trailing-separator removal, so "app/" and "app"
/// name the same subtree. Every place that compares subtree paths
/// component-wise has to agree on this or the two sides silently stop
/// matching: `bomwerk.toml`'s include/exclude lists and the build
/// trace's component roots both normalize through here, and a root
/// spelled one way in an SBOM and the other in a config would otherwise look
/// like two different subtrees.
/// Total on every input, including a bare filesystem root: `"/"` normalizes
/// to itself rather than hanging, leaving each caller's own containment guard
/// to reject it (rule 1: this is reachable from a scanned repo's
/// `bomwerk.toml` and from an untrusted SBOM's component location).
/// Example: `normalized_subtree_path("third_party/./zlib/")` ->
/// `"third_party/zlib"`.
[[nodiscard]] std::filesystem::path normalized_subtree_path(const std::filesystem::path& raw_path);

/// True when `relative_path` (root-relative, lexically-normal) is in scope
/// under the same include/exclude subtree rules `build_file_index` applies to
/// the files it collects: exclusion always wins, and when `included_subtrees`
/// is non-empty only a path inside one of them is in scope (empty means
/// "everything"). For a producer that discovers components without walking
/// `file_index` itself (e.g. `parsers::cpp::submodules`, whose components
/// come from `.gitmodules`, not the file walk) so bomwerk.toml's `[scan]
/// include`/`exclude` still applies to its output.
[[nodiscard]] bool path_in_scan_scope(const std::filesystem::path& relative_path,
                                      const std::set<std::filesystem::path>& excluded_subtrees,
                                      const std::set<std::filesystem::path>& included_subtrees);

}  // namespace bomwerk::core
