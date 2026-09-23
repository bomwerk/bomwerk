#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/json_utils.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::cpp::conan
{

/// Runtime-tunable safety limits and behavior switches for `parse`. Numeric
/// defaults suit real projects; exceeding a limit appends a warning and stops
/// early: never a crash, never `complete = false` (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = core::json_utils::kMaxFileBytes;  ///< per-manifest read cap (1 MiB)
  std::size_t max_graph_file_bytes = 8u * 1024u * 1024u;  ///< `--conan-graph` read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< conan files parsed per scan
  std::size_t max_total_requirements = 10000;     ///< requirements across all files

  /// When true, a pinned recipe revision becomes an `rrev` purl qualifier
  /// (purl-spec conan type). Default false: the revision stays in the
  /// evidence detail so a declared `conanfile.txt` entry and its resolved
  /// `conan.lock` entry share one purl and merge into one component.
  bool emit_recipe_revision_qualifier = false;

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule
  /// is one component, not a source of nested conanfiles.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for conan dependency declarations across every `conanfile.txt`
/// (sections `[requires]`, `[tool_requires]`, `[build_requires]`,
/// `[test_requires]`), `conanfile.py` (bounded text scan of `requires = …`
/// attributes and `self.requires(…)`-family calls: the file is NEVER
/// executed, Hard Rule 9) and `conan.lock` (conan-2 arrays and conan-1
/// `graph_lock` nodes), returning each as a `pkg:conan` component.
///
/// Example: a `conanfile.txt` containing
///
///     [requires]
///     zlib/1.2.13
///     openssl/3.2.0@corp/stable
///
/// yields `pkg:conan/zlib@1.2.13` and
/// `pkg:conan/openssl@3.2.0?channel=stable&user=corp`.
///
/// Confidence: a lockfile entry or revision-pinned reference is High (conan's
/// own resolution output), an exact declared version Medium, a version range
/// or unresolved interpolation Low. Reads files only: never invokes conan or
/// python. Never throws: hostile input degrades to warnings (Hard Rule 1).
/// Output is deduplicated and purl-ordered via `core::merge_all` (Rule 3).
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root);

/// As above, with caller-supplied limits and behavior switches.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root,
                                                               const ParseOptions& options);

/// As above, but scans a pre-built `core::FileIndex` instead of walking the
/// tree itself: the exclusion set that produced `file_index` is the one that
/// applies (`options.excluded_subtrees` is not consulted). `run_scan` uses
/// this to share its single walk.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                               const std::filesystem::path& root,
                                                               const ParseOptions& options);

/// Ingest the JSON that `conan graph info . --format=json` wrote: run by the
/// USER or their CI, never by bomwerk (Hard Rule 9). Every graph node except
/// the consumer root ("0") becomes a High-confidence component. Unreadable or
/// malformed input degrades to warnings, never an error.
[[nodiscard]] core::Result<std::vector<core::Component>> parse_graph_file(
    const std::filesystem::path& graph_json_path, const ParseOptions& options);

}  // namespace bomwerk::parsers::cpp::conan
