#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::lockfiles::rubygems
{

/// Per-file read cap. Larger than the 1 MiB manifest default: a
/// `Gemfile.lock` of a large Rails application lists every resolved gem with
/// its dependency edges and can run well past a megabyte.
inline constexpr std::size_t kMaxGemfileLockBytes = 8u * 1024u * 1024u;

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit returns partial output with a warning and
/// `complete = false`, and never crashes (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxGemfileLockBytes;  ///< per-file read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< Gemfile.lock files parsed per scan
  std::size_t max_total_packages = core::kDefaultMaxPackagesPerEcosystem;

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule is
  /// one component, not a source of nested manifests.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for Ruby dependencies across every `Gemfile.lock`, returning
/// each resolved gem as a `pkg:gem` component.
///
/// Confidence is High throughout: the lockfile is Bundler's own resolver
/// output. Gemfile.lock is indentation-structured; the scanner reads exactly
/// the shape Bundler writes:
/// - a `GEM` section's 4-space `name (version)` lines under `specs:` are
///   registry gems: emitted, with the section's `remote:` in the evidence
///   detail;
/// - a `GIT` section's specs are third-party gems pinned to a revision :
///   emitted, with `remote`/`revision` in the evidence detail (a pinned git
///   dependency is still a dependency);
/// - a `PATH` section's specs are first-party local gems: skipped silently
///   (the npm workspace-link precedent);
/// - 6-space lines are a gem's own dependency edges, `PLATFORMS`/
///   `DEPENDENCIES`/`BUNDLED WITH` carry no resolved gems: all ignored.
/// Platform-suffixed versions (`1.16.5-arm64-darwin`) are kept verbatim.
/// Gemfile.lock does not mark dev-only groups (that lives in the Gemfile),
/// so scope is never guessed.
///
/// Reads files only: never invokes bundler/ruby (Hard Rule 9). Never throws
/// past this producer's boundary: hostile input degrades to warnings (Hard
/// Rule 1). Output is deduplicated and purl-ordered via `core::merge_all`
/// (Rule 3).
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root);

/// As above, with caller-supplied limits.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root,
                                                               const ParseOptions& options);

/// As above, but scans a pre-built `core::FileIndex` instead of walking the
/// tree itself: the exclusion set that produced `file_index` is the one that
/// applies (`options.excluded_subtrees` is not consulted). `run_scan` uses this
/// to share its single walk.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                               const std::filesystem::path& root,
                                                               const ParseOptions& options);

}  // namespace bomwerk::parsers::lockfiles::rubygems
