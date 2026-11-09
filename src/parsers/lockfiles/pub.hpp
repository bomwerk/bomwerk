#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <string_view>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::lockfiles::pub
{

/// Generated pub lockfiles are line-based and use the shared 8 MiB lockfile
/// safety tier; an oversized file still yields its complete-line prefix.
inline constexpr std::size_t kMaxPubspecLockBytes = 8u * 1024u * 1024u;

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit returns partial output with a warning and
/// `complete = false`, and never crashes (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxPubspecLockBytes;  ///< per-lockfile read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< pubspec.lock files parsed per scan
  std::size_t max_total_packages = core::kDefaultMaxPackagesPerEcosystem;

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule is
  /// one component, not a source of nested manifests.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for Dart and Flutter dependencies across every `pubspec.lock`,
/// returning each `packages:` entry as a `pkg:pub` component.
///
/// Confidence is High throughout: `pubspec.lock` is pub's own resolver
/// output. `hosted`, `git` and `sdk` entries become components (git and sdk
/// ones need a version); `path` entries are first-party and skip silently;
/// any other source is skipped with a warning rather than guessed into a purl.
///
/// Reads files only: never invokes dart or flutter (Hard Rule 9). Never
/// throws: hostile input degrades to warnings (Hard Rule 1). Output is
/// deduplicated and purl-ordered via `core::merge_all` (Rule 3).
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

/// Parse one file held in memory exactly as `parse` parses the file
/// `file_name` (root-relative, e.g. `app/pubspec.lock`): its last segment
/// must be `pubspec.lock`, or the result is empty with no warning.
/// `file_name` is the label in warnings and evidence, and
/// `options.max_file_bytes` bounds `bytes` the way it bounds a file read.
/// Never touches the filesystem: this is the entry point of the `fuzz_pub`
/// harness.
[[nodiscard]] core::Result<std::vector<core::Component>> parse_bytes(std::string_view file_name,
                                                                     std::string_view bytes,
                                                                     const ParseOptions& options);

}  // namespace bomwerk::parsers::lockfiles::pub
