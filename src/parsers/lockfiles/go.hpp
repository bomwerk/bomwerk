#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::lockfiles::go
{

/// Per-file read cap for `go.sum`. Larger than the 1 MiB manifest default: a
/// big module graph routinely produces multi-megabyte checksum files, and the
/// format is line-based so a truncated read still parses cleanly line by line.
inline constexpr std::size_t kMaxGoSumFileBytes = 8u * 1024u * 1024u;

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit returns partial output with a warning and
/// `complete = false`, and never crashes (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxGoSumFileBytes;  ///< per-go.sum read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< go.sum files parsed per scan
  std::size_t max_total_packages = core::kDefaultMaxPackagesPerEcosystem;

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule is
  /// one component, not a source of nested manifests.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for Go dependencies across every `go.sum` checksum file,
/// returning each module as a `pkg:golang` component.
///
/// A `go.sum` line is `module version hash`; the `version/go.mod` variant of a
/// line carries metadata for the same module and is dropped, so a module that
/// appears only as a `/go.mod` entry (graph-only, pruned from the build) is
/// deliberately not reported. Versions are Go's exact resolver output: the
/// `v` prefix stays in the purl (purl-spec `golang` type) and confidence is
/// High: but `go.sum` accumulates the module download set, which can exceed
/// what the final binary links; the evidence says so honestly, and
/// `bomwerk observe` narrows it in P2.
///
/// Example: a `go.sum` containing
///
///     github.com/gorilla/mux v1.8.0 h1:i40aqfkR1h2SlN9hojwV5ZA91wcXFOvkdNIeFDP5koI=
///     github.com/gorilla/mux v1.8.0/go.mod h1:DVbg23sWSpFRCP0SfiEN6jmj59UnW/n46BH5rLB71So=
///
/// yields the single component `pkg:golang/github.com/gorilla/mux@v1.8.0`.
///
/// Reads files only: never invokes go (Hard Rule 9). Never throws: hostile
/// input degrades to warnings (Hard Rule 1). Output is deduplicated and
/// purl-ordered via `core::merge_all` (Rule 3).
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

}  // namespace bomwerk::parsers::lockfiles::go
