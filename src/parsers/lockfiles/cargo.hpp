#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::lockfiles::cargo
{

/// Per-file read cap. Larger than the 1 MiB manifest default: a `Cargo.lock`
/// of a real workspace lists every transitive crate with its checksum and can
/// run to megabytes.
inline constexpr std::size_t kMaxCargoLockfileBytes = 8u * 1024u * 1024u;

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit returns partial output with a warning and
/// `complete = false`, and never crashes (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxCargoLockfileBytes;  ///< per-file read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< Cargo.lock files parsed per scan
  std::size_t max_total_packages = core::kDefaultMaxPackagesPerEcosystem;

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule is
  /// one component, not a source of nested manifests.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for Rust dependencies across every `Cargo.lock`, returning each
/// `[[package]]` entry as a `pkg:cargo` component.
///
/// Confidence is High throughout: `Cargo.lock` is cargo's own resolver output.
/// An entry without a `source` key is a workspace member: the product itself,
/// not a dependency: and is skipped silently (the same first-party rule as
/// uv.lock's virtual root). `Cargo.lock` does not mark dev-dependencies, so
/// scope is never guessed. A registry `checksum` is the sha256 of the crate
/// archive and lands in `Component::sha256` after hex validation; anything
/// that fails validation stays in the evidence detail instead.
///
/// Reads files only: never invokes cargo (Hard Rule 9). Never throws past
/// this producer's own boundary: hostile input degrades to warnings (Hard
/// Rule 1): TOML parse errors are caught inside the TOML-parsing helper
/// itself, since vcpkg's tomlplusplus ships a precompiled, exceptions-enabled
/// library rather than the non-throwing API. Output is deduplicated and
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

}  // namespace bomwerk::parsers::lockfiles::cargo
