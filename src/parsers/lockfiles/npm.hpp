#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::lockfiles::npm
{

/// Per-file read cap for `package-lock.json`. Larger than the 1 MiB manifest
/// default: real application lockfiles routinely run to several megabytes.
inline constexpr std::size_t kMaxPackageLockBytes = 8u * 1024u * 1024u;

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit returns partial output with a warning and
/// `complete = false`, and never crashes (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxPackageLockBytes;  ///< per-lockfile read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< package-lock.json files parsed per scan
  std::size_t max_total_packages = core::kDefaultMaxPackagesPerEcosystem;

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule is
  /// one component, not a source of nested manifests.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for npm dependencies across every `package-lock.json` (npm 7+,
/// `lockfileVersion` 2/3), returning each installed package as a `pkg:npm`
/// component with High confidence: the lockfile is npm's own resolver output.
///
/// The `packages` map is walked: the root `""` entry (the product itself) and
/// version-less workspace/link entries are skipped with counted warnings. A
/// package's name comes from the last `node_modules/` segment of its key, so
/// nested installs collapse to the same purl; a scoped package keeps its scope
/// as the purl namespace (`pkg:npm/%40scope/name@version`). A `dev: true`
/// package gets CycloneDX `Scope::Excluded`: recorded, never guessed; its
/// `integrity` checksum (usually sha512) is kept in the evidence detail, never
/// in `Component::sha256` (that field means sha256 only).
///
/// A `lockfileVersion` 1 file (npm <7, nested `dependencies` tree) is not
/// parsed: one clear warning asks for a regenerate with npm 7+ and the run
/// degrades to exit 1: never silence.
///
/// Reads files only: never invokes npm (Hard Rule 9). Never throws: hostile
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

}  // namespace bomwerk::parsers::lockfiles::npm
