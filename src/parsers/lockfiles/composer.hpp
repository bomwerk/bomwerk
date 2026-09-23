#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::lockfiles::composer
{

/// Per-file read cap. Larger than the 1 MiB manifest default: a
/// `composer.lock` embeds full package metadata (dist, autoload, authors) per
/// entry and can run to megabytes.
inline constexpr std::size_t kMaxComposerLockfileBytes = 8u * 1024u * 1024u;

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit returns partial output with a warning and
/// `complete = false`, and never crashes (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxComposerLockfileBytes;  ///< per-file read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< lockfiles parsed per scan
  std::size_t max_total_packages = core::kDefaultMaxPackagesPerEcosystem;

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule is
  /// one component, not a source of nested manifests.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for PHP dependencies across every `composer.lock`, returning
/// each package as a `pkg:composer` component (`vendor` is the purl
/// namespace, the package name the purl name). Every entry is High
/// confidence: composer.lock is composer's own resolver output.
///
/// `composer.json` is deliberately NOT read as a fallback when no
/// `composer.lock` exists: the same policy `parsers::lockfiles::go` applies
/// to a lockfile-less `go.mod`: a declared `require`/`require-dev` range
/// (`"^2.0"`) is a constraint, not a resolved version, and reporting it as if
/// it were a component's identity would produce a purl that can never match a
/// real OSV/CPE record. `core::ecosystem_manifests()` lists `composer.json`
/// as a loose manifest for this reason, so a composer.json-only project
/// surfaces the generic "found composer.json ... with no lockfile alongside"
/// warning (`core::find_unparsed_manifests`, wired in `cli::scan_command`)
/// instead of synthetic components.
///
/// `packages` entries are runtime dependencies; `packages-dev` entries get
/// CycloneDX `Scope::Excluded`: the lock itself says dev-only, nothing is
/// guessed. Versions are kept exactly as composer.lock wrote them (`v` prefix
/// included: normalizing would guess). Platform pseudo-requirements (`php`,
/// `ext-*`, `lib-*`, …) never become components. The first `license` array
/// entry lands in `Component::license`; `dist.shasum` (sha1, often empty)
/// stays in the evidence detail, never `Component::sha256`.
///
/// Reads files only: never invokes composer/php (Hard Rule 9). Never throws
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

}  // namespace bomwerk::parsers::lockfiles::composer
