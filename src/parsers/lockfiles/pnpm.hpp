#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::lockfiles::pnpm
{

/// Per-file read cap for `pnpm-lock.yaml`. 8 MiB is the tier every generated
/// lockfile takes in this codebase (npm, yarn, cargo, go, maven, nuget,
/// composer, python, rubygems all declare the same); the 1 MiB
/// `core::json_utils::kMaxFileBytes` tier is for hand-written manifests. Parsing
/// is line-based, so a file past the cap still yields its readable prefix.
inline constexpr std::size_t kMaxPnpmLockBytes = 8u * 1024u * 1024u;

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit returns partial output with a warning and
/// `complete = false`, and never crashes (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxPnpmLockBytes;  ///< per-lockfile read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< pnpm-lock.yaml files parsed per scan
  std::size_t max_total_packages = core::kDefaultMaxPackagesPerEcosystem;

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule is
  /// one component, not a source of nested manifests.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for npm dependencies across every `pnpm-lock.yaml`, returning
/// each resolved package as a `pkg:npm` component with High confidence: the
/// lockfile is pnpm's own resolver output.
///
/// Only the `packages:` section is read, and reading ONLY that section is the
/// whole correctness argument. A pnpm v9 lockfile repeats every package key in a
/// second `snapshots:` section, where the key additionally carries the peer
/// dependencies it was resolved against: `'@scope/name@1.2.3(react@18.2.0)'`.
/// A parser that matched on key shape instead of section would emit a component
/// whose VERSION is `1.2.3(react@18.2.0)`: a purl no feed can match, silently
/// wrong rather than loudly missing. `importers:` is skipped by the same gate;
/// it names the workspace's own members, which are the product being scanned.
///
/// Both key spellings are read: `name@version` (v9, optionally `'`-quoted) and
/// `/name@version` (v6), with any trailing `(peer@version)` suffix stripped
/// before the name/version split. A scoped package keeps its scope as the purl
/// namespace (`pkg:npm/%40scope/name@1.2.3`). Any other `lockfileVersion` is
/// skipped with one warning rather than guessed at: v5 spells its keys
/// `/name/version`, which this grammar would silently misread.
///
/// An entry is emitted only when its `resolution:` carries an `integrity:`,
/// which is what marks it a registry tarball. Git and URL dependencies resolve
/// to `{tarball: …}` or `{repo:, commit:}` and put a URL where the version
/// belongs, so they are skipped with a counted warning instead of being forced
/// into a purl. That `integrity` is sha512 and therefore stays in the evidence
/// detail, never in `Component::sha256`, which means sha256 only.
///
/// No component is given a narrowed `Scope`, in either generation. A v9
/// lockfile records dev-vs-prod only in `importers:`, where a dev dependency's
/// transitives are unmarked: marking the direct ones alone would be a
/// half-truth in CRA evidence. A v6 lockfile does carry a per-package `dev:`
/// flag, which is deliberately not read, so both generations describe the same
/// tree the same way rather than differing by which pnpm wrote them: recorded,
/// never guessed (the same call yarn makes).
///
/// Reads files only: never invokes pnpm (Hard Rule 9). Never throws: hostile
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

}  // namespace bomwerk::parsers::lockfiles::pnpm
