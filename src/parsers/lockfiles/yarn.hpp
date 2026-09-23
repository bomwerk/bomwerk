#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::lockfiles::yarn
{

/// Per-file read cap for `yarn.lock`. Larger than the 1 MiB manifest default:
/// a real monorepo lockfile runs to several megabytes (backstage's is 1.7 MiB
/// across 47k lines).
inline constexpr std::size_t kMaxYarnLockBytes = 8u * 1024u * 1024u;

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit returns partial output with a warning and
/// `complete = false`, and never crashes (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxYarnLockBytes;  ///< per-lockfile read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< yarn.lock files parsed per scan
  std::size_t max_total_packages = core::kDefaultMaxPackagesPerEcosystem;

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule is
  /// one component, not a source of nested manifests.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for npm dependencies across every `yarn.lock`, returning each
/// resolved package as a `pkg:npm` component with High confidence: the
/// lockfile is Yarn's own resolver output.
///
/// Both lockfile generations are read, told apart by the `# yarn lockfile v1`
/// banner Yarn Classic writes:
///
/// * **Berry** (`__metadata: version 8`, a YAML subset): identity comes from
///   each entry's `resolution:` field, never from the entry key, whose
///   `^1.2.3` range is a request rather than a result. An `npm:` locator is
///   emitted as-is; a `patch:` locator is resolved to the `npm:` locator
///   underneath it and records the patch in its evidence, since a patched
///   dependency is not the pristine registry tarball. A `workspace:` locator
///   IS the product being scanned: skipped silently, exactly like a rubygems
///   PATH spec, since a monorepo declaring hundreds of members is normal
///   shape, not a gap. `link:`, `portal:` and `file:` locators are also
///   first-party but can point outside that declared workspace graph, so they
///   are skipped with a counted warning instead, as are locators whose
///   protocol has no purl mapping (`exec:`, git and http URLs).
/// * **Classic v1** (`name@range:` blocks, not YAML): the name comes from the
///   first descriptor in the entry key and the version from its `version`
///   line; entries that never resolve a version are counted and skipped.
///
/// A scoped package keeps its scope as the purl namespace
/// (`pkg:npm/%40scope/name@1.2.3`). Yarn does not record dev-vs-prod in the
/// lockfile: that lives in `package.json`, so no component is given a
/// narrowed `Scope` (recorded, never guessed). The Berry `checksum` and Classic
/// `integrity` fields are sha512/blake2 and so never reach
/// `Component::sha256`, which means sha256 only.
///
/// Reads files only: never invokes yarn (Hard Rule 9). Never throws: hostile
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

}  // namespace bomwerk::parsers::lockfiles::yarn
