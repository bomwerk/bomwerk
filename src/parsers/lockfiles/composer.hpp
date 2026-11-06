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

/// Per-file read cap, applied to both filenames this producer reads. Larger
/// than the 1 MiB manifest default: a `composer.lock` embeds full package
/// metadata (dist, autoload, authors) per entry and can run to megabytes. A
/// `composer.json` is far smaller, and shares the cap rather than earning a
/// second knob.
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

/// Scan `root` for PHP dependencies across every `composer.lock`, and every
/// `composer.json` that has no `composer.lock` beside it, returning each
/// package as a `pkg:composer` component (`vendor` is the purl namespace, the
/// package name the purl name). A composer.lock entry is High confidence:
/// composer.lock is composer's own resolver output.
///
/// `composer.json` is the fallback, so a project that never committed a lock
/// still produces a dependency list rather than nothing. It is read only
/// where no sibling `composer.lock` exists, in that file's own directory: the
/// lock is authoritative wherever it is present, and a manifest parsed beside
/// one would only add a weaker duplicate of what the lock already resolved.
///
/// A `require`/`require-dev` value is a declared range (`"^2.0"`), not a
/// resolved version, so such a component is Medium confidence (the tier
/// `parsers::lockfiles::maven` gives a pom.xml dependency) and its purl is
/// **version-less**: `pkg:composer/vendor/name` with no `@` segment, with the
/// range kept in the evidence detail. Writing the range into the purl would
/// produce an identity that can never match a real OSV/CPE record, so the
/// version is dropped rather than guessed, and the component still matches on
/// name alone. This is the one way the fallback departs from the policy
/// `parsers::lockfiles::go` applies to a lockfile-less `go.mod`.
///
/// A version-less fallback component is dropped when the scan also holds a
/// versioned entry for the same `vendor/package` from some composer.lock: the
/// lock's entry is the same package with its resolved version, so listing
/// both would count one dependency twice. The exception is scope: if every
/// versioned entry is dev-only and the version-less one is a runtime
/// requirement, both stay, because dropping it would make the package look
/// dev-only.
///
/// A `composer.json` inside an installed dependency tree
/// (`core::is_inside_installed_dependencies`: `vendor/`, `node_modules/`, …)
/// is ignored: `vendor/acme/lib/composer.json` is acme's own declaration, not
/// this project's. Neither skip warns: a file this producer has no reason to
/// open is not a degraded read. `core::ecosystem_manifests()` therefore lists
/// `composer.json` among composer's *supported* locks, not as a loose
/// manifest, so a composer.json-only project no longer surfaces the generic
/// "found composer.json ... with no lockfile alongside" warning from
/// `core::find_unparsed_manifests`: there is a parser for it now.
///
/// Platform pseudo-requirements (`php`, `hhvm`, `ext-*`, `lib-*`,
/// `composer-*`) constrain the environment, not the dependency graph, and are
/// not Packagist packages: they never become components, and are skipped with
/// one counted warning per file.
///
/// `packages` entries (and a manifest's `require`) are runtime dependencies;
/// `packages-dev` and `require-dev` entries get CycloneDX `Scope::Excluded`:
/// the file itself says dev-only, nothing is guessed. Lock versions are kept
/// exactly as composer.lock wrote them (`v` prefix included: normalizing
/// would guess). The first `license` array entry lands in
/// `Component::license`; `dist.shasum` (sha1, often empty) stays in the
/// evidence detail, never `Component::sha256`. A composer.json carries
/// neither, so a fallback component has no license and no hash.
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
