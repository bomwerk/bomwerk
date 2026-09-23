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

namespace bomwerk::parsers::ci::github_actions
{

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit appends a warning and stops early: never a
/// crash, never `complete = false` (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = core::json_utils::kMaxFileBytes;  ///< per-file read cap (1 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< workflow files parsed per scan
  std::size_t max_total_uses_references = 20000;  ///< 'uses:' lines across all files

  /// Subtree roots to skip entirely, given as `root`-relative, already
  /// lexically-normal paths (e.g. `parsers::cpp::submodules::parse`'s
  /// `Component::root` values): a vendored git submodule's own workflow
  /// files belong to that submodule's component, not this project.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for GitHub Actions dependencies declared in every
/// `.github/workflows/*.yml`/`*.yaml` file, returning each external `uses:`
/// reference (step-level and job-level reusable-workflow calls alike: both
/// share the same `uses:` key, so one scan catches both) as a
/// `pkg:github/<owner>/<repo>@<ref>` component.
///
/// Confidence is tiered by how mutable the ref is: the exact distinction
/// behind incidents like the tj-actions compromise, where a mutable tag was
/// re-pointed at malicious code: a full 40-character commit SHA is High
/// (immutable), a tag or branch name is Medium (re-pointable), and a missing
/// ref or one containing an unresolved `${{ ... }}` expression is Low with a
/// warning. An unresolved expression in the owner or repo segment leaves
/// nothing to identify: no component is emitted for that line at all. In
/// every case, the literal substring `${{` never appears in an emitted purl:
/// an unresolved ref is reported with no `@ref` segment rather than leaking
/// the expression text into it (stricter than how the CMake producer treats
/// its own unresolved `${var}` case).
///
/// A local action (`uses: ./...` or `../...`) or a Docker action
/// (`uses: docker://...`) is not a dependency bomwerk can track and is
/// skipped silently: note that `docker/build-push-action@...` is a GitHub
/// Action published by the `docker` org, not the `docker://` URI scheme, and
/// is reported normally.
///
/// Reads files only: never shells out to `git`/`gh` (Hard Rule 9): a
/// workflow file is read exactly as any other manifest. Never throws: a
/// malformed or hostile file degrades to warnings, never a crash and never
/// the exit-2 path (Hard Rule 1). Output is deduplicated and ordered by purl
/// via `core::merge_all` (Hard Rule 3).
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root);

/// As above, with caller-supplied limits.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root,
                                                               const ParseOptions& options);

/// As above, but scans a pre-built `core::FileIndex` instead of walking the
/// tree itself: the exclusion set that produced `file_index` is the one that
/// applies (`options.excluded_subtrees` is not consulted). `run_scan` uses
/// this to share its single walk.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                               const std::filesystem::path& root,
                                                               const ParseOptions& options);

}  // namespace bomwerk::parsers::ci::github_actions
