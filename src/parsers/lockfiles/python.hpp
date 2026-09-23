#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::lockfiles::python
{

/// Per-file read cap. Larger than the 1 MiB manifest default: `uv.lock` and
/// `poetry.lock` of real applications run to megabytes (hash blocks per
/// package); requirements files never come close, so one cap serves all.
inline constexpr std::size_t kMaxPythonLockfileBytes = 8u * 1024u * 1024u;

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit returns partial output with a warning and
/// `complete = false`, and never crashes (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxPythonLockfileBytes;  ///< per-file read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< python files parsed per scan
  std::size_t max_total_packages = core::kDefaultMaxPackagesPerEcosystem;

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule is
  /// one component, not a source of nested manifests.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for Python dependencies across every `uv.lock`, `poetry.lock`,
/// `requirements.txt`, `requirements-<name>.txt`, `requirements_<name>.txt`,
/// `requirements.<name>.txt` and `<name>.requirements.txt`, returning each
/// package as a `pkg:pypi` component.
///
/// Names are normalized per PEP 503 (lower-cased; runs of `-`/`_`/`.` collapse
/// to `-`) before the purl is built, so the same package found in a lock and a
/// requirements file becomes ONE component with layered evidence.
///
/// Confidence ladder:
/// - `uv.lock` / `poetry.lock` `[[package]]` entries -> High (resolver output).
///   uv's root-project entry (`source` virtual/editable) is skipped: it is
///   the product, not a dependency. A poetry package whose `groups` lack
///   `main` (or whose legacy `category` isn't `main`) gets CycloneDX
///   `Scope::Excluded`: recorded, never guessed; uv entries are never
///   dev-marked because uv.lock does not say.
/// - Any recognized requirements file's `name==version` -> High (pip enforces
///   the exact pin: the same logic that makes a vcpkg `overrides` pin High).
/// - Any other requirement (bare name, `>=`, `~=`, multi-clause) -> Low; the
///   raw constraint stays in the evidence detail and out of the identity purl.
///   `-r`/`-c`/`-e`/option/URL/path lines are counted and skipped with one
///   warning per file (batch 1 scope).
///
/// Reads files only: never invokes pip/uv/poetry (Hard Rule 9). Never throws
/// past this producer's own boundary: hostile input degrades to warnings
/// (Hard Rule 1): TOML parse errors are caught inside the TOML-parsing helper
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

}  // namespace bomwerk::parsers::lockfiles::python
