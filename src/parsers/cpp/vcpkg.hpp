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

namespace bomwerk::parsers::cpp::vcpkg
{

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit appends a warning and stops early: never a
/// crash, never `complete = false` (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = core::json_utils::kMaxFileBytes;  ///< per-manifest read cap (1 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< vcpkg.json files parsed per scan
  std::size_t max_total_requirements = 10000;     ///< dependencies across all files

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule is
  /// one component, not a source of nested manifests.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for vcpkg dependency declarations across every `vcpkg.json`
/// manifest, returning each declared dependency as a `pkg:vcpkg` component.
///
/// A dependency is either a bare string (`"zlib"`) or an object
/// (`{"name": "zlib", "version>=": "1.2.13", "features": […]}`). Exact version
/// pins come from the manifest's own `overrides` array: vcpkg's in-manifest
/// "lock": and raise a dependency to High confidence; a bare name or a
/// `version>=` floor stays Low (a floor is a constraint, not the resolved
/// version, so it is recorded as evidence but kept out of the identity purl).
///
/// Example: a `vcpkg.json` containing
///
///     {
///       "dependencies": [ "spdlog", { "name": "fmt", "version>=": "10.0.0" } ],
///       "overrides": [ { "name": "spdlog", "version": "1.14.1" } ]
///     }
///
/// yields `pkg:vcpkg/fmt` (Low, floor `10.0.0` in evidence) and
/// `pkg:vcpkg/spdlog@1.14.1` (High).
///
/// When a manifest's root-relative path matches the vcpkg ports-registry
/// shape `ports/<port-name>/vcpkg.json` exactly (three path segments,
/// anchored at the scan root), its own top-level `name` and version-family
/// fields are ALSO reported as one High-confidence `pkg:vcpkg` component: for
/// a port definition those fields are that package's identity, not one of
/// its dependencies. This does not apply to any other `vcpkg.json` path
/// shape: a consumer manifest's own name/version are never treated as one of
/// its dependencies, unchanged from prior behavior. That same own-identity
/// component also carries the port's top-level `"license"` (an SPDX
/// expression, e.g. `"MIT"` or `"curl AND ISC AND BSD-3-Clause"`) verbatim
/// into `Component::license` when present and a string; a bare dependency
/// reference never gets one, since it has no manifest of its own to read a
/// license from.
///
/// Reads files only: never invokes vcpkg (Hard Rule 9). Never throws: hostile
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

}  // namespace bomwerk::parsers::cpp::vcpkg
