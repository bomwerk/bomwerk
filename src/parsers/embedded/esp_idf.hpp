#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <string_view>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::embedded::esp_idf
{

/// Both files are small and written whole: a `dependencies.lock` is a few
/// kilobytes, an `idf_component.yml` less. A truncated lock could drop its
/// `version:` or `manifest_hash:` (both written after `dependencies:`), so an
/// oversized file is skipped with a warning rather than half-read.
inline constexpr std::size_t kMaxEspIdfFileBytes = 1u * 1024u * 1024u;

/// Runtime safety limits for ESP-IDF file discovery and component emission.
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxEspIdfFileBytes;  ///< per-file read cap
  std::size_t max_scanned_files = core::kDefaultMaxScannedFilesPerEcosystem;
  std::size_t max_total_components = core::kDefaultMaxPackagesPerEcosystem;
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for the ESP-IDF component manager's files and emit one
/// component per dependency:
///
/// - **`dependencies.lock`** is the component manager's resolver output, so
///   each `dependencies:` entry is reported with its exact version at High
///   confidence. A file by that name is read only when it carries the
///   top-level `dependencies:` and `manifest_hash:` keys the component manager
///   writes; any other `dependencies.lock` yields nothing and no warning. Lock
///   format `version` 1.x and 2.x are read; another major is skipped whole
///   with a warning.
/// - **`idf_component.yml`** declares constraints, not versions. It is read
///   only where no `dependencies.lock` sits in its directory or any directory
///   above it inside the scan: the lock lives at the project root while the
///   manifests live in `main/` and `components/<name>/`, and the lock already
///   resolved everything they declare. A declared constraint (`^2.4.1`) is
///   kept in the evidence detail, never as a version: the component is
///   version-less at Medium confidence, the rule
///   `parsers::lockfiles::composer` applies to a lockless `composer.json`.
///
/// Identity:
///
/// - A registry component `<namespace>/<name>` becomes
///   `pkg:generic/<namespace>/<name>@<version>`; a bare name is in the
///   `espressif` namespace, the component manager's default. The namespace is
///   the supplier. A lock entry's `component_hash` (SHA-256) becomes
///   `Component::sha256`.
/// - The `idf` pseudo-component (the framework itself) becomes
///   `pkg:generic/espressif/esp-idf@<version>`, named `esp-idf` so the CPE the
///   NVD fallback derives from it names the product NVD files ESP-IDF under.
/// - A `git:` source goes through `core::build_git_purl` (github.com ->
///   `pkg:github`, any other host -> `pkg:generic` with a `vcs_url`), and its
///   `path:` inside the repository becomes the purl subpath. A full commit SHA
///   is High confidence, a tag or branch Medium, no version at all Low with a
///   warning.
/// - A local component (`path:` or `override_path:` without `git:`, or a lock
///   source of type `local`) is part of the project itself, not a dependency:
///   it is dropped without a warning, as `parsers::lockfiles::pub` drops a
///   path dependency.
///
/// None of these identities has an OSV ecosystem, so match coverage reports
/// them as unmatched unless the NVD CPE fallback finds them. That is the
/// honest answer and is left visible.
///
/// A version-less manifest component is dropped when a lock in the scan holds
/// the same identity with a version, so one dependency is not listed twice.
/// Files under `managed_components/` (the component manager's download
/// directory) or an installed-dependency directory are someone else's
/// declaration and are never read. Entries with `rules:` or `matches:` are
/// reported whatever the build target, and marked conditional in the evidence.
///
/// Reads files only, never runs `idf.py` or the component manager (Hard Rule
/// 9). Never throws: hostile input degrades to warnings (Hard Rule 1). Output
/// is merged and ordered by purl.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root);

[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root,
                                                               const ParseOptions& options);

[[nodiscard]] core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                               const std::filesystem::path& root,
                                                               const ParseOptions& options);

/// Parse one file held in memory exactly as `parse` parses the file
/// `file_name` (root-relative, e.g. `app/dependencies.lock`): its last segment
/// must name `dependencies.lock` or `idf_component.yml`, or the result is
/// empty with no warning. Only that one file is in scope: an
/// `idf_component.yml` is parsed even where a real scan would prefer a lock
/// above it, since no other file is visible. `file_name` is the label in
/// warnings and evidence, and `options.max_file_bytes` bounds `bytes` the way
/// it bounds a file read. Never touches the filesystem: this is the entry
/// point of the `fuzz_esp_idf` harnesses.
[[nodiscard]] core::Result<std::vector<core::Component>> parse_bytes(std::string_view file_name,
                                                                     std::string_view bytes,
                                                                     const ParseOptions& options);

}  // namespace bomwerk::parsers::embedded::esp_idf
