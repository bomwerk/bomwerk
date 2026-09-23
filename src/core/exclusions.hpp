#pragma once
#include <filesystem>
#include <set>
#include <string>

#include "core/result.hpp"

namespace bomwerk::core
{

/// Directory basenames skipped during a scan by default: version-control
/// metadata, build outputs, IDE state and dependency caches. These hold
/// generated or tooling files that would inflate the file count and produce
/// spurious manifests (e.g. a CMakeLists.txt inside a build tree). `scan --all`
/// disables this so every directory is walked.
///
/// Note: folders that legitimately hold third-party sources (`third_party`,
/// `vendor`, `node_modules`, …) are intentionally NOT excluded: those are
/// exactly what an SBOM must see.
const std::set<std::string>& default_excluded_dir_names();

/// The subset of `default_excluded_dir_names()` common enough to also
/// legitimately hold first-party source rather than only ever holding
/// generated output: a project's own `build/` directory can carry checked-in
/// tooling (e.g. vscode's `build/win32/Cargo.lock`), unlike `.git` or
/// `_deps`, which never do by any real-world convention. `build_file_index`
/// (core/file_index.cpp) peeks a bounded two levels into a directory
/// matching one of these names before pruning it, and warns instead of
/// staying silent when that peek finds a recognized manifest: the directory
/// is still excluded either way; only the silence changes.
const std::set<std::string>& collision_prone_excluded_dir_names();

/// Load excluded directory basenames from `list_path` (see core/name_list.hpp
/// for the file format), mirroring load_manifest_names() so includes and
/// excludes are configurable the same way. Never throws (rule 1): an
/// unreadable or empty file degrades to the built-in list with a warning.
Result<std::set<std::string>> load_excluded_dir_names(const std::filesystem::path& list_path);

}  // namespace bomwerk::core
