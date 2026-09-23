#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::cpp::cmake_deps
{

/// Per-file read cap for `CMakeLists.txt` / `*.cmake` files. Larger than the
/// 1 MiB manifest default: root `CMakeLists.txt` files in large real-world
/// C/C++ projects routinely exceed it (grpc's is 2.4 MiB).
inline constexpr std::size_t kMaxCmakeFileBytes = 8u * 1024u * 1024u;

/// Runtime-tunable safety limits and scan scope for `parse`. The numeric
/// defaults suit real projects (orders of magnitude above anything
/// legitimate); a caller: `bomwerk scan --max-files` chief among them: can
/// tighten or relax them without touching the producer. Exceeding a limit
/// appends a warning and stops early; it never crashes and never sets
/// `complete = false` (Hard Rule 1).
struct ParseLimits
{
  std::size_t max_file_bytes = kMaxCmakeFileBytes;  ///< per-file read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< CMake files parsed per scan
  std::size_t max_total_declarations = 10000;     ///< declarations across all files

  /// Subtree roots to skip entirely, given as `root`-relative, already
  /// lexically-normal paths (e.g. `parsers::cpp::submodules::parse`'s
  /// `Component::root` values). A vendored git submodule is already reported
  /// as one component by that producer: without this, its CMake files would
  /// be scanned again as if they belonged to the scanned project, both
  /// double-counting and burning `max_scanned_files` on vendored noise.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for CMake dependency declarations across every `CMakeLists.txt`
/// and `*.cmake` file, and return them as components. Recognizes FetchContent
/// (`FetchContent_Declare`, git and `URL`/`URL_HASH` archive forms), CPM
/// (`CPMAddPackage` / `CPMFindPackage` / `CPMDeclarePackage`, keyword and
/// `gh:`/`gl:`/`bb:` shorthand) and `ExternalProject_Add`: including the
/// legacy `SVN_REPOSITORY` / `HG_REPOSITORY` / `CVS_REPOSITORY` keywords, which
/// are reported as `pkg:generic` components pinning the exact URL in a
/// `vcs_url` qualifier.
///
/// Example: a `CMakeLists.txt` containing
///
///     FetchContent_Declare(googletest
///       GIT_REPOSITORY https://github.com/google/googletest.git
///       GIT_TAG        v1.14.0)
///     FetchContent_MakeAvailable(googletest)
///     CPMAddPackage("gh:fmtlib/fmt#10.2.1")
///
/// yields `pkg:github/google/googletest@v1.14.0` (Medium confidence: a
/// mutable tag) and `pkg:github/fmtlib/fmt@10.2.1`.
///
/// CMake-version note: matching is grammar-level, never evaluated, so any file
/// CMake ≥ 3.0 accepts lexes identically here regardless of the version that
/// builds it. The recognized commands span FetchContent (CMake 3.11+;
/// `MakeAvailable` 3.14+), CPM (3.14+) and `ExternalProject_Add` (2.x).
///
/// Reads files only: never invokes `cmake` or `git` (Hard Rule 9). Build and
/// dependency-cache directories (`build`, `_deps`, …) are skipped, so generated
/// FetchContent checkouts are not double-counted. Never throws: an unresolved
/// `${var}`, a malformed call, or a hostile file degrades to warnings and lower
/// confidence, never a crash and never the exit-2 path (Hard Rule 1). Output is
/// deduplicated and ordered by purl via `core::merge_all` (Hard Rule 3).
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root);

/// As above, with caller-supplied limits (see `ParseLimits`).
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root,
                                                               const ParseLimits& limits);

/// As above, but scans a pre-built `core::FileIndex` (see `core/file_index.hpp`)
/// instead of walking the tree itself: the exclusion set that produced
/// `file_index` is the one that applies here (`limits.excluded_subtrees` is
/// not consulted by this overload, since the index already reflects
/// whichever subtrees its builder chose to skip). Callers that already built
/// an index for their own purposes (e.g. `run_scan`'s file-count/manifest
/// walk) use this to avoid a second walk of the same tree.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                               const std::filesystem::path& root,
                                                               const ParseLimits& limits);

}  // namespace bomwerk::parsers::cpp::cmake_deps
