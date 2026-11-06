#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::embedded::west
{

/// A west manifest is hand-written and small (Zephyr's own is about 30 KiB).
/// It is read whole: a truncated prefix could drop the `remotes:` or
/// `defaults:` that later projects resolve against, so an oversized file is
/// skipped with a warning rather than half-read.
inline constexpr std::size_t kMaxWestManifestBytes = 1u * 1024u * 1024u;

/// Runtime safety limits for west manifest discovery and project emission.
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxWestManifestBytes;  ///< per-manifest read cap
  std::size_t max_scanned_files = core::kDefaultMaxScannedFilesPerEcosystem;
  std::size_t max_total_projects = core::kDefaultMaxPackagesPerEcosystem;
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for Zephyr west manifests (`west.yml`, `west.yaml`) and emit one
/// component per `manifest.projects[]` entry, resolved by west's own rules:
///
/// - **url**: an explicit `url` wins; otherwise the project's `remote` (else
///   `defaults.remote`, else the only remote) contributes its `url-base`,
///   joined with `repo-path` or, failing that, the project `name`. A project
///   with no resolvable url is skipped with a warning.
/// - **revision**: the project's `revision`, else `defaults.revision`, kept
///   verbatim (tags and SHAs both occur). No revision at all yields a
///   versionless, Low-confidence component and a warning: west's implicit
///   `master` is never guessed.
/// - **purl**: `core::build_git_purl`, so a github.com project becomes
///   `pkg:github/<owner>/<repo>@<revision>` and any other host `pkg:generic`.
///   A full commit SHA is High confidence, a tag or branch Medium.
///
/// `manifest.self` is never a component. Projects pulled in by `import:` (on a
/// project or on `self`) are not followed: the importing project is still
/// emitted and the import is reported as a warning, never guessed. Groups,
/// allowlists, `userdata` and `west-commands` are read past and ignored. A
/// file named `west.yml` with no top-level `manifest:` key is not a west
/// manifest and yields nothing.
///
/// `Component::root` is the project's checkout path when the workspace top
/// directory (the parent of the directory holding the manifest) lies inside
/// `root`, so `observe` can attribute compiled files to it; otherwise empty.
///
/// Reads files only, never runs `west` (Hard Rule 9). Never throws: hostile
/// input degrades to warnings (Hard Rule 1). Output is merged and ordered by
/// purl.
// TODO(T40): register a fuzz target for this parser once the harness exists.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root);

[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root,
                                                               const ParseOptions& options);

[[nodiscard]] core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                               const std::filesystem::path& root,
                                                               const ParseOptions& options);

}  // namespace bomwerk::parsers::embedded::west
